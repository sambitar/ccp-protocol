"""FastAPI adapter tests."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
sys.path.insert(0, SDK_DIR)

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from ccp.adapters.fastapi import manifest_router, provider_router  # noqa: E402
from ccp.consumer import verify_manifest  # noqa: E402
from world import build_world, signal_for  # noqa: E402


def make_client(world, resolver=None):
    app = FastAPI()
    if resolver is None:
        resolver = lambda request: world["requester"].verifying_key()  # noqa: E731
    app.include_router(provider_router(world["runtime"], resolver))
    app.include_router(manifest_router(world["manifest"].document))
    return TestClient(app)


class FastApiAdapterTests(unittest.TestCase):
    def setUp(self):
        self.world = build_world()
        self.client = make_client(self.world)

    def test_authorizes_a_signed_signal(self):
        response = self.client.post(
            "/ccp", json={"signal": signal_for(self.world)})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["outcome"], "authorized")
        self.assertEqual(body["result"],
                         {"item_id": "item-123", "name": "Widget"})
        self.assertNotIn("error", body)

    def test_rejects_a_tampered_signal_with_403(self):
        tampered = signal_for(self.world).replace('"item-123"',
                                                  '"item-999"')
        response = self.client.post("/ccp", json={"signal": tampered})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"], "unauthenticated")

    def test_rejects_a_missing_signal_with_400(self):
        response = self.client.post("/ccp", json={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_request")

    def test_rejects_malformed_json_with_400(self):
        response = self.client.post(
            "/ccp", content="{not json",
            headers={"content-type": "application/json"})
        self.assertEqual(response.status_code, 400)

    def test_rejects_an_unknown_sender_with_401(self):
        client = make_client(self.world, lambda request: None)
        response = client.post(
            "/ccp", json={"signal": signal_for(self.world)})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"], "unauthenticated")

    def test_supports_an_async_key_resolver(self):
        async def resolver(request):
            return self.world["requester"].verifying_key()

        client = make_client(self.world, resolver)
        response = client.post(
            "/ccp", json={"signal": signal_for(self.world)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["outcome"], "authorized")

    def test_serves_the_signed_manifest(self):
        response = self.client.get("/manifest")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/json")
        manifest = verify_manifest(response.text)
        self.assertEqual(manifest.digest, self.world["manifest"].digest)

    def test_rejects_a_non_post_signal_request(self):
        self.assertEqual(self.client.get("/ccp").status_code, 405)


if __name__ == "__main__":
    unittest.main()
