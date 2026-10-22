"""MCP bridge behavior tests."""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
sys.path.insert(0, SDK_DIR)

from ccp.adapters.mcp import ConfirmationRequest, McpServer  # noqa: E402
from ccp.agent import Agent  # noqa: E402
from world import (  # noqa: E402
    PARAMS_SCHEMA,
    RESULT_SCHEMA,
    build_world,
)

CALL = {"item_id": "item-123"}


def build_bridge(**overrides):
    confirm = overrides.pop("confirm", None)
    world = build_world(**overrides)
    server = McpServer(
        runtime=world["runtime"],
        agent=Agent(world["requester"]),
        grant=world["grant"],
        confirm=confirm,
    )
    return world, server


def body(result):
    return json.loads(result.content[0]["text"])


class McpBridgeListingTests(unittest.TestCase):
    def test_lists_the_granted_intent_with_its_schemas(self):
        _, server = build_bridge()
        self.assertEqual([tool.name for tool in server.tools],
                         ["example.lookup"])
        tool = server.tools[0]
        self.assertEqual(tool.input_schema, PARAMS_SCHEMA)
        self.assertEqual(tool.output_schema, RESULT_SCHEMA)
        self.assertIn('"example.lookup"', tool.description)
        self.assertIn("untrusted", tool.description)

    def test_refuses_a_grant_bound_to_another_key(self):
        world = build_world()
        with self.assertRaises(ValueError) as caught:
            McpServer(runtime=world["runtime"],
                      agent=Agent(world["provider"]),
                      grant=world["grant"])
        self.assertIn("not bound", str(caught.exception))


class McpBridgeCallTests(unittest.IsolatedAsyncioTestCase):
    async def test_runs_an_authorized_call_and_returns_data(self):
        _, server = build_bridge()
        result = await server.call_tool("example.lookup", CALL)
        self.assertFalse(result.is_error)
        self.assertEqual(body(result), {"item_id": "item-123",
                                        "name": "Widget"})
        self.assertEqual(result.structured_content,
                         {"item_id": "item-123", "name": "Widget"})

    async def test_refuses_an_ungranted_tool(self):
        _, server = build_bridge()
        result = await server.call_tool("files.search", {})
        self.assertTrue(result.is_error)
        self.assertEqual(body(result)["outcome"], "intent_not_allowed")

    async def test_refuses_non_object_arguments(self):
        _, server = build_bridge()
        result = await server.call_tool("example.lookup", "item-123")
        self.assertTrue(result.is_error)
        self.assertEqual(body(result)["outcome"], "invalid_request")

    async def test_surfaces_confirmation_without_a_host(self):
        _, server = build_bridge(confirmation="per_action")
        result = await server.call_tool("example.lookup", CALL)
        payload = body(result)
        self.assertTrue(result.is_error)
        self.assertEqual(payload["outcome"], "confirmation_required")
        self.assertIsInstance(payload["pending_id"], str)
        self.assertNotIn("error", payload)

    async def test_executes_after_the_host_approves(self):
        seen = []

        def confirm(request):
            seen.append(request)
            return True

        _, server = build_bridge(confirmation="per_action", confirm=confirm)
        result = await server.call_tool("example.lookup", CALL)

        self.assertFalse(result.is_error)
        self.assertEqual(body(result), {"item_id": "item-123",
                                        "name": "Widget"})
        self.assertEqual(len(seen), 1)
        self.assertIsInstance(seen[0], ConfirmationRequest)
        self.assertEqual(seen[0].intent, "example.lookup")
        self.assertEqual(seen[0].params, CALL)
        self.assertEqual(seen[0].card.who, "Example Service")
        self.assertEqual(seen[0].card.what,
                         "Look up one item requested by the consumer")

    async def test_does_not_execute_when_the_host_denies(self):
        _, server = build_bridge(confirmation="per_action",
                                 confirm=lambda request: False)
        result = await server.call_tool("example.lookup", CALL)
        self.assertTrue(result.is_error)
        self.assertEqual(body(result)["outcome"], "cancelled")
        self.assertNotIn("error", body(result))

    async def test_treats_a_thrown_host_decision_as_denial(self):
        def confirm(request):
            raise RuntimeError("no trusted ui")

        _, server = build_bridge(confirmation="per_action", confirm=confirm)
        result = await server.call_tool("example.lookup", CALL)
        self.assertEqual(body(result)["outcome"], "cancelled")

    async def test_reports_limit_exceeded(self):
        _, server = build_bridge(limits={"calls_per_hour": 1})
        first = await server.call_tool("example.lookup", CALL)
        second = await server.call_tool("example.lookup", CALL)
        self.assertFalse(first.is_error)
        self.assertEqual(body(second)["outcome"], "limit_exceeded")
        self.assertEqual(body(second)["error"], "limit_exceeded")

    async def test_reports_a_revoked_grant(self):
        _, server = build_bridge(grant_state="revoked")
        result = await server.call_tool("example.lookup", CALL)
        self.assertEqual(body(result)["outcome"], "grant_revoked")


if __name__ == "__main__":
    unittest.main()
