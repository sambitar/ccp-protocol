# Quickstart — web client (requester + permission card)

A browser or React app signs a signal and lets the user decide whether a
capability may run. Private keys stay in the client.

## Sign a request

```ts
import { Requester } from "ccp-core";

const seed = crypto.getRandomValues(new Uint8Array(32));
const requester = new Requester(seed);

const signal = requester.signal({
  requestId: crypto.randomUUID(),
  grantDigest, // the digest of the grant this request runs under
  intent: "example.lookup",
  params: { item_id: "item-123" },
  issuedAt: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
  expiresAt: new Date(Date.now() + 60_000)
    .toISOString()
    .replace(/\.\d+Z$/, "Z"),
});

await fetch("/ccp", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ signal }),
});
```

The provider must map the authenticated channel to your public key. Do not
send the key inside the signal and expect it to be trusted.

## Permission card

```tsx
import { usePermissionCard } from "ccp-core/react";

function PermissionCard({ runtime, signal, publicKey, card }) {
  const { status, decision, approve, deny } = usePermissionCard({
    runtime,
    signal,
    publicKey,
    card,
  });

  if (status === "loading") return <p>Checking…</p>;
  if (status === "confirmation_required") {
    return (
      <section>
        <h2>{card.who} wants to {card.what}</h2>
        <p>{card.dataRead.join(", ")} — {card.where}</p>
        <p>{card.egress}</p>
        <button onClick={approve}>Allow</button>
        <button onClick={deny}>Deny</button>
      </section>
    );
  }
  if (status === "authorized") return <pre>{JSON.stringify(decision?.result)}</pre>;
  return <p>Request {status}</p>;
}
```

The hook submits once per signal, keeps the decision, and ignores stale
confirmations after the signal changes. Render the card fields yourself;
they come from the verified manifest (§11.4).

## Verify

```sh
cd sdk/typescript
npx vitest run test/requester.test.ts test/adapters-react.test.ts
npm run provider        # a runnable provider to point fetch() at
```
