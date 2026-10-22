# TypeScript Web + Provider Adapters Plan

**Goal:** Meet providers and web clients in their own frameworks: an Express provider middleware, a Next.js signal handler, a React permission-card hook, and a runnable example provider.

**Architecture:** Adapters ship as subpath exports of `ccp-core` (`ccp-core/express`, `/next`, `/react`) so consumers pull only what they use. `react` is an optional peer dependency. The Next handler uses standard Web `Request`/`Response`, so it needs no Next dependency to implement or test. Adapters stay out of the root `index.ts` to keep the core bundle free of express/react.

**Tech Stack:** TypeScript 5, ESM, Vitest (with `jsdom` for React), `express`, React 18, `@testing-library/react`. No new runtime dependencies for the core.

**Spec:** `CCP_Working_Draft_v0.5.md`; contract: `test-vectors/`.

## Global Constraints

- All 51 frozen vectors and the 105 existing tests stay green.
- `src/` (kernel + adapters) must not import Node built-ins.
- Adapters never bypass the `Runtime`; they only parse a request, resolve the sender key, and call `submit` / `confirm`.
- Wire fields stay snake_case; adapter option names are camelCase.
- Commit only when the user asks.

## File map

| File | Responsibility |
| --- | --- |
| `sdk/typescript/src/adapters/express.ts` | `providerMiddleware({ runtime, keyResolver })` |
| `sdk/typescript/src/adapters/next.ts` | `createSignalHandler({ runtime, keyResolver })` (Web Request/Response) |
| `sdk/typescript/src/adapters/react.ts` | `usePermissionCard(...)` headless hook |
| `sdk/typescript/test/world.ts` | shared end-to-end fixture |
| `sdk/typescript/test/adapters-express.test.ts` | real HTTP round-trip |
| `sdk/typescript/test/adapters-next.test.ts` | `Request` → `Response` |
| `sdk/typescript/test/adapters-react.test.ts` | render hook + approve/deny (jsdom) |
| `examples/provider-node/server.ts` | runnable provider |
| `sdk/typescript/package.json` / `tsconfig*.json` | exports, peers, build/typecheck |

---

### Task 1: Package config

**Files:** Modify `sdk/typescript/package.json`, `tsconfig.json`; create `tsconfig.test.json`.

- [ ] Add `exports` for `.`, `./express`, `./next`, `./react`; `peerDependencies` `{ "react": ">=18" }` with `peerDependenciesMeta.react.optional`; dev deps `express`, `@types/express`, `react`, `react-dom`, `@types/react`, `@types/react-dom`, `@testing-library/react`, `jsdom`.
- [ ] `tsconfig.json` builds `src` only (`rootDir: "src"`, `outDir: "dist"`); `tsconfig.test.json` extends it with `noEmit` and `include: ["src", "test"]`.
- [ ] Scripts: `build` = `tsc -p tsconfig.json`; `typecheck` = `tsc -p tsconfig.test.json`.
- [ ] `npm install`; `npm run build` emits `dist/index.js` and `dist/adapters/*.js`; `npm run typecheck` passes.

### Task 2: Shared world fixture

**Files:** Create `sdk/typescript/test/world.ts`; modify `sdk/typescript/test/runtime.test.ts` to import it.

**Interfaces:** `buildWorld(options)`, `signalFor(world, options)`, plus the schemas/intents/store constants and seeds.

- [ ] Move the fixture out of `runtime.test.ts`; runtime tests stay 14/14.

### Task 3: Express middleware

**Files:** Create `sdk/typescript/src/adapters/express.ts`; Test `test/adapters-express.test.ts`.

**Interfaces:**
```ts
providerMiddleware({ runtime, keyResolver }): RequestHandler
keyResolver: (req) => Uint8Array | undefined | Promise<...>
```

- [ ] Test: app with `express.json()`, start on port 0, POST `{ signal }`; expect 200 `authorized`; tampered signal → 403; missing body → 400.
- [ ] Map outcomes: `authorized`/`confirmation_required` → 200; `unauthenticated`/`no_matching_grant` → 403; `invalid_request` → 400; else 409.

### Task 4: Next signal handler

**Files:** Create `sdk/typescript/src/adapters/next.ts`; Test `test/adapters-next.test.ts`.

**Interfaces:** `createSignalHandler({ runtime, keyResolver }): (request: Request) => Promise<Response>`.

- [ ] Test: `new Request(url, { method: "POST", body })` → 200 JSON decision; bad JSON → 400; unknown sender → 401.

### Task 5: React permission-card hook

**Files:** Create `sdk/typescript/src/adapters/react.ts`; Test `test/adapters-react.test.ts` (`// @vitest-environment jsdom`).

**Interfaces:**
```ts
usePermissionCard({ runtime, signal, publicKey, card }): {
  status: "loading" | "authorized" | "confirmation_required" | "rejected" | "cancelled";
  card; decision; approve(); deny();
}
```

- [ ] Test with `renderHook`: a `per_action` grant yields `confirmation_required`; `approve()` → `authorized`; `deny()` → `cancelled`. Submit once per signal (a ref guards re-submission).

### Task 6: Example provider

**Files:** Create `examples/provider-node/{server.ts,README.md}`.

- [ ] A runnable server that serves one manifest and accepts signed signals via the Express adapter. Add a `provider` npm script.

### Task 7: Full gate

- [ ] `npm run typecheck`, `npm run build`, `npx vitest run` all green.
