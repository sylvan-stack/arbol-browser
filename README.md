# Arbol Browser

Arbol Browser is an independent component of Arbol 2. ABR-1 implements its
package foundation: typed contracts, command dispatch, private macOS process
support and test-free candidate compilation. The local preview below is
available for User Demos. The ordinary signed release requires qualification.

## First User Demo

The local preview runs on the pinned Electron runtime on macOS arm64. It
starts with disposable state and stays in the terminal until you close it.
Run the dependency installation below once, then start the demo.

```sh
npm run demo -- --fixture
```

Enter these commands one at a time in the preview terminal.

```text
fill #message My unsaved draft
click #increment
show
hide
click #increment
inspect #count
show
quit
```

At the first `show`, read the document ID, timer and field in the window.
You can click **Increase count** in the window too. After `hide`, the
terminal can still act on the page. At the second `show`, the original ID
and draft are still present and the timer and count have advanced.

Use `--url https://example.com/` to start with your own address or
`--visible` to show the window immediately. `go URL` navigates the selected
tab. `open URL` creates another live tab. Use `tabs` to find tab IDs and
`tab ID` to select one. `status` shows the current window and Dock state.
Page actions accept ordinary CSS selectors. Each command responds with JSON.

### Sign in to two accounts on one site

Start the preview with `npm run demo -- --visible`. Open the first login
profile and sign in directly in the window. Then open the second profile and
sign in to the other account.

```text
login https://www.kimi.ai/code/console first
login https://www.kimi.ai/code/console second
tabs
```

`tabs` includes the profile name and tab ID. Use `tab ID` to choose an
account and `hide` to keep working headlessly. Use the same hostname and
label to reopen a saved login, or omit the label to select `primary`.
Use `open URL` for ordinary tabs in the shared `default` profile. `go URL`
keeps the selected tab's profile, and redirects stay with the login tab.
Named logins are saved under `~/.arbol/browser-preview/`. Default website
data and fixture runs are disposable.

| | |
|---|---|
| Package | `@sylvan-stack/arbol-browser` 1.0.0 |
| Checkout | `~/repos/sylvan-stack/arbol-browser`, shared `main` |
| Code repository | `sylvan-stack/arbol-browser` |
| Specifications | `~/Artifacts/arbol-browser/specs/README.md`, accepted BRW-0 through BRW-4 |
| Protocols | Browser contract 1; profile format 1; private native ABI 1 (not implemented here) |

## Compile and package a candidate

Development requires Node/npm, Apple's command-line compiler and Node-API C
headers. `NODE_API_HEADERS` may select the development header directory; the
compiler otherwise looks in `/opt/homebrew/include/node` and
`/usr/local/include/node`. The process addon uses Node-API 8. No Electron or
Chromium source checkout/build is involved.

```sh
npm ci --ignore-scripts --no-audit --no-fund
node node_modules/electron/install.js
npm run compile
npm run package:candidate -- --out /tmp/arbol-browser-candidate --build 1
```

These are test-free commands. The explicit Electron dependency-install step
obtains the pinned stock distribution at build time. Compilation checks generated
type freshness, compiles 84 named schema roots and 26 self-contained public tool
schemas, type-checks/emits TypeScript and compiles the small process addon with
warnings as errors. Packaging refuses stale source/compiled digests and existing
payload destinations. Use a new destination outside the checkout each time.
`--build` is a required hexadecimal candidate identifier; this example neither
allocates nor qualifies numbered Build 1.

The supported target remains exactly Electron 45.3.2 / Chromium 156.0.8078.100 /
Node 24.22.2 / Node-API 10 / modules 150 / macOS 27.0.1 arm64. Candidate metadata
records this declared target and actual payload hashes; it is not the qualified,
signed native `BuildCompatibility` manifest or evidence that this tuple passes
production admission.

A candidate contains `bin/arbol-browser`, the stock app under
`runtime/Electron.app`, bundled CLI plus compiled modules under `lib/`,
`native/platform.node`, production dependencies/licenses and `metadata.json`.
The launcher executes its bundled runtime, so packaged invocation installs
nothing and needs neither this checkout nor global Node. `info` reads packaged
component metadata and computes the state-directory location without importing
Electron, loading an addon, inspecting profiles, opening sockets or starting a
host. The source package's bin path describes that staged layout; npm linking
an unbuilt checkout is not an installation path.

`metadata.json` inventories payload files and symlink targets with SHA-256,
excluding itself and external Build-registry records/logs. It carries a source
inventory digest and explicitly records blocked admission and absent native
input/watchdog capabilities. `dist/compile-record.json` retains the exact source,
library, addon and bundled-entry digests used for packaging.

<!-- sources:
arbol-browser:@code/scripts/compile.mjs
arbol-browser:@code/scripts/compile-platform.mjs
arbol-browser:@code/scripts/package-base.mjs
arbol-browser:@artifact/specs/04-native-input-and-renderer-health.md#Version-1 support manifest and release boundary
-->

## Source and service interfaces

| Location | Responsibility |
|---|---|
| `src/contracts/*.schema.json` | Byte-identical copies of the four accepted normative bundles |
| `src/contracts/schema.ts` | Schema-derived type generation, exact definition validators and isolated public tool schemas |
| `src/contracts/generated.ts` | Generated `ContractTypes` and `Contract<K>`; runtime validators enforce value/conditional constraints |
| `src/contracts/errors.ts` | Closed browser error vocabulary and CLI exit-code handling |
| `src/cli/parse.ts`, `main.ts` | Exact commands/options, JSON management output, MCP-only stdout and redacted diagnostic codes |
| `src/runtime/ports.ts` | Injected `ProfilePort` and `ProcessPort`, independent adapter stdio lifetime and candidate metadata types |
| `src/runtime/bootstrap.ts` | Missing-native refusal; no page or shell creation |
| `src/runtime/platform.ts`, `platform.mm` | Explicitly loaded private kernel-lock and verified process/peer-identity port |

ABR-2 supplies `ProfilePort.list/create/remove`. ABR-3 supplies `ProcessPort`
arbitration/open/close and per-client adapter lifetime. `runCli` accepts those
ports; default foundation ports always refuse their missing stages. Management
commands print one JSON result/error and use exits 0/2/3/4/5/70. MCP stdout is
reserved for its transport, including failures; no MCP server is implemented yet.
Leading `-v` belongs to the common launcher. No successful open/close, control,
page or transport result is fabricated.

`loadPlatform()` returns a private injected `PlatformPort`: `tryLock(path)` is
nonblocking and returns a retained `HeldLock` or contention; `assertIdentity()`
revalidates inode/device/UID against the published lock path; `release()` closes
without unlinking. Callers validate canonical private ancestors and retain locks
through engine/helper exit and flush. `processIdentity(pid)` returns the Darwin
kernel unique-start id, or null only for ESRCH; uncertain identity refuses.
`peerIdentity(fd)` requires an owner-UID connected Unix stream and checks peer
PID, audit-token PID version and kernel start identity. This addon supplies no
native input enforcement, page authority or raw agent method. Startup deadlines,
profile-instance checks, readiness and verified stale-runtime cleanup remain the
caller's responsibility; there is no lockfile or PID-only fallback.

<!-- sources:
arbol-browser:@code/src/cli/main.ts
arbol-browser:@code/src/cli/parse.ts
arbol-browser:@code/src/contracts/schema.ts
arbol-browser:@code/src/runtime/ports.ts
arbol-browser:@code/src/runtime/bootstrap.ts
arbol-browser:@code/src/runtime/platform.ts
arbol-browser:@code/src/runtime/platform.mm
arbol-browser:@artifact/specs/00-the-browser-component.md#Interface
arbol-browser:@artifact/specs/00-the-browser-component.md#Startup arbitration and local identity
-->

## Qualification and integration limits

No behavioral test, fixture, test inventory, test-running Build, GUI/native
qualification, browser launch, profile mutation, signing upload or installation
is part of ABR-1. ABR-4 owns foundation qualification. `arbol-build.json` retains
an explicitly failing gate until ABR-4 supplies the real gate; compilation and
candidate packaging cannot mark a normal Build working. Never activate an
incomplete candidate as the normal browser. Native input/manifest/watchdog,
complete MCP tools and final distribution qualification remain later work.

Browser indexing is currently disabled and the configured Mycel store is
unreachable. Source declarations are retained for reconciliation; ingest,
indexed-origin verification, embeddings and retrieval are deferred and are not
claimed by static compilation. The Browser artifact corpus is pre-existing
untracked material with no publication remote; this Beat preserves it.

## Sylvan Stack 2

| Repository | Package | Version | Artifact corpus | Artifact repository |
|---|---|---|---|---|
| `arbol` | `@sylvan-stack/arbol` | 2.0.0 | `~/Artifacts/arbol` | `sylvan-stack/arbol-artifacts` |
| `arbol-root` | `@sylvan-stack/arbol-root` | 1.0.0 | `~/Artifacts/arbol-root` | `sylvan-stack/arbol-root-artifacts` |
| `arbol-trunk` | `@sylvan-stack/arbol-trunk` | 1.0.0 | `~/Artifacts/arbol-trunk` | `sylvan-stack/arbol-trunk-artifacts` |
| `arbol-claude-driver` | `@sylvan-stack/arbol-claude-driver` | 1.0.0 | `~/Artifacts/arbol-claude-driver` | `sylvan-stack/arbol-claude-driver-artifacts` |
| `arbol-codex-driver` | `@sylvan-stack/arbol-codex-driver` | 1.0.0 | `~/Artifacts/arbol-codex-driver` | `sylvan-stack/arbol-codex-driver-artifacts` |
| `arbol-classifier` | `@sylvan-stack/arbol-classifier` | 1.0.0 | `~/Artifacts/arbol-classifier` | `sylvan-stack/arbol-classifier-artifacts` |
| `arbol-pi-driver` | `@sylvan-stack/arbol-pi-driver` | 1.0.0 | `~/Artifacts/arbol-pi-driver` | `sylvan-stack/arbol-pi-driver-artifacts` |
| `arbol-browser` | `@sylvan-stack/arbol-browser` | 1.0.0 | `~/Artifacts/arbol-browser` | `sylvan-stack/arbol-browser-artifacts` |
| `mycel` | `@sylvan-stack/mycel` | 2.0.0 | `~/Artifacts/mycel` | `sylvan-stack/mycel-artifacts` |
