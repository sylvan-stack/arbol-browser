# Tests: arbol-browser

The current [Test Strategy](/Users/msix/Artifacts/mycel/operations/test-strategy.md)
governs execution. ABR-32 is the current Foundation final testing Beat. The complete
inventory and individual admission reasons are in [test-tiers.json](test-tiers.json).
There were no previous retained cases or low-tier bodies to restore or archive.

The normal unit gate explicitly runs all six retained cases: `receiptRace`,
`ownershipBoundary`, `preservationBoundary`, `transportBoundary`,
`closeAcquisitionBoundary`, `startupAcquisitionBoundary`. They use the
actual packaged CLI, compiled libraries, Darwin process addon and embedded Node,
private disposable state and kernel locks/AF_UNIX sockets. They open no engine or
page. Test-only workers/dispatchers supply no successful native trust, readiness
or exit evidence. No discovery, case filter or missing-runner success exists.
Missing/commented exports or inventory drift refuse the gate.

Normal isolated Build invocation (new private paths outside the checkout):

```sh
arbol-builds build arbol-browser --repo /Users/msix/repos/sylvan-stack/arbol-browser \
  --registry-dir /absolute/new-private-run/registry --bin-dir /absolute/new-private-run/bin
```

The gate stores `result.json` and private fixture state in
`<isolated-registry>/arbol-browser/.qualification-<build>/`, outside the payload.
It verifies actual payload against metadata and records executing runtime,
source/payload/harness identities and every named pass/failure. An immutable
predecessor check uses the same complete selection:

```sh
node scripts/top-gate.mjs --candidate /absolute/immutable/package --out /absolute/new-private-output
```

Never invoke this against owner profiles or the normal selected Build registry.
The top-tier gate is foundation evidence, not full browser qualification. Native
page admission remains blocked. A tool `working` status in an isolated registry
means only its documented gate passed; it authorizes no normal installation,
default selection, native page or complete-close claim. Required unavailable
evidence is enumerated in the inventory and [MID_TIER.md](MID_TIER.md).
No test result is stored in Git.

The deadline case uses the unchanged packaged lifecycle module with testing-only
acquisition/monotonic-clock seams via Node module hooks. Actual locks/sockets are
retained strongly while a separate kernel contender/server-disconnect observation
proves cleanup before host exit. No engine/native readiness or successful exit
authority is supplied. A full pre-fix package run is expected to fail that case;
it is regression sensitivity, never a successful candidate result. Long canonical
profile paths and fictional browsing-content exclusion extend the retained
transport and profile cases. All support files are included in harness digests.

ABR-26's accepted allocation limits Foundation review to BRW-0.1, BRW-1.6,
BRW-1.10, BRW-1.13, BRW-4.11 and explicitly bounded infrastructure contributions.
The five earlier unavailable groups remain historical gaps. Full positive
host/session/compatibility/custody/close/removal is ABR-29/12; packaged MCP is
ABR-30/16; native/Driver/integration/release evidence retains its actual downstream
owner and scope. A revised Foundation pass never marks those routes passed.

The startup case imports unchanged packaged lifecycle/starter modules and uses
actual authenticated RuntimeClients, Unix peers and kernel Build/owner guards.
Lifecycle resource-return and monotonic-clock seams isolate late/post-wait/final
transfer refusal, rejected acquisition and actual stream disconnect before client
assignment. The three starter resource paths use explicitly synthetic upstream
trust/readiness predicates and a no-engine transport-fixture launch. These
predicates are testing-only, never production providers or native readiness
proof. A rejecting failed-attempt authority leaves real guard retention intact
during observation; fixture teardown after transport shutdown is not verified
production exit. Strong references/live process exclude garbage collection and
process death as the cleanup oracle. Ordinary client exchanges demonstrate only
usable resource transfer, not browser open, page control or stdio MCP. All six
cases and every helper remain in the complete normal gate/harness digest.
