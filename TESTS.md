# Tests: arbol-browser

The current [Test Strategy](/Users/msix/Artifacts/mycel/operations/test-strategy.md)
governs execution. ABR-32 owns the Foundation testing record and ABR-8 owns
native qualification of the pinned signed ABR-42 consumer. The exact case and
scenario selection, admission reasons and unavailable routes are in
[test-tiers.json](test-tiers.json). No earlier low-tier bodies existed.

The normal Build gate executes all six Foundation cases and nine native cases.
The Foundation worker uses the ordinary candidate's packaged CLI, compiled
libraries, Darwin process addon and embedded Node with disposable state, kernel
locks and AF_UNIX sockets. The native worker uses the independently bound,
immutable ABR-42 signed consumer and separately built private fixtures. Its
representative cases cover trust, transactional install, binding lifetime,
cached routes, responder isolation, retirement, startup custody, failure custody
and independent monitor loss. There are 46 separately recorded native scenarios.
Case and scenario selection is fixed. Missing sources, results or required
observations fail the gate.

Run the normal Build with a fresh isolated registry and bin directory outside
the checkout.

```sh
arbol-builds build arbol-browser --repo /Users/msix/repos/sylvan-stack/arbol-browser \
  --registry-dir /absolute/new-private-run/registry --bin-dir /absolute/new-private-run/bin
```

The gate writes `result.json`, a Foundation worker result and private native
case directories under `<isolated-registry>/arbol-browser/.qualification-<build>/`.
It validates the ordinary candidate payload and executing Foundation runtime
against its metadata and current package source. Independently, it binds the
accepted ABR-42 consumer manifest, frozen source, compiled closure, exact signed
assembly, case/harness source and compiled fixture evidence. The Foundation
worker has its own 90-second deadline. Each native launch and external observer
has its own bounded deadline. Scenarios with a declared observation retry keep
every attempt, and a witnessed failure ends the scenario.

To repeat the complete gate against the exact ordinary package made from the
same source and a fresh private output, use:

```sh
node scripts/top-gate.mjs --candidate /absolute/immutable/package --out /absolute/new-private-output \
  --native-consumer /Users/msix/Builds/sylvan-stack/arbol-browser/ABR-42-20261115/consumer-manifest.json
```

Keep the run outside owner profiles, the normal registry and the accepted
consumer's artifact tree. The isolated `working` status covers the documented
Foundation and pinned-consumer cases. Production host start, complete family
confinement, clean close, complementary input and full release remain tracked
in [MID_TIER.md](MID_TIER.md). Evidence stays outside Git.

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
usable resource transfer, not browser open, page control or stdio MCP. All six Foundation cases and their helpers remain bound in the complete gate.
