# Tests: arbol-browser

The current [Test Strategy](/Users/msix/Artifacts/mycel/operations/test-strategy.md)
governs execution. ABR-32 owns the Foundation testing record. ABR-47 owns
the current native qualification of the pinned signed ABR-46 consumer,
retaining ABR-8's earlier cases and recorded limitations. The exact case and
scenario selection, admission reasons and unavailable routes are in
[test-tiers.json](test-tiers.json). No earlier low-tier bodies existed.

The default Build uses the explicit `promotionUnitTests` selection in
`arbol-build.json`. Browser currently has no standalone unit tests. Its Build
record carries the empty declaration and the results of any checks that ran.
Signing and artifact verification follow the release procedure.

The separately requested `browser-verification` check selects all six
Foundation cases, ten Native cases with 50 scenarios, and five Control cases.
ABR-12 owns the recorded current-host evidence. When expressly selected for a
Build that produces a signed release image, it also runs `releaseArtifactIdentity`
against the exact signed disk image named by the original Building record.
The case mounts that image read-only and verifies its Publisher, Build, runtime,
native executables, and full app inventory. It leaves the selected installation
and notarization to the separate ABR-25 release operations.
The Foundation worker calls the ordinary candidate's physical compiled `runCli`
through explicit no-integration fixture ports, compiled
libraries, Darwin process addon and embedded Node with disposable state, kernel
locks and AF_UNIX sockets. The native worker uses the independently bound,
immutable ABR-46 signed consumer and separately built private fixtures. Its
representative cases cover trust, transactional install, binding lifetime,
cached routes, responder isolation, retirement, startup custody, failure custody
independent monitor loss, and source-sensitive plus signed supported helper exit.
There are 50 separately recorded native scenarios.
Case and scenario selection is fixed. Missing sources, results or required
observations fail the gate.

Get the user's explicit approval for the requested Browser verification scope,
including any launch or rerun. Choose a focused integration check when it can
answer the question. To request the complete retained verification suite, add
the named check to a Build with a fresh isolated registry and bin directory
outside the checkout.

```sh
ARBOL_BROWSER_MANUAL_FOCUS=1 arbol-builds build arbol-browser --repo /Users/msix/repos/sylvan-stack/arbol-browser \
  --registry-dir /absolute/new-private-run/registry --bin-dir /absolute/new-private-run/bin \
  --check browser-verification
```

Native scenarios that depend on real keyboard focus show a passive window
titled `Arbol Browser test · Click title bar · …`. When it appears, click its
title bar within 20 seconds and leave it selected until it finishes. Click the
title bar of each new fixture when it appears. If you leave a fixture, it stops
sending focus-dependent input and reports the missing evidence. Timeout or
missing focus evidence leaves the scenario unqualified.

The verification check writes `result.json`, a Foundation worker result and
private native case directories under
`<isolated-registry>/arbol-browser/.verification-<build>/`.
It validates the ordinary candidate payload and executing Foundation runtime
against its metadata and current package source. Independently, it binds the
accepted ABR-46 consumer manifest, frozen source, compiled closure, exact signed
assembly, case/harness source and compiled fixture evidence. The Foundation
worker has its own 90-second deadline. Each native launch and external observer
has its own bounded deadline. Scenarios with a declared observation retry keep
every attempt, and a witnessed failure ends the scenario.

Control runs the actual `<Build>/bin/arbol-browser` sealed production entry while
the ordinary record is still `building`. Its private selection hint comes from
that real record, canonical layout and actual `.uses` inode; it supplies no
native authority. The gate cannot force a record working or repeat Control
through an arbitrary staged package. Use a clean detached managed testing commit
and fresh private registry/bin/state under canonical non-writable ancestors
beneath `/Users/msix/Builds/sylvan-stack/arbol-browser/`, with the explicit
verification command above.

The five Control cases cover startup arbitration and listener observations,
ungranted connection isolation and release, genuine renderer hang latching,
separate persistent website Sessions, and complete-close observations. Every
selected case remains required. The gate binds bodies, support and inventory
before and after use, exact sealed assembly and separate lane results. Control
supplies no Tools provider or privileged shell fixture.

Keep the run outside owner profiles, the normal registry and the accepted
consumer's artifact tree. Read the named check and its result to see which
Foundation and pinned-consumer cases ran. Production host start, complete family
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

ABR-47 renews the exact consumer binding and adds source-bound census controls,
supported signed helper exit, a distinct still-live primary timeout, and the
positive cached aria-actions cycle with its original AX tab attached through
retirement. All earlier cases/scenarios remain selected. The census record binds
the driver, effective frozen shared header, compile command and actual binary;
the verification check rechecks those bytes and all four effective callback headers.
The one-time published-predecessor sensitivity is separate from candidate gate
results. Natural primary SIGHUP remains distinct from measured timeout SIGKILL.
Actual installed route guards and sealed features do not qualify unmeasured
complementary effects, physical input or configured text services. Production
agent admission remains false; no normal registry, installed profile or real
account is used. See MID_TIER.md for the explicit limitations.
