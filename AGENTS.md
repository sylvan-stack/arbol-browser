# Arbol Browser agent instructions

Read the accepted BRW specifications and the owning Beat's current plan and
hand-over before changing this shared checkout. Use Forester bookings and Step
Intentions, managed publication, and the existing Git identity. Keep runtime
qualification, tests and test-running Builds with their eligible testing Beat.
Default page admission remains closed until the complete qualified host exists.

## Arbol design-system synchronization

The shared design reference is the private repository
https://github.com/sylvan-stack/arbol-design-system.

Every user-requested UI/UX design change must also update that repository as
part of the same task. Do not change only this application's design and leave
the shared reference stale. This includes styling, tokens, components, layouts,
navigation, responsive behavior, forms, dialogs, states and accessibility.
Backend-only changes with no observable UI/UX effect are exempt.

Before implementing a design change, locate the design-system checkout or use
`gh repo clone sylvan-stack/arbol-design-system`, then read its root AGENTS.md
and relevant design contracts. Follow its synchronization workflow: reuse or
generalize shared components, update executable stories and affected sections
and pages, document the resulting contract, and validate both implementations.
Keep production integrations in this application and fictional fixtures in the
design system. Preserve unrelated work in both repositories.

When delivering, identify the changes and validation in both repositories and
link their commits or PRs when available. Follow repository delivery rules and
the user's publishing instructions. If access or another dependency blocks
the shared update, explicitly report the unfinished work; do not claim the
design task is complete or remotely synchronized. Explicit user instructions
limiting scope or requesting a temporary experiment take precedence; disclose
any resulting divergence.

The full maintained workflow is in the design-system repository's
[root AGENTS.md](https://github.com/sylvan-stack/arbol-design-system/blob/main/AGENTS.md).
