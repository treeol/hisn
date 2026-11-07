# Architecture decision records

Each ADR records one decision: what was chosen, why, and what follows from it.
The code is the source of truth for behaviour; an ADR says why it is that way.
Format: title, `Status`, `Date`, a short `Origin` line, then Decision, Why, and
Consequences. Accepted ADRs are not rewritten. A correction is added as a dated
note in the same file.

| ADR | Status | Decision in one line |
|---|---|---|
| [0001](0001-profiles.md) | proposed | Profiles are an envelope around `hisn-policy/v1`, not a new policy format. |
| [0002](0002-in-sandbox-services.md) | proposed | `[[services]]` run inside the sandbox through the normal exec path. |
| [0003](0003-host-services-and-forwarding.md) | proposed | Host-side services and socket forwarding, with explicit risk labels. |
| [0004](0004-docker-access.md) | proposed | Docker access comes in three tiers: T1 proxy, T2 socket, T3 nested userns. |
| [0005](0005-ssh-git-signing.md) | proposed | SSH and git signing: host git (T0), filtering agent proxy (T1), socket (T2). |
| [0006](0006-risk-disclosure.md) | proposed | Every capability that widens the boundary carries a risk label and is disclosed. |
| [0007](0007-recipes.md) | proposed | Recipes are named, reviewable profile fragments. |
| [0008](0008-multi-agent.md) | proposed | Multi-agent use: discovery in 0.3, leases in 0.4. |
| [0009](0009-persistent-home.md) | accepted | `[home] persist` binds a host directory as the session `$HOME`. |
| [0010](0010-rootfs-and-import.md) | accepted | A read-only rootfs replaces the host toolchain dirs; `hisn rootfs import` publishes it atomically. |
| [0011](0011-ssh-agent-t1.md) | accepted | SSH agent T1 is a filtering proxy: it signs but never adds, removes or extracts keys. |
| [0012](0012-ro-src-dst-mounts.md) | accepted | `mounts.ro` accepts `src:dst` read-only binds, with `/etc` sources refused. |
| [0013](0013-rootfs-resolver-precedence.md) | accepted | On `network = "host"`, `resolv.conf` comes from the host first and the rootfs file is the last resort. |

Status `proposed` means the record was written as a design and has not been
reviewed to acceptance; the behaviour it describes is in `DESIGN.md` where it
shipped.
