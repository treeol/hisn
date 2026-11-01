# Security policy

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability**
on <https://github.com/treeol/hisn> (private vulnerability reporting). Do not
open a public issue or pull request for a suspected vulnerability.

hisn is maintained by one person. Reports are handled on a best-effort basis
with no guaranteed response time. Include the commit or version, the kernel and
distribution, the policy used, and the smallest reproduction you have.

Supported: the latest release and `main`.

## In scope

A demonstrated way for a sandboxed process (including one started with
`hisn exec`) to:

* **escape** — see, read, write, or execute anything on the host that the
  policy does not make visible (the sandbox is meant to show ENOENT for
  everything else), or end up less confined than the original command
  (capabilities, `no_new_privs`, seccomp, Landlock, environment);
* **leak** — obtain host secrets, for example from the environment or from
  masked `/etc` entries, or reach the control socket or other sessions;
* **persist a grant** — keep access to a granted path after the revoke
  (`--hard` revoke) or after the session ends, or leave a mount or a process
  behind on the host.

The binding invariants are in [docs/BRIEF.md](docs/BRIEF.md) and
[docs/DESIGN.md](docs/DESIGN.md) (§14 for `exec`). A failing leak test
(`make leaktest`) on a supported host is a valid report.

## Out of scope

Stated as non-goals in [DESIGN §1](docs/DESIGN.md) and tracked in
[docs/OPEN-POINTS.md](docs/OPEN-POINTS.md):

* kernel vulnerabilities (user namespaces, seccomp and Landlock reduce the
  kernel attack surface; they do not remove it);
* terminal escape sequences from the sandboxed command reaching your terminal
  (P8);
* network isolation when `network = "host"` (P11), and egress filtering in
  general;
* resource exhaustion beyond rlimits, and covert channels (P9);
* confidentiality of data the sandboxed command is *allowed* to read;
* the documented residual of a soft revoke (a file descriptor the process
  already holds survives; use `--hard`), DESIGN D14;
* a compromised host side: the user or the program that writes the policy and
  issues grants is trusted.

If you are unsure whether something is in scope, report it privately anyway.
