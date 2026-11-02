# ADR 0007 — Recipes

Status: proposed. Date: 2026-11-02. Context: `docs/PLAN-0.3.md §6`.

## Decision

Each recipe is a profile shipped in `profiles/` with a matching leak test
(continuing from L24) that proves the recipe exposes only what it says.

| recipe | file | risk label | leak test | ships |
|---|---|---|---|---|
| git identity (env.set) | `profiles/git-identity.toml` | `none` | L25 | 0.3 |
| git identity (~/.gitconfig ro) | `profiles/git-config.toml` | `none` | L26 | 0.3 |
| ssh agent forward (T1) | `profiles/ssh-proxy.toml` | `signing` | L27 | 0.3 |
| docker T2 | `profiles/docker-socket.toml` | `root-equivalent` | L29 | 0.3 |
| docker T1 | `profiles/docker-proxy.toml` | `data`/`none` | L28 | 0.4 |
| toolchains under $HOME (rustup/nvm/mise in persistent home) | `profiles/toolchains.toml` | `none` | L30 | 0.3 |
| kvr service | `profiles/kvr.toml` | `none` | L31 | 0.3 |
| Wakil | `profiles/wakil.toml` | `none` (T0) | L32 | 0.3 |

## What each leak test asserts

Each test asserts (a) the recipe's declared exposure works (the agent can
talk to the socket / the service is up / the toolchain is on `PATH`), and
(b) the recipe does **not** expose anything else (no host paths beyond the
declared binds, no other sockets, no extra mounts in `inspect`).

- **L25** (git-identity): `git config user.name` inside the sandbox equals
  the `env.set` value; `git push` to a real remote fails (no agent); the
  host's `~/.gitconfig` is absent.
- **L26** (git-config): `~/.gitconfig` is readable; `touch ~/.gitconfig` →
  `EROFS`; `~/.ssh` is absent.
- **L27** (ssh-proxy): a sign request for an allowlisted host succeeds; a
  sign request for a different host is denied; `SSH_AGENTC.LIST_IDS` is
  denied; a non-allowlisted key is invisible.
- **L28** (docker-proxy): `docker run --privileged hello-world` is denied by
  the proxy (403); `docker run hello-world` (unprivileged, image present)
  succeeds; `docker exec` is denied; `docker pull` is denied (default
  `image_pull = "deny"`); the session `inspect` shows only the proxy socket.
- **L29** (docker-socket): `docker run --privileged` succeeds *and* `hisn run`
  printed `RISK: docker=socket is root-equivalent`; the profile has the
  matching `risk_ack`; the test cleans up the container.
- **L30** (toolchains): `rustc --version` inside the sandbox is the rustup
  one; `which cargo` is under the persistent home; `touch $CARGO_HOME/..` →
  `EROFS` (the home is a bind, ro above the home root).
- **L31** (kvr): the service socket is connectable from a second exec; the
  service dies with the session; `inspect` shows the service socket and
  nothing else.
- **L32** (wakil): the Wakil profile (T0 ssh, no docker, no forward) yields
  `RISK: none`; `hisn profile explain wakil` lists no widening capabilities;
  `inspect` equals the 0.2 plan.

## Why each recipe is the shape it is

- **git-identity (env.set):** the cheapest git identity — name/email in the
  environment, no files. Risk `none` because it is just strings; the
  sandbox cannot sign or push.
- **git-config (~/.gitconfig ro):** for tools that read `~/.gitconfig` (not
  just `GIT_*` env). ro bind of the file, not the whole `~/.git`. Risk
  `none`.
- **ssh-proxy (T1):** the first signing exposure. `per_session_agent = true`
  and `require_fido = true` so the host agent is not exposed and each sign
  requires a touch; `allow_keys` restricts to a dedicated key. Risk
  `signing`.
- **docker T1:** the default docker recipe. Risk `data` only if
  `[docker] network = "host"` (the deploy case); `none` otherwise.
- **docker T2:** root-equivalent, gated by `risk_ack`. Shipped as a recipe so
  the leak test (L29) proves the risk line prints and the ack is enforced.
- **toolchains (persistent home):** rustup/nvm/mise live under `$HOME`; a
  persistent home bind (`session.home = "/path"`) warm-caches them across
  sessions. ro above the home root is not needed (the home is rw); the test
  checks the toolchain is on `PATH` and the host `~` is absent. Risk `none`.
- **kvr service:** the first in-sandbox service. Risk `none` (the socket is
  in-sandbox only).
- **Wakil:** the integration profile. T0 ssh, no docker, no forward, the
  inner policy at the wakil defaults. Risk `none`. This is the "secure by
  default" proof: the wakil profile is the 0.2 sandbox.

## Invariants

- Each recipe either widens the boundary in a declared, labelled way or not
  at all (DO NOT ALTER #3).
- 5: the profiles are annotation-only; the inner policies map per
  `POLICY-SPEC §8`.
- 6: the leak tests (L25–L32) are the acceptance criterion.