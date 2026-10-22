# wist-center

Aggregation and governance service for the **wist** control plane.

[![Build & Test](https://github.com/dayu-sec/wist-center/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/dayu-sec/wist-center/actions/workflows/build-and-test.yml)
[![codecov](https://codecov.io/gh/dayu-sec/wist-center/branch/main/graph/badge.svg)](https://codecov.io/gh/dayu-sec/wist-center)
[![dependency status](https://deps.rs/repo/github/dayu-sec/wist-center/status.svg)](https://deps.rs/repo/github/dayu-sec/wist-center)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`wist-center` sits above the per-fleet [`wist-gateway`](https://github.com/dayu-sec/wist-gateway)
instances. Each gateway registers with the center, pulls its initial `config.toml` from it, and
reports gateway and agent status back to it. On top of that plane the center exposes the admin API
consumed by [`wist-center-web`](https://github.com/dayu-sec/wist-center-web): fleet status,
instance provisioning, customer binding, release publishing, and upgrade-plan approval.

Gateway state lives in PostgreSQL, or in a JSON file when no database is configured. Time-series
history is optional (VictoriaMetrics) and so is S3-compatible object storage for release
artifacts.

## Features

- **Gateway onboarding** — one-time **link token** (renamed from “bootstrap”), initial `config.toml` provisioning with
  a derived RegistToken, plus client-certificate (mTLS) rotation and verification.
- **Status ingestion** — accepts gateway status reports and the per-gateway agent status lists;
  optionally pushes each report to VictoriaMetrics for history.
- **Fleet admin API** — gateway list and status cards, per-gateway status / uptime / history,
  agent lists, per-agent history, and lifecycle transitions.
- **Instance provisioning** — create management instances, bind gateways to customers, and read
  the initial config from the admin side.
- **Release and upgrade** — publish `wist-agentd` / `wist-gateway` artifacts to a local directory
  or object storage, and create / list / approve multi-step upgrade plans.
- **Auth and rate limiting** — admin bearer token (SHA-256, constant-time compare) and gateway
  client certificates (mTLS, verified against CA-G on the TLS handshake); per-peer-IP rate limiting
  that deliberately ignores the spoofable `x-real-ip` and `x-forwarded-for` headers.
- **Two storage backends** — PostgreSQL when a database URL is set, otherwise a plain JSON file
  store, so `cargo test` and local runs need no infrastructure.

## Building

```bash
cargo build --release
```

This produces the `wist-center` binary in `target/release/`.

## Quick start

```bash
cargo run
```

With no configuration at all, the service listens on `127.0.0.1:3100`, keeps its state under the
config file's directory (`<config dir>/state/`; with no config file, that is the working
directory), and runs *without* admin authentication — that mode is for local development only.

To bring up PostgreSQL and VictoriaMetrics as well:

```bash
docker compose up -d          # PostgreSQL :55432, VictoriaMetrics :8428

export WARP_INSIGHT_CENTER_DATABASE_URL=postgres://demo:demo@127.0.0.1:55432/insight_demo
export WARP_INSIGHT_CENTER_VICTORIAMETRICS_URL=http://127.0.0.1:8428
# Admin token is NOT an env var: set `server.admin_token` in the config file
# (e.g. ./wist-center.toml). Leave it empty → local dev runs with no auth.

cargo run
```

The credentials in `docker-compose.yml` (`demo` / `demo`) are demo-only. The PostgreSQL schema is
applied automatically from [`docker/initdb/01_schema.sql`](docker/initdb/01_schema.sql): the compose
`initdb` runs it on the **first** start of the data volume, and the center re-applies the same
(idempotent) file on **every** start — so a schema change (a new column) also lands on databases
that already exist. Re-applying is best-effort: a database user without DDL rights only gets a
startup warning, and the operator applies the file by hand.

Exported variables only last for that shell, so the admin token changes on every launch. To keep one
around, use a config file instead:

```bash
wist-center init-config          # ./wist-center.toml, random admin token + HMAC secret
cargo run
```

[`examples/local-dev.toml`](examples/local-dev.toml) is the same thing spelled out, ready to copy.
See [Configuration](#configuration).

## Configuration

Settings are resolved in three layers, each overriding the one before it; see
[`src/config.rs`](src/config.rs) for the full definition.

1. the TOML file at `./wist-center.toml` (relative to the working directory; point
   `WIST_CENTER_CONFIG` elsewhere to change that; a missing file is simply skipped, so the binary
   also runs on environment variables alone),
2. `WARP_INSIGHT_CENTER_*` environment variables,
3. built-in defaults.

### Configuration file

Generate a file rather than hand-editing one — `init-config` fills in freshly random credentials:

```bash
wist-center init-config                      # ./wist-center.toml
wist-center init-config /etc/wist-center.toml
```

It prints the generated admin token and HMAC secret once, and refuses to overwrite an existing
file (rotating those credentials invalidates the token you already handed out, so the overwrite has
been made deliberate: delete the file or pass another path). This is what makes the admin token
survive restarts — otherwise it has to be re-pasted into the admin UI every launch.

A ready-to-run example, with every key spelled out and the production caveats inline, lives at
[`examples/local-dev.toml`](examples/local-dev.toml):

```bash
cp examples/local-dev.toml ./wist-center.toml
```

Its values are the built-in defaults (`admin_token = "dev-admin-token"` is a weak dev-only value),
so it doubles as the annotated reference for the schema. [`wist-center.toml`](wist-center.toml) in
the repository root is the template `init-config` renders and defines the generated shape; it holds
exactly the same set of keys, which a test keeps that way.

In the file:

- values may reference the environment as `${VAR}`; an unset variable is a load error.
- relative paths (`store.store_path`, `artifacts.dir`, `security.ca_cert_path`) resolve against the
  directory holding the file.
- every key maps to the environment variable of the same meaning in the table below, so the file is
  simply a place to put the values that should outlive a shell. (`enrollment.gateway_credentials`
  is a TOML array of `gateway_id:token` entries; the variable takes the same entries comma-joined.)
- the file is the **rendered / deliverable** half. The site fact `server.public_url` lives in the
  **site layer**, split into a **declaration** and its **values**: the declaration
  (`wist-center-pub.toml`, next to this one, or the path given by `WARP_INSIGHT_CENTER_PUB_CONFIG`)
  holds only the `${VAR}` reference; the value comes from the process environment or the sibling
  `.env` (next to the declaration, or the path given by `WARP_INSIGHT_CENTER_ENV_FILE`). The
  declaration is loaded **alongside** the main file: sections may overlap, but a **leaf key in both
  files is refused at startup** (a key has exactly one owner). Re-rendering the main file therefore
  never clobbers the site's public URL, and re-rendering the declaration never clobbers the value
  (the value is not in there).

### Package sources (auto-detect the latest)

The install-package entry does **not** ask for a version after the first import. It takes the most
recently recorded version as the base and asks for the newest one: GitHub releases are listed
(newest first); a COS-only deployment probes the next patch versions under the configured prefix
(`v0.1.46-alpha` → `v0.1.47-alpha`, …, stopping after three consecutive misses). When a newer
version is found the page fills the artifact URLs and digests automatically and leaves the submit
button. The first import (nothing recorded) uses the GitHub release list; a COS-only component
without a recorded version keeps the manual version field. `GET /api/v1/admin/package-sources/latest`
backs this; `GET /api/v1/admin/package-sources` returns the configured locations (never credentials).
No background polling or bucket listing is involved — the COS bucket stays public-read. Set
`WIST_CENTER_GITHUB_TOKEN` (fallback `GITHUB_TOKEN`): anonymous GitHub requests are limited to
60/hour, and the auto-detection makes two calls per page load.

```toml
[packages]

[[packages.sources]]
component = "wist-agentd"                # same segment as /api/v1/admin/releases/:component
github_repo = "dayu-sec/wist-agentd"     # https://github.com/<owner>/<repo>/releases/tag/<version>
cos_bucket = "github-1347593047"           # <bucket>/<prefix>/<version>
cos_prefix = "wist-agentd"               # defaults to the repository name
cos_region = "ap-hongkong"              # optional; when set the virtual-host URL carries the region
```

`GET /api/v1/admin/package-sources` returns these locations (never credentials). GitHub and COS can
be configured together; if neither is configured the page falls back to pasting a full URL.

### Rule / config publish entries (`wparse-rules` / `wparse-infra`)

Two admin entries read a repo's tag list and publish a selected tag through the **same**
`gateway_commands` queue used by the wparse-proxy. gwlinkd's `wparse_relay` executes it with no
gateway change: the command is still `kind=proxy` + `POST /admin/v1/reloads/model`.

Publishing goes through the **same approval gate as every other release**: `POST …/publish` only
creates a rollout plan (`action = wparse-release`, single phase, `status = draft`) and returns
`201` with that plan. Nothing is queued yet. The plan shows up on the *release execution* page; once
an operator approves it (`POST /api/v1/admin/rollout-plans/approve`), the center enqueues one reload
per target and backfills each entry from the command result. This action is **center-executed**, so
the gateway-facing `GET /api/v1/gateway/upgrade-plan` skips it.

```http
GET  /api/v1/admin/wparse/repos
GET  /api/v1/admin/wparse/repos/{name}/tags?limit=100&refresh=false
POST /api/v1/admin/wparse/repos/{name}/publish        # 201 → { plan, repo, group, tag, commit, tag_verified }
POST /api/v1/admin/rollout-plans/approve              # { plan_id } → draft becomes rolling + commands enqueued
```

```toml
[wparse_release]
enabled = true
# 0 is rejected; the page uses this TTL before asking the provider again.
tag_cache_seconds = 60
# false = the page may only pick a tag from the list.
allow_manual_tag = false
max_targets = 20

[[wparse_release.repos]]
name = "wparse-rules"          # fixed route segment used by the UI
group = "models"               # models | infra
provider = "cnb"              # cnb | github | manual
repo = "dy-sec/jingang-cust/wist/wp-rules"
token = "${SEC_WP_GIT_PUB_TOKEN}"   # CNB access token needs repo-release:r
tags_limit = 100

[[wparse_release.repos]]
name = "wparse-infra"
group = "infra"
provider = "cnb"
repo = "dy-sec/jingang-cust/wist/wp-infra"
token = "${SEC_WP_GIT_PUB_TOKEN}"
tags_limit = 100
```

The tag list is read-only and works even when `[wparse_proxy].enabled = false`; publishing requires
both `[wparse_release].enabled` and an active wparse-proxy (PostgreSQL). Tokens are never returned by
the API and are expanded from `${SEC_...}`, so the same `.wist` read token used by the Git Proxy can
be reused. Approval needs an active wparse-proxy as well — if the queue is unreachable the plan stays
`draft` instead of silently becoming an approved plan that never dispatched anything.

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `WARP_INSIGHT_CENTER_LISTEN` | `127.0.0.1:3100` | HTTP listen address. |
| `WARP_INSIGHT_CENTER_PUBLIC_URL` | `https://center.warpinsight.example` | Externally reachable base URL, used to build the gateway init URL. Must fall inside the control-center certificate SANs. Overrides the site layer. |
| `WARP_INSIGHT_CENTER_HMAC_SECRET` | dev placeholder | HMAC-SHA256 key used to derive RegistTokens. **Must be set in production.** Rotating it does not invalidate existing credentials, since only the derived hashes are stored. |
| `WARP_INSIGHT_CENTER_DATABASE_URL` | *(unset)* | PostgreSQL DSN. Unset or empty → JSON file store. |
| `WARP_INSIGHT_CENTER_STORE_PATH` | `state/warp-insight-center-store.json` (under the config-file directory) | JSON store path. |
| `WARP_INSIGHT_CENTER_PUB_CONFIG` | `wist-center-pub.toml` (next to the config file) | Path to the site-layer **declaration** (only `${VAR}` references, no values). Loaded alongside the main file; the same leaf key in both → startup refused. `init-config` writes a skeleton. |
| `WARP_INSIGHT_CENTER_ENV_FILE` | `.env` (next to the declaration) | Path to the site-layer **values** file interpolated into the declaration's `${VAR}` (process environment wins over it). `init-config` writes a skeleton. |
| `WARP_INSIGHT_CENTER_VICTORIAMETRICS_URL` | *(unset)* | VictoriaMetrics base URL. Unset or empty → no time-series push. |
| `WARP_INSIGHT_CENTER_GATEWAY_CREDENTIALS` | *(unset)* | `gateway_id:token,...` seeds written into the store at boot when missing. |
| `WARP_INSIGHT_CENTER_CREDENTIAL_TTL_SECONDS` | `2592000` (30 days) | Gateway **client-certificate** lifetime (register/renew). |
| `WARP_INSIGHT_CENTER_LINK_TTL_SECONDS` | `900` (15 minutes) | One-shot **link** token lifetime (provision/link-token). Expired → must re-issue. |
| `WARP_INSIGHT_CENTER_ARTIFACT_DIR` | `artifacts` | Local release-artifact directory. |
| `WARP_INSIGHT_CENTER_OBJECT_STORAGE_ENDPOINT` | *(unset)* | S3-compatible endpoint (MinIO, AWS S3, …). |
| `WARP_INSIGHT_CENTER_OBJECT_STORAGE_BUCKET` | *(unset)* | Bucket that holds release artifacts. |
| `WARP_INSIGHT_CENTER_OBJECT_STORAGE_ACCESS_KEY` | *(unset)* | Object-storage access key. |
| `WARP_INSIGHT_CENTER_OBJECT_STORAGE_SECRET_KEY` | *(unset)* | Object-storage secret key. |
| `WARP_INSIGHT_CENTER_CA_CERT_PATH` | `<config dir>/ca/control-center.pem` | Trust root handed to gateways as their trust bundle. Missing file → no trust bundle. |
| `WARP_INSIGHT_CENTER_GATEWAY_CLIENT_CA_CERT_PATH` / `..._KEY_PATH` | `<config dir>/ca/gateway-client-ca.{pem,key.pem}` | The **gateway client-certificate CA (CA-G)**, separate from the server CA. Read if present; generated in place only when **both** are missing. |
| `WARP_INSIGHT_CENTER_SERVER_CERT_PATH` | *(unset)* | Server TLS certificate (PEM). Set **together with** the key → the center serves HTTPS and verifies gateway client certificates (CA-G); unset → plain HTTP. |
| `WARP_INSIGHT_CENTER_SERVER_KEY_PATH` | *(unset)* | Server TLS private key (PEM). |
| `WARP_INSIGHT_CENTER_PROTOCOL_VERSION` | `1.0` | Gateway ↔ center wire protocol version. |
| `WARP_INSIGHT_CENTER_GATEWAY_IMAGE` | `wist-gateway:latest` | Image reference used in the generated gateway install command. |
| `WIST_CENTER_GITHUB_TOKEN` | *(unset; falls back to `GITHUB_TOKEN`)* | Token used to list / resolve GitHub releases (auto-detect latest, one-click fill). Anonymous requests are limited to 60/hour; set it for private repos or frequent checks. |

All four `..._OBJECT_STORAGE_*` variables must be set together; if any is missing, release
artifacts are written to `ARTIFACT_DIR` instead.

For the on/off settings (`DATABASE_URL`, `VICTORIAMETRICS_URL`, `..._OBJECT_STORAGE_*`) an
explicitly empty variable means "turn this off" and does override the file value — that is how a
launcher disables a dependency it probed but does not want. For every other variable an empty value
counts as unset, leaving the file value in place.

## HTTP API

### Gateway-facing

Authenticated by the gateway's own credential:

| Method | Path | Credential |
| --- | --- | --- |
| `POST` | `/api/v1/gateway/register` | one-time enrollment token carried in the request body; returns a client certificate |
| `GET` | `/api/v1/gateway/link-upstream` | one-time link token before initialization; client certificate (mTLS) afterwards |
| `POST` | `/api/v1/gateway/status` | client certificate (mTLS) |
| `POST` | `/api/v1/gateway/agents/status` | client certificate (mTLS) |
| `POST` | `/api/v1/gateway/credentials:renew` | client certificate (mTLS); the old certificate is invalidated on success |
| `POST` | `/api/v1/gateway/credentials/verify` | client certificate (mTLS) |

### Admin-facing

All require the admin Bearer token:

| Method | Path |
| --- | --- |
| `GET` | `/api/v1/admin/gateways` |
| `GET` | `/api/v1/admin/gateways/status` |
| `GET` | `/api/v1/admin/gateways/:gateway_id/status` |
| `GET` | `/api/v1/admin/gateways/:gateway_id/status/uptime` |
| `GET` | `/api/v1/admin/gateways/:gateway_id/status/history` |
| `GET` | `/api/v1/admin/gateways/:gateway_id/agents` |
| `GET` | `/api/v1/admin/gateways/:gateway_id/agents/:agent_id/history` |
| `GET` | `/api/v1/admin/gateways/:gateway_id/lifecycle` |
| `POST` / `GET` | `/api/v1/admin/gateways/instances` |
| `GET` | `/api/v1/admin/gateways/:gateway_id/config` |
| `POST` | `/api/v1/admin/gateways/bind` |
| `POST` | `/api/v1/admin/policies/global` |
| `POST` | `/api/v1/gateway/agents/dispatch` |
| `GET` | `/api/v1/admin/package-sources` |
| `GET` | `/api/v1/admin/package-sources/latest` (`?component=…&base_version=…&source=…`) |
| `POST` / `GET` | `/api/v1/admin/releases/:component` |
| `POST` | `/api/v1/admin/releases/:component/batch` |
| `POST` | `/api/v1/admin/releases/:component/:version/status` |
| `POST` / `GET` | `/api/v1/admin/rollout-plans` |
| `POST` | `/api/v1/admin/rollout-plans/approve` |
| `POST` | `/api/v1/admin/rollout-plans/advance` |
| `GET` | `/api/v1/admin/rollout-plans/:plan_id` |

> `POST /api/v1/gateway/agents/dispatch` sits under the `/gateway/` prefix but is an admin-side
> command (dispatching an agent-fleet command), so it takes the admin token.

### Unauthenticated

These two check no credential:

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/gateway/initialization-status` | Reports whether an instance is initialized, keyed only by `instance_id`. |
| `GET` | `/api/v1/releases/artifact/:component/:version/:filename` | Serves files directly from `WARP_INSIGHT_CENTER_ARTIFACT_DIR`. |

`OPTIONS /api/v1/gateway/link-upstream` is also open, as CORS preflight.

## Repository layout

```
src/
  api/       # router, gateway-facing and admin-facing handlers, auth, rate limiting
  config.rs  # CenterConfig: config file + environment variables
  infra/     # store (PostgreSQL / JSON file), S3 artifacts, secrets, VictoriaMetrics
examples/    # example wist-center.toml configs
```

HTTP contract types (commands, responses, view models) come from
[`wist-control`](https://github.com/dayu-sec/wist-control); this crate adds the router, the store
and the handlers on top.

## Related repositories

- [`wist-gateway`](https://github.com/dayu-sec/wist-gateway) — the per-fleet gateway that registers with the center.
- [`wist-center-web`](https://github.com/dayu-sec/wist-center-web) — the admin web frontend.
- [`wist-agentd`](https://github.com/dayu-sec/wist-agentd) — the edge agent.
- [`wist-control`](https://github.com/dayu-sec/wist-control) — the Control domain model.

## License

[Apache-2.0](LICENSE)
