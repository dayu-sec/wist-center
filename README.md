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

- **Gateway onboarding** — one-time bootstrap credentials, initial `config.toml` provisioning with
  a derived RegistToken, plus runtime credential renewal and verification.
- **Status ingestion** — accepts gateway status reports and the per-gateway agent status lists;
  optionally pushes each report to VictoriaMetrics for history.
- **Fleet admin API** — gateway list and status cards, per-gateway status / uptime / history,
  agent lists, per-agent history, and lifecycle transitions.
- **Instance provisioning** — create management instances, bind gateways to customers, and read
  the initial config from the admin side.
- **Release and upgrade** — publish `wist-agentd` / `wist-gateway` artifacts to a local directory
  or object storage, and create / list / approve multi-step upgrade plans.
- **Auth and rate limiting** — admin bearer token (SHA-256, constant-time compare) and gateway
  runtime credentials; per-peer-IP rate limiting that deliberately ignores the spoofable
  `x-real-ip` and `x-forwarded-for` headers.
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

With no configuration at all, the service listens on `127.0.0.1:3100`, keeps state under
`~/.wist-center/state/`, and runs *without* admin authentication — that mode is for local
development only.

To bring up PostgreSQL and VictoriaMetrics as well:

```bash
docker compose up -d          # PostgreSQL :55432, VictoriaMetrics :8428

export WARP_INSIGHT_CENTER_DATABASE_URL=postgres://demo:demo@127.0.0.1:55432/insight_demo
export WARP_INSIGHT_CENTER_VICTORIAMETRICS_URL=http://127.0.0.1:8428
export WARP_INSIGHT_CENTER_ADMIN_TOKEN=dev-admin-token

cargo run
```

The credentials in `docker-compose.yml` (`demo` / `demo`) are demo-only. The PostgreSQL schema is
applied automatically from [`docker/initdb/01_schema.sql`](docker/initdb/01_schema.sql) on first
start.

Exported variables only last for that shell, so the admin token changes on every launch. To keep one
around, use a config file instead:

```bash
wist-center init-config          # ~/.wist-center/wist-center.toml, random admin token + HMAC secret
cargo run
```

[`examples/local-dev.toml`](examples/local-dev.toml) is the same thing spelled out, ready to copy.
See [Configuration](#configuration).

## Configuration

Settings are resolved in three layers, each overriding the one before it; see
[`src/config.rs`](src/config.rs) for the full definition.

1. the TOML file at `~/.wist-center/wist-center.toml` (point `WIST_CENTER_CONFIG` elsewhere to
   change that; a missing file is simply skipped, so the binary also runs on environment variables
   alone),
2. `WARP_INSIGHT_CENTER_*` environment variables,
3. built-in defaults.

### Configuration file

Generate a file rather than hand-editing one — `init-config` fills in freshly random credentials:

```bash
wist-center init-config                      # ~/.wist-center/wist-center.toml
wist-center init-config /etc/wist-center.toml
```

It prints the generated admin token and HMAC secret once, and refuses to overwrite an existing
file (rotating those credentials invalidates the token you already handed out, so the overwrite has
been made deliberate: delete the file or pass another path). This is what makes the admin token
survive restarts — otherwise it has to be re-pasted into the admin UI every launch.

A ready-to-run example, with every key spelled out and the production caveats inline, lives at
[`examples/local-dev.toml`](examples/local-dev.toml):

```bash
mkdir -p ~/.wist-center
cp examples/local-dev.toml ~/.wist-center/wist-center.toml
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

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `WARP_INSIGHT_CENTER_LISTEN` | `127.0.0.1:3100` | HTTP listen address. |
| `WARP_INSIGHT_CENTER_PUBLIC_URL` | `https://center.warpinsight.example` | Externally reachable base URL, used to build the gateway init URL. Must fall inside the control-center certificate SANs. |
| `WARP_INSIGHT_CENTER_ADMIN_TOKEN` | *(unset)* | Admin bearer token. Unset → the admin API requires no authentication (development only). Overrides `server.admin_token` from the file. |
| `WARP_INSIGHT_CENTER_HMAC_SECRET` | dev placeholder | HMAC-SHA256 key used to derive RegistTokens. **Must be set in production.** Rotating it does not invalidate existing credentials, since only the derived hashes are stored. |
| `WARP_INSIGHT_CENTER_DATABASE_URL` | *(unset)* | PostgreSQL DSN. Unset or empty → JSON file store. |
| `WARP_INSIGHT_CENTER_STORE_PATH` | `state/warp-insight-center-store.json` (under the config-file directory) | JSON store path. |
| `WARP_INSIGHT_CENTER_VICTORIAMETRICS_URL` | *(unset)* | VictoriaMetrics base URL. Unset or empty → no time-series push. |
| `WARP_INSIGHT_CENTER_GATEWAY_CREDENTIALS` | *(unset)* | `gateway_id:token,...` seeds written into the store at boot when missing. |
| `WARP_INSIGHT_CENTER_CREDENTIAL_TTL_SECONDS` | `2592000` (30 days) | Runtime credential lifetime. |
| `WARP_INSIGHT_CENTER_ARTIFACT_DIR` | `artifacts` | Local release-artifact directory. |
| `WARP_INSIGHT_CENTER_OBJECT_STORAGE_ENDPOINT` | *(unset)* | S3-compatible endpoint (MinIO, AWS S3, …). |
| `WARP_INSIGHT_CENTER_OBJECT_STORAGE_BUCKET` | *(unset)* | Bucket that holds release artifacts. |
| `WARP_INSIGHT_CENTER_OBJECT_STORAGE_ACCESS_KEY` | *(unset)* | Object-storage access key. |
| `WARP_INSIGHT_CENTER_OBJECT_STORAGE_SECRET_KEY` | *(unset)* | Object-storage secret key. |
| `WARP_INSIGHT_CENTER_CA_CERT_PATH` | `~/.wist-center/ca/control-center.pem` | Trust root handed to gateways as their trust bundle. Missing file → no trust bundle. |
| `WARP_INSIGHT_CENTER_PROTOCOL_VERSION` | `1.0` | Gateway ↔ center wire protocol version. |
| `WARP_INSIGHT_CENTER_GATEWAY_IMAGE` | `wist-gateway:latest` | Image reference used in the generated gateway install command. |

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
| `POST` | `/api/v1/gateway/register` | one-time enrollment token carried in the request body |
| `GET` | `/api/v1/gateway/initial-config` | one-time bootstrap token before initialization, runtime token afterwards |
| `POST` | `/api/v1/gateway/status` | runtime Bearer token |
| `POST` | `/api/v1/gateway/agents/status` | runtime Bearer token |
| `POST` | `/api/v1/gateway/credentials:renew` | runtime Bearer token; the old one is invalidated on success |
| `POST` | `/api/v1/gateway/credentials/verify` | runtime Bearer token |

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
| `GET` | `/api/v1/admin/gateways/instances/:instance_id/config` |
| `POST` | `/api/v1/admin/gateways/bind` |
| `POST` | `/api/v1/admin/policies/global` |
| `POST` | `/api/v1/gateway/agents/dispatch` |
| `POST` / `GET` | `/api/v1/admin/releases/:component` |
| `POST` / `GET` | `/api/v1/admin/upgrade-plans` |
| `POST` | `/api/v1/admin/upgrade-plans/approve` |

> `POST /api/v1/gateway/agents/dispatch` sits under the `/gateway/` prefix but is an admin-side
> command (dispatching an agent-fleet command), so it takes the admin token.

### Unauthenticated

These two check no credential:

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/gateway/initialization-status` | Reports whether an instance is initialized, keyed only by `instance_id`. |
| `GET` | `/api/v1/releases/artifact/:component/:version/:filename` | Serves files directly from `WARP_INSIGHT_CENTER_ARTIFACT_DIR`. |

`OPTIONS /api/v1/gateway/initial-config` is also open, as CORS preflight.

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
