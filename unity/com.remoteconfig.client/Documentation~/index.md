# RemoteConfig Client

See the package [README](../README.md) for installation and usage.

## How it fits together

```
 Unity app (this package)  <-- local REST -->  agent  <-- HTTPS, whenever there is signal -->  server / dashboard
```

The client only ever talks to the agent on `127.0.0.1`. The agent deals with the network, so the app never
has to know whether the connection is up. The endpoints it uses:

| Loop | Request | Purpose |
|---|---|---|
| config | `GET /v1/config?wait=30` (ETag) | long-poll for new config; `304` when nothing changed |
| config | `POST /v1/config/ack` | tell the agent the revision was applied (or why not) |
| heartbeat | `PUT /v1/status` every 10 s | proof of life; the agent restarts an app that goes quiet |
| lifecycle | `GET /v1/lifecycle?wait=30` | learn that the agent wants the app to quit |
| telemetry | `POST /v1/events`, `POST /v1/metrics` | batched; errors go out immediately |

The full contract is in the repository's `api/openapi.yaml`.

## Environment variables the agent sets

| Variable | Meaning |
|---|---|
| `REMOTECONFIG_URL` | API root, e.g. `http://127.0.0.1:7878/v1` (its presence triggers auto-start) |
| `REMOTECONFIG_TOKEN` | bearer token for the local API |
| `REMOTECONFIG_CONFIG_FILE` | the agent's `effective-config.json`, read at startup before the agent answers |

## Assemblies

| Assembly | Contents |
|---|---|
| `RemoteConfig.Runtime` | everything; `Core/` is plain C# with no UnityEngine dependency, `Unity/` is the thin Unity layer |
| `RemoteConfig.Editor` | the menu items and the test-scene generator |

Reference `RemoteConfig.Runtime` from your own asmdefs; code in the default `Assembly-CSharp` sees it automatically.
