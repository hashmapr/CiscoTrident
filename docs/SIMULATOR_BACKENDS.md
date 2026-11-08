# SIMULATOR BACKENDS

Two backends exist and they are not interchangeable. This page states the
difference precisely so no report can blur it.

## BackendKind

| Value | Meaning | Can produce `observed=True`? |
|---|---|---|
| `SIMULATOR_LIVE` | A real Packet Tracer process answered over PTMP | yes |
| `SCRIPTED` | A deterministic in-process peer reading canned JSON | **no** |
| `UNAVAILABLE` | Nothing could be used; every operation fails | no |

`OperationResult.is_live` is `True` only for `SIMULATOR_LIVE` **and**
`observed=True`. That conjunction is the single place the distinction is made,
so there is no path where a scripted result leaks into a live claim.

## Live backend

`trident/simulator/backends.py::LiveBackend`

| Aspect | Detail |
|---|---|
| Transport | TCP + PTMP, length-prefixed NUL-delimited frames |
| Auth | MD5 challenge/response against a registered ExApp |
| Process | `PacketTracer --no-gui --ipc-port <port>`, own process group |
| Readiness | polls the port until it accepts, bounded by `startup_timeout_s` |
| Shutdown | `SIGTERM` to the process group, then `SIGKILL` |
| Capabilities | `RUN_CLI`, `PING`, `TRACEROUTE`, interface/routing/VLAN/ACL views |
| Mutations | **not advertised** — `MUTATE_CONFIG` is absent |

### Verified against the real installation

- Executable: `<bundle>/Contents/MacOS/PacketTracer`, universal arm64 + x86_64
- Window count after launch: **0**
- Listener ready: **~8 s**
- Negotiation response: `:PTVER9.0.1.0858`
- Auth: **challenge received, then disconnect** — app id not registered

Therefore: launch, process control and protocol framing are proven; authenticated
diagnostics are not. See `docs/HEADLESS_RUNTIME_FEASIBILITY.md`.

## Scripted backend

`trident/simulator/backends.py::ScriptedBackend`

Reads a JSON document:

```json
{
  "devices": [
    {
      "name": "R1",
      "device_type": "router",
      "commands": {
        "show ip route": "S* 0.0.0.0/0 [1/0] via 203.0.113.1\n"
      }
    }
  ]
}
```

Every result carries `caveats=("scripted backend: not a simulator observation",)`
and the session adds a note saying the same thing. It is used for:

- deterministic testing of isolation, budgeting, parsing and investigation;
- degraded operation, so static analysis keeps working when Packet Tracer is
  absent.

It is **never** used to answer a question that needs packet-level truth. If it is
the only backend and a question needs observation, the outcome is
`UNSUPPORTED_COMMAND` or `RUNTIME_UNAVAILABLE`, not a fabricated observation.

## Selection

`select_backend()` prefers live and falls back to scripted only when the caller
explicitly allows it. The choice is reported as `BackendKind` on every result, so
downstream code branches on evidence, never on configuration.

## Command safety

`is_read_only()` gates every command before it reaches a backend.

Accepted prefixes: `show `, `ping `, `traceroute `, `tracert `, `display `.

Rejected always: `configure`, `conf t`, `no `, `write`, `copy run`, `erase`,
`delete`, `reload`, `shutdown`, `clear `, `debug `.

This is an allowlist plus a denylist, deliberately redundant: either check alone
would eventually admit something it should not.

## Why no MCP

An MCP server would add a process boundary, a protocol layer and an external
dependency to reach a socket that is already local. The directive requires MCP
not to be a runtime dependency, and a direct adapter is also easier to audit:
every field on the wire is visible in `ptmp.py`.

## Attribution

The PTMP field order and type codes were read from Cisco's shipped Java framework
documentation inside the installation. **No Cisco source code is copied into this
repository.** The one Cisco artefact invoked is the `meta` utility, run unchanged,
to encrypt an ExApp manifest.
