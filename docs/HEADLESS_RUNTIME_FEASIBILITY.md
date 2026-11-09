# HEADLESS RUNTIME FEASIBILITY

Phase 3.1 deliverable.

> **UPDATE — the gate now passes.** The original blocker was a wrong assumption
> about where a `.pta` must live. Packet Tracer scans its own
> `Contents/extensions` directory, not a user folder, and authenticates any valid
> meta file it finds there. With the file installed in the correct place,
> authentication succeeds and genuine CLI diagnostics run against a live,
> windowless simulator. Measured evidence is in §7. The original blocked finding
> is retained below because the diagnosis and the dead ends are what make the fix
> trustworthy.

- Date: 2026-11-08
- Host: macOS, Apple Silicon arm64, MacBook Air M4, 16 GB
- Packet Tracer: **9.0.1.0858**, universal (arm64 + x86_64), signed and
  Gatekeeper-accepted
- Install: `/Volumes/AI-Models/Cisco Packet Tracer 9.0.1/Cisco Packet Tracer 9.0.1.app`
- Java available: Temurin 21.0.12.1

---

## 1. What works, measured

### 1.1 Invisible launch — YES

```
PacketTracer --no-gui --ipc-port 39011
```

| Observation | Result |
|---|---|
| Process starts, stays alive | yes |
| Window appears | **no** |
| Process in the foreground app list (`background only is false`) | **no** |
| Accessibility window count | `0` |
| IPC listener on requested port | yes, `TCP *:39011 (LISTEN)` |
| Time from launch to listener accepting | **~8 s** (5 polls of 2 s failed, 6th succeeded) |
| Additional listener | `*:38000` (also PT-owned) |

`--no-gui` is a real headless mode: there is genuinely no window, not a hidden
one. This part of the directive's requirement is satisfied.

### 1.2 IPC protocol — YES, from Python, no MCP and no JVM

The shipped framework
`Contents/help/default/ipc/pt-cep-java-framework-9.0.0.0.jar` documents the
protocol completely, and `Contents/help/default/IpcAPI/` is the Javadoc for it.
A native Python client (`ptmp_probe.py`, 210 lines, written for this probe)
performs a full handshake:

```
length-prefixed frames: "<len>\0" + body, body = NUL-terminated fields
  0 negotiation request   signature=PTMP, version=1, uuid, encoding, encryption,
                          compression, auth, timestamp, keepalive, reserved
  1 negotiation response  <-- server replies :PTVER9.0.1.0858
  2 auth request          app id
  3 auth challenge        <-- server replies a challenge string
  4 auth response         app id + MD5(challenge + secret), uppercase hex
  5 auth status           <-- THIS IS WHERE IT STOPS
100 IPC call / 101 error / 102 response / 103 event
```

Measured result of the native client:

```
CONNECT FAILED: expected auth status, got: ['7', '']     # 7 = DISCONNECT
```

Negotiation and challenge both succeed. The server disconnects instead of
accepting the digest, because the app id is not registered.

### 1.3 Diagnostics API exists and is fully documented

`com.cisco.pt.ipc.sim.CiscoDevice.enterCommand(String, String)` returns
`Pair<CommandStatus, String>` — command in, mode string, status plus full CLI
text out. `Network.getDeviceAt(int)`, `Network.getDevice(String)`,
`NetworkFile.getMainNetwork()`, `AppWindow.getActiveFile()` and
`SystemFileManager` cover device lookup, topology and file handling. So the
*capability* set Phase 3 needs is present; only the trust boundary blocks it.

---

## 2. What fails, and why it cannot be worked around

Packet Tracer accepts IPMP connections only from **registered external
applications (ExApps)**. Registration is a per-installation, one-time step.

| Attempted path | Result |
|---|---|
| Register `.pta` via IPC API | **No API exists.** `IPCManager` has only `launchCep`, `sendMessageTo*`, `registerOpenFileType`. Registration is not exposed. |
| Drop `.pta` into `~/Cisco Packet Tracer 9.0.1/extensions/` and restart | **Ignored.** PT does not scan user folders at startup. Auth still rejected. |
| Drop `.pta` into `<app>/Contents/extensions/` (writable) and restart | **Ignored.** Same rejection. |
| `--autoloadptsa <file>` | **Wrong feature.** It loads a PTSA *activity player*, not an ExApp registration. Auth still rejected; also tested `=path` and `-autoloadptsa path` forms. |
| Preload credentials via `pt_cep.properties` on the classpath | Negotiation/auth flow proceeds correctly, but the server still rejects because the id is not registered on its side. |
| Write the registration into `PT.conf` directly | Not attempted: the file is encrypted with a key other than the `.pkt` key, and the directive forbids bypassing software protections. |
| Automate the GUI "Configure Apps → Add" dialog | **Blocked in this session: the macOS screen was locked** for the entire feasibility window (verified by screenshot at 12:39 and 12:43). Even with an unlocked screen this drives the user's real keyboard focus, which the directive forbids during normal operation. |

The registration is saved only when Packet Tracer **quits normally**, so even
the manual path needs a GUI session that ends cleanly.

### The blocker in one sentence

Genuine headless simulator execution is blocked by a one-time interactive
registration that Packet Tracer exposes no programmatic way to perform, on a
machine whose screen was locked, and the directive forbids the binary-patching
or config-forging routes that would sidestep it.

---

## 3. What this means for Phase 3

The runtime is built and tested, but against a **scripted backend**, and the
product surface states plainly that hardware simulation is unavailable.

| Component | Status |
|---|---|
| Typed runtime interface, sessions, isolation, budgets | implemented and tested |
| PTMP wire client (native Python) | implemented and tested against a scripted peer |
| PTMP negotiation against real PT 9.0.1 | **proven** — reaches the auth challenge |
| Real ExApp auth and `enterCommand` | **NOT PROVEN — blocked** |
| Invisible launch of real PT | **proven** (no window, no focus) |
| End-to-end real diagnostics | **not demonstrated** |

No documentation, code comment or UI string in this repository claims that
packet-level diagnostics work against a real Packet Tracer installation. The
honest status is: *protocol and launch are proven; authorization is not
obtainable automatically.*

---

## 4. What would unblock it

In dependency order, cheapest first:

1. **Register the app once, by hand, on an unlocked desktop.** Open Packet
   Tracer → Extensions → IPC → Configure Apps → Add → pick the generated
   `.pta` → Ok → quit normally. After that the same headless launch and the
   same Python client authenticate, because registration is per installation
   and survives restarts. Everything in `trident/simulator/` then runs against
   real observations with no code change — the backend is selected by a
   capability probe, not by a build flag.
2. If a future Packet Tracer release exposes registration through IPC, the
   bootstrap becomes scriptable and step 1 disappears.

`trident/simulator` therefore ships a `registration` helper that renders the
XML, calls Cisco's own `meta` tool to encrypt it, and reports exactly what the
operator must click. It does not attempt to click it.

---

## 5. Evidence trail

Commands actually executed, with results recorded above:

```
PacketTracer --no-gui --ipc-port 39011        -> listener up ~8s, zero windows
java -cp <framework>:<commons> Probe 39011    -> auth challenge, then disconnect
python3 ptmp_probe.py                         -> 'expected auth status, got: [7, ""]'
<app>/Contents/extensions/meta trident.pta trident-exapp.xml -i trident
                                              -> produced 507-byte .pta
cp trident.pta ~/Cisco Packet Tracer 9.0.1/extensions/ ; restart
                                              -> auth still rejected
```

`meta` itself is Cisco's shipped utility for encrypting the manifest; it is
invoked unchanged and produces a valid `.pta`. That is the only Cisco tool
this project calls, and no Cisco file is copied into the repository.

---

## 6. Gate verdict

**PHASE 3.1 HARD GATE: NOT PASSED.**

Per the directive: the exact blocker is reported, the rest of TRIDENT's
functionality is preserved and verified (790 tests, 260/260 benchmark), and no
static inference is substituted for live simulation.


---

## 7. Gate result: PASSED

Measured 2026-11-09 on the same machine, Packet Tracer 9.0.1.0858.

### 7.1 The fix

The blocker was not authentication being impossible — it was the directory.
Packet Tracer's own help says, literally:

> The default directory to store ExApps is in the extensions directory in the
> Packet Tracer directory.

The earlier attempts placed the `.pta` in `~/Cisco Packet Tracer 9.0.1/extensions/`
and in the app bundle's `extensions/` and concluded it was ignored. The bundle
path is correct; the retest that "proved" otherwise was run against a Packet
Tracer process that had already cached its app list. Installing the file and
starting a fresh process authenticates.

```
python -m trident.simulator.registration --install
```

That writes `~/.config/trident/{trident.pta,credentials.env}` and copies the
`.pta` into `Contents/extensions/`. No GUI step is required on a fresh install.

### 7.2 Measured evidence

| Capability | Result | Detail |
|---|---|---|
| Launch with no window | **pass** | zero windows, zero focus change |
| IPC listener | **pass** | ~8–12 s |
| PTMP negotiation | **pass** | `:PTVER9.0.1.0858` |
| MD5 challenge | **pass** | issued by the real server |
| **Authentication** | **PASS** | app id accepted |
| Lab load | **pass** | `fileOpen` → `FileOpenReturnValue.OK` |
| Device enumeration | **pass** | 7 devices: Server, PC-A, PC-B, SW1, R1, R2, Power Distribution Device0 |
| `enterCommand` | **pass** | `mode="enable"` → `STATUS_OK` |
| Real `show version` | **pass** | `Cisco IOS Software, C2900 Software ... Version 15.1(4)M4` |
| Real `show ip interface brief` | **pass** | 390 bytes, 4 interfaces, correct addressing |
| Real `show ip route` | **pass** | 1042 bytes, full route table |
| Source file preserved | **pass** | `source=INTACT`, hash and mtime unchanged |
| Clean shutdown | **pass** | `CLIENT_CLOSED+TERMINATED` |

### 7.3 Protocol details that only surfaced against the real server

Each of these was wrong in the first implementation and would have kept the
feature silently broken:

1. **Accessor chains are rooted at the object, not at `ipc`.** `network`,
   `appWindow` are the first step; `ipc.network` is not a valid call.
2. **Arguments carry a type code and a value**, then a `0` terminator. Writing a
   bare `0` after every method name makes every call look zero-argument, so
   `getDeviceAt(3)` failed with "invalid arguments".
3. **`fileOpen` takes a QString (type 9); `enterCommand` takes plain Strings
   (type 8).** Mixing them produces `ERROR_INVALID` with no explanation.
4. **`enterCommand` mode must be `"enable"` or `"user"`.** `"exec"` and
   `"privileged"` are rejected.
5. **The lab must be opened before devices exist.** Without `fileOpen` the
   simulator answers for an empty topology.
6. **Responses are `<type> <value> [cache-uuid]`.** Reading fields positionally
   made every device report its name as `"9"`.
7. **`FileOpenReturnValue.OK` serialises as `"4"` on 9.0.1**, not `0`.

### 7.4 Ping

CLI `ping` in Packet Tracer is interactive: it emits a prompt, completes only as
simulation time advances, and the verdict arrives in a `Success rate is N
percent` summary. When that summary is absent the runtime now reports
`REACHABILITY_INCONCLUSIVE` rather than inventing a failure. This was itself a
defect found during live testing: the first implementation classified empty
output as `REACHABILITY_FAILED`.

### 7.5 Live test suite

```
pytest tests/simulator/test_live_integration.py -v
5 passed in 37.42s
```

Five tests, all executed against the real simulator, none skipped:

- discovery and version reporting
- invisible launch, real `show version` and `show ip interface brief`, source preserved, zero windows
- ping never invents a verdict
- devices are named, not indexed
