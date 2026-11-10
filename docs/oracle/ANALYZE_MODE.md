# ANALYZE MODE

One button, no questions. Upload a lab, press **Analyze Network**, get a
device-by-device assessment.

## What it produces

| Part | Contents |
|---|---|
| Overview | devices by type, physical links, interfaces, VLANs, routing protocols detected, findings by severity, count of unsupported checks |
| Device sections | one per device, routers first, then firewalls, switches, endpoints, infrastructure |
| Basic information | display name, hostname, model, type, interface addresses, disabled interfaces, connected networks, default and static routes, gateway, DNS, VLANs, applied ACLs, direct neighbours |
| Common Cisco Questions | likely exam questions answered from the model, each with its evidence status |
| Potential Problems | severity, device and interface, description, evidence, why it matters, commands to check with, suggested fix where justified |
| Network-wide issues | findings not attributable to one device |
| What was not checked | the unsupported features, by name and reason |

Every report ends with the same sentence: *a report with no findings means no
check fired; it is not proof that the network is correct.*

## Status vocabulary

`VERIFIED` (three families agreed) · `DERIVED` (computed from verified facts) ·
`OBSERVED` (live simulator) · `SUSPECTED` · `VIOLATION` · `UNRESOLVED` ·
`UNSUPPORTED` · `NOT_CHECKED`

A device with no recorded model answers "What is the hardware model?" as
`UNSUPPORTED` with the reason. It never guesses.

## Modes and export

- **Quick Analyze** — static analysis only (default).
- **Deep Analyze** — adds a warning that runtime experiments are not started
  implicitly from the browser, rather than pretending they ran.
- Export: JSON, Markdown, plain text. Headings, statuses, evidence and limitations
  are preserved in all three.

## Real acceptance run

`R3_OKCUP_24_25_CiscoPT(1).pka`, no questions entered, real Chromium:

```
status      Analyzed 33 device(s) in 13.9s
sections    33
headings    Router — Bowser's Castle Router 1
            Router — DK Jungle Router 1
            Router — Internet (Router) 1
            Multilayer Switch — Rainbow Road Layer 3 Switch 1   ...
overview    visible
```

33 devices, 37 links, 362 interfaces, OSPF and RIP detected, 6 findings
(1 HIGH, 1 MEDIUM, 4 LOW), 8 unsupported checks.

Every finding carried exact evidence, for example:

```
[HIGH] Rainbow Road Layer 3 Switch 2 Gi1/0/1
  evidence: 35.72.15.10 held by Rainbow Road L3 Switch 2:Gi1/0/1,
            Warp Zone L3 Switch ...
  why: two hosts answer for one address, giving intermittent connectivity
```

Source file SHA-256 unchanged before and after:
`1ff12f2bbeddb1d9f225e176b9672549e5e13cba8fb3dc23829727c1bb41df1f`

## Known limitations

1. **Device type is not in the file.** Classification is inferred from the model
   string (`2911` → Router, `2960-24TT` → Switch). An unrecognised model is shown
   as "Device", not guessed.
2. **Host addresses are often absent.** Packet Tracer assigns host IPs at runtime,
   so a host's address, mask and DNS may be `UNSUPPORTED`. That is the truth about
   the file, not a defect in the report.
3. **Deep Analyze does not start a simulator** from the browser. Runtime evidence
   comes from the CLI path.
4. **Coverage is bounded by the protocol matrix**: 2 features simulator-tested, 5
   statically verified, 1 parsed-only (OSPF), 8 unsupported. The report says which
   on every run.
5. **Sections stream only at the API level.** The endpoint returns the whole report;
   per-device streaming to the browser is not wired yet, so a large lab shows one
   status line while it builds.
