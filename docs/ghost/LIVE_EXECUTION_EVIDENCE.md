# LIVE EXECUTION EVIDENCE

Proof that the simulator tests execute against a real Packet Tracer process, not
a mock. Captured 2026-11-09 on the development machine.

## Environment

| Field | Value |
|---|---|
| Packet Tracer version | **9.0.1.0858** (from the PTMP negotiation, not a file name) |
| Backend kind | `SIMULATOR_LIVE` |
| Bundle | `~/.local/share/trident/ghost-app/PTGhost.app` (background-agent copy) |
| Launch flags | `--no-gui` |
| macOS app type | `type="UIElement"` — no Dock icon, no Cmd-Tab entry |

## Process evidence

`ps -p 82266` during a session:

```
82266 /Users/tanayshah/.local/share/trident/ghost-app/PTGhost.app/Contents/MacOS/PacketTracer --no-gui
```

A real OS process running Cisco's binary. `lsappinfo` reports it as a
`UIElement`, which is the background-agent type macOS assigns when
`LSUIElement` is set.

## PDU evidence

```
PDU status      : DELIVERED
PDU observed    : True | live: SIMULATOR_LIVE
PDU frames      : 60 sent: 2 dropped: 0
session id match: True
raw sample      : frame 0 R1 -> sent=True dropped=False
decision sample : The Ping process starts the next ping request.
```

The decision text is Packet Tracer's own simulation reasoning, returned over
PTMP. A mock cannot produce it.

## Test results

`pytest tests/simulator/test_pdu_live.py -v`

```
test_session_advertises_pdu_capability                        PASSED
test_router_to_directly_connected_router_is_delivered         PASSED
test_pc_to_pc_is_delivered_when_dynamic_routing_reaches_...   PASSED
test_a_cold_host_endpoint_is_never_reported_as_a_fault        PASSED
test_unknown_destination_is_refused_not_delivered             PASSED
test_unknown_source_is_refused                                PASSED
test_repeated_experiments_are_independent                     PASSED
test_pdu_is_invisible_and_preserves_the_source                PASSED
test_non_icmp_protocol_is_refused                             PASSED

9 passed in 161.85s
```

**9 passed, 0 skipped, 0 mocked.** The module is marked `live_simulator` and each
test skips when no registration exists; none skipped on this run.

## How to distinguish a real run from a skipped one

A skipped run prints `SKIPPED` and the reason. The counts above show `9 passed`
with no skip line, and the evidence block above shows a live PID, a PTMP
handshake version, and simulator-generated decision text.
