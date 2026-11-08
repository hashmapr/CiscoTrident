# Wireless & Endpoint Services

Phase 2 · `trident/wireless/`

This package reads the **recorded running-configuration text** of every device in
the trusted `NetworkModel` and reports what that text says about wireless SSIDs,
endpoint addressing, and network services.

> **Matching configuration is NOT connectivity.**
>
> Everything here is a fact about a configuration export. A configured SSID does
> not prove a client associated with it. A DHCP pool does not prove a client got a
> lease. An `ip helper-address` does not prove the server answers. An endpoint
> address does not prove the host is up. There is deliberately **no function that
> returns "connected", "reachable", "online", "associated" or "lease acquired"**,
> and no result type carries such a field.

It is a *pure function of the model*: no device connection, no socket, no shell, no
mutation, and no AI.

---

## 1. Public surface

```python
from trident.wireless import (
    analyse_wireless, analyse_endpoints, analyse_services,
    analyse_dhcp_relays, analyse_dns_resolvers,
)

analyse_wireless(model)      -> tuple[WirelessDevice, ...]
analyse_endpoints(model)     -> tuple[EndpointConfig, ...]
analyse_services(model)      -> tuple[ServiceConfig, ...]
analyse_dhcp_relays(model)   -> tuple[DhcpRelay, ...]      # ip helper-address
analyse_dns_resolvers(model) -> tuple[DnsResolver, ...]    # ip name-server
```

All five functions are deterministic and return results sorted by device key
(services additionally ordered `dhcp`, `dns`, `http`, `tftp`).

### `WirelessStatus`

| Value | Meaning |
| --- | --- |
| `CONFIGURED` | At least one SSID is defined, **every** SSID has a classified security mode, and an enabled `Dot11Radio` or a controller role backs the SSIDs. Each SSID cites a configuration line. |
| `PARTIAL` | SSID/radio definitions exist but are incomplete — an SSID's security is `UNKNOWN`, or no enabled radio and no controller role is recorded. |
| `MISSING` | Positive evidence that wireless is absent: the device category is an AP/WLC but the config has no wireless directive, or the category is non-wireless (router/switch/PC/…) with that reason stated. |
| `INDETERMINATE` | The config mentions wireless but does not form a configured subsystem, or the device category is unknown so inapplicability cannot be stated. |
| `UNSUPPORTED` | The device records **0** configuration lines, so the snapshot cannot speak to wireless at all. Never `CONFIGURED`, never `MISSING`. |

`UNSUPPORTED` and `MISSING` are never collapsed. `UNSUPPORTED` = the snapshot is
silent. `MISSING` = the snapshot positively shows absence.

### `SecurityMode`

`OPEN`, `WEP`, `WPA`, `WPA2`, `WPA3`, `ENTERPRISE`, `UNKNOWN`.

`UNKNOWN` is the honest answer when an SSID block has no encryption or
key-management directive. **Silence is never promoted to `OPEN`.** `OPEN` is only
reported when a configuration line explicitly states it
(`authentication open`, `security open`, `no security wpa`, `no encryption`).

### `SsidConfig`

```python
@dataclass(frozen=True)
class SsidConfig:
    ssid: str
    security_mode: SecurityMode
    psk_configured: bool          # True only with a cited PSK/passphrase line
    evidence: tuple[str, ...]     # cited line(s); PSK material redacted
```

PSK/passphrase material is replaced with `<redacted>` before it reaches evidence.
A non-`UNKNOWN` mode requires a cited configuration line; `psk_configured=True`
requires a cited PSK line.

### `WirelessDevice`

```python
@dataclass(frozen=True)
class WirelessDevice:
    device: str
    is_controller: bool
    ssids: tuple[SsidConfig, ...]
    radios_enabled: int           # Dot11Radio interfaces without 'shutdown'
    status: WirelessStatus
    evidence: tuple[str, ...]
```

### `EndpointConfig`

```python
@dataclass(frozen=True)
class EndpointConfig:
    device: str
    kind: str                     # pc | server | laptop | printer
    ipv4: str | None
    mask: str | None
    gateway: str | None
    dns: tuple[str, ...]
    dhcp_enabled: bool | None
    evidence: tuple[str, ...]
```

`dhcp_enabled` is `True` only from `ip address dhcp` / `ip dhcp client …`, `False`
only from a recorded static `ip address`, and `None` when the method is not stated.
An address recovered from end-host observations leaves it `None` — a recorded
address is not proof the address is static.

### `ServiceConfig`

```python
@dataclass(frozen=True)
class ServiceConfig:
    device: str
    service: str                 # dhcp | dns | http | tftp
    enabled: bool | None         # None when the config does not state the state
    pools: tuple[dict, ...]      # DHCP server pools only (service == "dhcp")
    evidence: tuple[str, ...]
```

A record is emitted only when at least one relevant line is recorded; silence is
never reported as "service disabled". `pools` is forbidden on non-DHCP services.

---

## 2. DHCP relay vs DHCP server — kept apart

| Configuration | Reported by | Not reported by |
| --- | --- | --- |
| `ip dhcp pool LAN` + `network …` + `default-router …` | `analyse_services` → `ServiceConfig(service="dhcp", pools=(…))` | — |
| `ip helper-address 10.10.10.5` (inside an interface) | `analyse_dhcp_relays` → `DhcpRelay(device, interface, server)` | `analyse_services` (never a pool) |
| `service dhcp` / `no service dhcp` | `analyse_services` → `enabled=True/False` | — |

`test_helper_address_is_relay_not_server_pool` proves a relay interface produces
**zero** DHCP service records, and `test_relay_and_pool_on_same_device_stay_distinct`
proves that a device with both keeps the pool's `default-router` distinct from the
relay target.

## 3. DNS resolver vs DNS server — kept apart

| Configuration | Reported by |
| --- | --- |
| `ip name-server 8.8.8.8` | `analyse_dns_resolvers` → `DnsResolver(servers=(…))` |
| `ip dns server` / `no ip dns server` | `analyse_services` → `ServiceConfig(service="dns", enabled=…)` |

`ip name-server` tells a device which server to *ask*. It is not evidence that the
device serves DNS. Covered by `test_name_server_is_resolver_not_dns_service` and
`test_ip_dns_server_is_dns_service_not_resolver`.

---

## 4. Evidence conventions

Same style as `trident.security`:

| Form | Meaning |
| --- | --- |
| `running-config line N: <text>` | A cited line from the recorded configuration. The only form that counts as positive evidence. |
| `not present: <what>` | A directive is positively absent **inside a non-empty recorded config**. |
| `not observable: <why>` | The snapshot cannot speak at all (0 configuration lines). |

`is_absence_note(entry)` returns `True` for the two absence/observability forms.
Structural guards raise `ValueError` at construction time if a result claims a
state without the evidence that could support it.

---

## 5. The honesty contract

1. **Configuration is not connectivity.** No result, function, parameter or field
   names a connectivity/reachability verdict. This is asserted against the whole
   `__all__` surface and every dataclass field in
   `test_public_api_exposes_no_connectivity_verdict` and
   `test_result_dataclasses_carry_no_connectivity_field`.
2. **0 config lines → `UNSUPPORTED`.** Never `CONFIGURED`, never `MISSING`.
3. **`MISSING` needs positive evidence.** An explicit negative directive, or a
   device category that makes the feature inapplicable *with that reason stated*.
4. **Silence is `UNKNOWN`, not `OPEN`.** `OPEN` requires an explicit open /
   no-encryption line to cite.
5. **Relay ≠ server.** `ip helper-address` is never a DHCP pool.
6. **Resolver ≠ server.** `ip name-server` is never the DNS server service.
7. **`CONFIGURED` is strict.** Every SSID classified, plus an enabled radio or a
   controller role; otherwise `PARTIAL`.
8. **Secrets never surface.** PSK/passphrase material is redacted in evidence.
9. **Evidence is mandatory.** Every `CONFIGURED` / `MISSING` result carries
   non-empty evidence, checked structurally and in the parametrised tests.

---

## 6. Recognised configuration forms

**Wireless**
- `dot11 ssid <name>` … block (IOS autonomous AP)
- `wlan <profile> <id> [ssid]` … block (AireOS WLC)
- `ssid <name>` … block
- `interface Dot11RadioN` for radio presence and `shutdown` state

**Endpoint**
- `ip address <addr> [mask]`, `ip default-gateway <gw>`, `ip name-server <…>`
- `ip address dhcp`, `ip dhcp client …`
- model observations `endhost_ip`, `endhost_gateway`, `endhost_dns`

**Services**
- `ip dhcp pool`, `service dhcp`, `no service dhcp`
- `ip dns server`, `no ip dns server`
- `ip http server`, `no ip http server`, `ip http secure-server`
- `tftp-server …`
- `ip helper-address` (relay) and `ip name-server` (resolver) on their own paths

---

## 7. Tests

`tests/test_phase2/test_wireless.py` — 37 tests.

| Requirement | Test |
| --- | --- |
| WLC/AP with 2 SSIDs WPA2 → `CONFIGURED`, both parsed | `test_wlc_two_ssids_wpa2_is_configured`, `test_ap_two_ssids_wpa2_is_configured_with_psk_redacted` |
| SSID without security directive → `UNKNOWN`, not `OPEN` | `test_ssid_without_security_directive_is_unknown_not_open` |
| AP with no config → `UNSUPPORTED` | `test_ap_with_no_configuration_is_unsupported` |
| Static endpoint IP/gateway/DNS parsed | `test_endpoint_static_ip_gateway_dns_parsed` |
| DHCP server pool detected on a router | `test_dhcp_server_pool_detected_on_router` |
| `ip helper-address` → relay, not a pool | `test_helper_address_is_relay_not_server_pool`, `test_relay_and_pool_on_same_device_stay_distinct` |
| No connectivity/reachability verdict on the API | `test_public_api_exposes_no_connectivity_verdict`, `test_result_dataclasses_carry_no_connectivity_field` |
| Evidence non-empty for every `CONFIGURED`/`MISSING` | `test_every_configured_or_missing_result_has_evidence` |

Additional structural tests prove the dataclasses refuse to construct
contradictory results (`MISSING` with SSIDs, `CONFIGURED` with an `UNKNOWN` SSID,
a mode without a cited line), and that output is deterministic and sorted.

---

## 8. Non-goals

- No runtime reachability, association, roaming, signal strength, or lease state.
- No RF planning, channel/interference analysis, or client inventory.
- No capability inference from platform defaults; only recorded lines count.
- No mutation, remediation application, or device interaction.
- No assumption that an SSID with no security line is open.
