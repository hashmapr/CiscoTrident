# Test Results

Recorded on macOS (Apple Silicon), Python 3.12.12, with all three engines installed.

```
$ pytest -q
125 passed in 59.11s
```

Additional suite added for the AI client and network queries after that run; see the
full-suite count below.

## Coverage map

| Requirement | Test file | Test |
|---|---|---|
| 1. Valid file ingestion | test_security.py | `test_accepts_pka_and_pkt`, `test_sha256_is_computed_over_exact_bytes` |
| 2. Invalid file rejection | test_security.py | `test_reject_unsupported_extension`, `..._empty`, `..._tiny`, `..._oversized`, `..._path_separators` |
| 3. File hash preservation | test_api.py | `test_analyze_real_file_end_to_end`, `test_original_file_untouched_after_upload` |
| 4. Parser timeout | test_parsers.py | `test_timeout_is_reported_not_raised` |
| 5. Parser crash | test_parsers.py | `test_crash_is_reported_not_raised` |
| 6. Missing parser output | test_parsers.py | `test_unavailable_adapter_reports_unavailable` |
| 7. Two-engine agreement + third missing | test_consensus.py | `test_two_engine_agreement_is_incomplete_under_strict`, `test_missing_output_never_counts_as_agreement` |
| 8. Three-engine agreement | test_consensus.py | `test_three_engine_agreement_is_verified` |
| 9. Three-engine disagreement | test_consensus.py | `test_three_engine_disagreement_is_conflict` |
| 10. Equivalent MAC formatting | test_consensus.py | `test_mac_address_formatting_is_equivalent` |
| 11. Equivalent interface naming | test_consensus.py | `test_equivalent_interface_names_resolve` |
| 12. Conflicting IP values | test_consensus.py | `test_conflicting_ip_has_no_value` |
| 13. Invalid subnet masks | test_normalization.py | `test_mask_validation` |
| 14. VLAN membership | test_network_queries.py | `test_vlan_membership`, `test_vlan_assignment` |
| 15. Route selection | test_network_queries.py | `test_route_lookup` |
| 16. ACL parsing | test_normalization.py, test_network_queries.py | `test_parse_numbered_acls`, `test_parse_named_acl`, `test_acl_lookup` |
| 17. MCQ matching | test_questions.py | `test_mcq_matches_ip_option`, `..._mac_in_different_format`, `..._interface_alias`, `..._vlan_number` |
| 18. MCQ with no correct option | test_questions.py | `test_mcq_no_matching_option_is_conflict`, `test_builder_conflict_when_option_missing` |
| 19. Multi-select | test_questions.py | `test_multi_select_all_match`, `test_multi_select_partial_is_incomplete` |
| 20. AI hallucination rejection | test_questions.py, test_ai_client.py | `test_ai_plan_cannot_inject_a_fact`, `test_parse_plan_filters_unknown_operations`, `test_parse_plan_rejects_garbage` |
| 21. No API key exposure | test_security.py, test_api.py | `test_api_key_never_in_public_dict`, `test_api_key_absent_from_frontend_assets`, `test_response_never_contains_api_key` |
| 22. No answer-key exposure | test_security.py, test_parsers.py | `test_answer_key_sections_not_exposed_in_adapter_output`, `test_snapshot_selection_never_reads_answer_keys` |
| 23. No source file mutation | test_parsers.py, test_api.py | `test_engine_a_does_not_modify_input`, `test_original_file_untouched_after_upload` |
| 24. Repeatability + stable ordering | test_api.py | `test_analyze_is_repeatable_and_stable`, `test_batch_of_65_questions_completes` |

## Real-file results (measured, not simulated)

File: `tests/fixtures/sample_lab.pkt` (81,474 bytes, SHA-256 `4a212faa…`)

| Engine | State | Devices | Links | Duration |
|---|---|---|---|---|
| engine_a | OK | 7 | 5 | ~700 ms |
| engine_b | OK | 7 | 5 | ~11.0 s |
| engine_c | OK | 7 | 5 | ~2.9 s |

Container decode comparison (executed, hashes computed):

```
sample_lab.pkt      A=1045755 sha=ae176dc9ad51b4b9  B=… ae176dc9ad51b4b9  C=… ae176dc9ad51b4b9  IDENTICAL
sample_activity.pka A=321434  sha=58083b3ca17ed9d6  B=… 58083b3ca17ed9d6  C=… 58083b3ca17ed9d6  IDENTICAL
```

Field consensus on the real file:

| Status | Count |
|---|---|
| VERIFIED (3/3) | 16 |
| INCOMPLETE | 14 |
| CONFLICT | 0 |

The 16 VERIFIED fields are interface IPv4 addresses and hostnames extracted independently
from the IOS configuration by all three engines. The 14 INCOMPLETE fields are end-host
facts (gateway, DNS, MAC) that only Engine A's XML exposes — correctly *not* upgraded.

## Empty activity file

`tests/fixtures/sample_activity.pka` is a genuine empty activity skeleton (all three
`<PACKETTRACER5>` blocks contain zero devices). TRIDENT reports 0 devices and returns no
VERIFIED answers. This is asserted by `test_empty_activity_file_reports_no_devices`.

## Not executed / not claimed

- **65-question benchmark accuracy**: the Round 1 audit tracker was not present in the
  workspace, so no accuracy figure is claimed. `test_batch_of_65_questions_completes`
  verifies batch scale, ordering and stability only.
- **Live AI provider call**: no API key was configured. Provider interaction is tested
  through mocked transport (`tests/test_ai_client.py`). Real-model quality is unverified.
