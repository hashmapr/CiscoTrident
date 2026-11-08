"""Tests for the offline knowledge layer.

The final group is the separation proof: the knowledge index is documentation
only and cannot be pointed at a ``NetworkModel`` to assert a network fact.
"""

from __future__ import annotations

import inspect
from itertools import islice

import pytest

from trident.knowledge import (
    KnowledgeEntry,
    KnowledgeIndex,
    KnowledgeKind,
    default_index,
)
from trident.knowledge.corpus import ENTRIES
from trident.models import NetworkModel


@pytest.fixture(scope="module")
def index() -> KnowledgeIndex:
    return default_index()


# ---------------------------------------------------------------------------
# corpus shape
# ---------------------------------------------------------------------------


def test_corpus_size_is_within_curated_range() -> None:
    assert 40 <= len(ENTRIES) <= 60


def test_corpus_ids_are_unique_and_non_empty() -> None:
    ids = [entry.id for entry in ENTRIES]
    assert len(ids) == len(set(ids))
    assert all(entry_id.strip() for entry_id in ids)


def test_corpus_covers_every_kind() -> None:
    kinds = {entry.kind for entry in ENTRIES}
    assert kinds == set(KnowledgeKind)


def test_corpus_covers_required_commands() -> None:
    required = [
        "show ip interface brief",
        "show running-config",
        "show vlan brief",
        "show interfaces trunk",
        "show ip route",
        "show spanning-tree",
        "show etherchannel summary",
        "show access-lists",
        "show ip ospf neighbor",
        "show ip protocols",
    ]
    for command in required:
        hits = default_index().by_command(command)
        assert hits, f"no knowledge entry for required command {command!r}"
        assert any(hit.kind is KnowledgeKind.COMMAND for hit in hits)


def test_corpus_covers_required_concepts() -> None:
    titles = " ".join(entry.title.lower() for entry in ENTRIES)
    for phrase in (
        "access port",
        "trunk",
        "native vlan",
        "switch virtual interface",
        "default-gateway",
        "network statement",
        "direction",
        "overload",
        "dhcp relay",
    ):
        assert phrase in titles, f"missing concept about {phrase!r}"


def test_corpus_covers_required_troubleshooting() -> None:
    titles = " ".join(entry.title.lower() for entry in ENTRIES)
    for phrase in ("interface down", "vlan mismatch", "trunk not forming", "missing route", "acl blocking"):
        assert phrase in titles, f"missing troubleshooting entry about {phrase!r}"


def test_every_related_id_resolves(index: KnowledgeIndex) -> None:
    known = {entry.id for entry in index.entries}
    for entry in index.entries:
        for related in entry.related:
            assert related in known, f"{entry.id} references unknown entry {related!r}"
            assert related != entry.id, f"{entry.id} relates to itself"


def test_related_links_never_repeat_and_are_ordered(index: KnowledgeIndex) -> None:
    for entry in index.entries:
        assert len(entry.related) == len(set(entry.related)), f"{entry.id} repeats a related id"
        assert all(isinstance(related, str) for related in entry.related)


def test_every_entry_has_detail_and_commands_or_source(index: KnowledgeIndex) -> None:
    for entry in index.entries:
        assert len(entry.detail) > 80, f"{entry.id} detail is too thin to be useful"
        assert entry.source, f"{entry.id} has no source"
        if entry.kind is KnowledgeKind.COMMAND:
            assert entry.ios_commands, f"command entry {entry.id} lists no commands"


# ---------------------------------------------------------------------------
# construction guards
# ---------------------------------------------------------------------------


def _entry(entry_id: str, related: tuple[str, ...] = ()) -> KnowledgeEntry:
    return KnowledgeEntry(
        id=entry_id,
        kind=KnowledgeKind.CONCEPT,
        title=entry_id,
        summary="summary",
        detail="detail",
        related=related,
    )


def test_index_rejects_dangling_related_id() -> None:
    with pytest.raises(ValueError, match="unresolved related ids"):
        KnowledgeIndex([_entry("a", related=("does-not-exist",))])


def test_index_rejects_duplicate_ids() -> None:
    with pytest.raises(ValueError, match="duplicate knowledge entry id"):
        KnowledgeIndex([_entry("a"), _entry("a")])


def test_index_rejects_non_entry_objects() -> None:
    with pytest.raises(TypeError, match="KnowledgeEntry"):
        KnowledgeIndex([{"id": "a"}])  # type: ignore[list-item]


def test_entry_rejects_empty_title() -> None:
    with pytest.raises(ValueError, match="empty title"):
        KnowledgeEntry(
            id="x",
            kind=KnowledgeKind.CONCEPT,
            title="   ",
            summary="s",
            detail="d",
        )


def test_index_is_iterable_and_sized(index: KnowledgeIndex) -> None:
    assert len(index) == len(ENTRIES)
    assert len(index.entries) == len(ENTRIES)
    assert [entry.id for entry in index.entries] == sorted(entry.id for entry in index.entries)


# ---------------------------------------------------------------------------
# search relevance
# ---------------------------------------------------------------------------


def test_search_exact_command_ranks_first(index: KnowledgeIndex) -> None:
    results = index.search("show ip route")
    assert results, "expected hits for a documented command"
    assert results[0].id == "cmd-show-ip-route"


def test_search_returns_command_entries_for_command_text(index: KnowledgeIndex) -> None:
    for query, expected in (
        ("show running-config", "cmd-show-running-config"),
        ("show vlan brief", "cmd-show-vlan-brief"),
        ("show ip ospf neighbor", "cmd-show-ip-ospf-neighbor"),
        ("show etherchannel summary", "cmd-show-etherchannel-summary"),
    ):
        results = index.search(query)
        assert results[0].id == expected, f"{query!r} ranked {results[0].id}"


def test_search_is_case_and_punctuation_insensitive(index: KnowledgeIndex) -> None:
    lower = [entry.id for entry in index.search("show interfaces trunk")]
    upper = [entry.id for entry in index.search("SHOW  Interfaces, TRUNK!")]
    assert lower and lower == upper


def test_search_finds_concepts_by_phrase(index: KnowledgeIndex) -> None:
    results = index.search("native vlan")
    ids = [entry.id for entry in results]
    assert "concept-native-vlan" in ids
    assert "ts-native-vlan-mismatch" in ids


def test_search_finds_troubleshooting_procedure(index: KnowledgeIndex) -> None:
    results = index.search("trunk not forming")
    assert results
    assert results[0].id == "ts-trunk-not-forming"


def test_search_token_match_without_exact_phrase(index: KnowledgeIndex) -> None:
    results = index.search("ospf neighbour stuck")
    assert results
    assert any(entry.id.startswith("ts-ospf") for entry in results)


def test_search_respects_limit(index: KnowledgeIndex) -> None:
    full = index.search("show", limit=50)
    assert len(index.search("show", limit=3)) == 3
    assert len(full) >= 3
    assert [entry.id for entry in index.search("show", limit=3)] == [entry.id for entry in full[:3]]


def test_search_limit_zero_or_negative_returns_empty(index: KnowledgeIndex) -> None:
    assert index.search("show ip route", limit=0) == []
    assert index.search("show ip route", limit=-5) == []


def test_search_is_deterministic(index: KnowledgeIndex) -> None:
    first = [entry.id for entry in index.search("vlan", limit=10)]
    for _ in range(3):
        assert [entry.id for entry in index.search("vlan", limit=10)] == first


def test_search_ranks_exact_title_over_incidental_mentions(index: KnowledgeIndex) -> None:
    results = index.search("administrative distance")
    assert results[0].id == "concept-administrative-distance"


def test_search_does_not_return_everything_for_a_rare_query(index: KnowledgeIndex) -> None:
    results = index.search("zzzq nonexistent protocol")
    assert results == []


def test_search_single_meaningful_token_still_works(index: KnowledgeIndex) -> None:
    results = index.search("overload")
    assert results
    assert any(entry.id == "concept-nat-overload" for entry in results)


def test_search_ignores_stopwords_in_query(index: KnowledgeIndex) -> None:
    assert index.search("the of and what is") == []
    results = index.search("what is a native vlan")
    assert results
    assert results[0].id == "concept-native-vlan"


# ---------------------------------------------------------------------------
# empty / unknown queries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("query", ["", "   ", "\t\n", "!!!", "   ???   "])
def test_search_empty_query_returns_empty(query: str, index: KnowledgeIndex) -> None:
    assert index.search(query) == []


@pytest.mark.parametrize("prefix", ["", "   ", "show nonexistent", "zzzq"])
def test_by_command_unknown_prefix_returns_empty(prefix: str, index: KnowledgeIndex) -> None:
    assert index.by_command(prefix) == []


def test_by_command_matches_prefix(index: KnowledgeIndex) -> None:
    results = index.by_command("show ip")
    ids = {entry.id for entry in results}
    assert "cmd-show-ip-route" in ids
    assert "cmd-show-vlan-brief" not in ids


def test_by_command_normalises_case_and_spacing(index: KnowledgeIndex) -> None:
    assert index.by_command("SHOW   ip  interface") == index.by_command("show ip interface")


def test_by_command_exact_command_returns_its_entry(index: KnowledgeIndex) -> None:
    results = index.by_command("show access-lists")
    assert results
    assert results[0].id == "cmd-show-access-lists"


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------


def test_explain_renders_all_sections(index: KnowledgeIndex) -> None:
    text = index.explain("cmd-show-vlan-brief")
    assert "show vlan brief" in text
    assert "show vlan brief" in text.split("IOS commands:")[1]
    assert "Related:" in text
    assert "Source:" in text
    assert "Documentation only" in text


def test_explain_resolves_related_titles(index: KnowledgeIndex) -> None:
    entry = next(e for e in index.entries if e.id == "concept-native-vlan")
    text = index.explain(entry.id)
    for related in entry.related:
        title = next(e.title for e in index.entries if e.id == related)
        assert title in text


def test_explain_unknown_id_raises(index: KnowledgeIndex) -> None:
    with pytest.raises(KeyError):
        index.explain("no-such-entry")


def test_explain_contains_no_device_claims(index: KnowledgeIndex) -> None:
    forbidden = ("is configured correctly", "is correctly configured", "is misconfigured", "verified")
    for entry in islice(index.entries, len(index)):
        text = index.explain(entry.id).lower()
        for phrase in forbidden:
            assert phrase not in text, f"{entry.id} claims a device fact: {phrase!r}"


# ---------------------------------------------------------------------------
# separation rule: documentation only, no network model
# ---------------------------------------------------------------------------

_PUBLIC_METHODS = {
    name
    for name, member in inspect.getmembers(KnowledgeIndex, predicate=inspect.isfunction)
    if not name.startswith("_")
}


def test_index_public_surface_is_only_lookup() -> None:
    assert _PUBLIC_METHODS == {"search", "by_command", "explain"}


def test_index_accepts_no_network_model_parameter() -> None:
    forbidden_names = {"model", "network", "network_model", "snapshot", "device", "devices", "config"}
    for name in _PUBLIC_METHODS:
        signature = inspect.signature(getattr(KnowledgeIndex, name))
        for parameter in signature.parameters.values():
            assert parameter.name.lower() not in forbidden_names, (
                f"KnowledgeIndex.{name} accepts a parameter named {parameter.name!r}; "
                "the knowledge layer must never inspect a network snapshot"
            )
            annotation = parameter.annotation
            assert annotation not in {NetworkModel, "NetworkModel"}, (
                f"KnowledgeIndex.{name} annotates {parameter.name!r} as NetworkModel"
            )


@pytest.mark.parametrize("method", ["search", "by_command", "explain"])
def test_index_rejects_a_network_model_argument(method: str) -> None:
    index = default_index()
    model = NetworkModel(devices={}, interfaces={}, snapshot_id="block0")
    with pytest.raises(TypeError, match="string"):
        getattr(index, method)(model)


def test_index_module_does_not_import_the_network_model() -> None:
    import ast

    import trident.knowledge.corpus as knowledge_corpus
    import trident.knowledge.index as knowledge_index

    for module in (knowledge_index, knowledge_corpus):
        tree = ast.parse(inspect.getsource(module))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
                imported.update(f"{node.module}.{alias.name}" for alias in node.names)
        for name in imported:
            assert "models" not in name.split("."), (
                f"{module.__name__} imports {name!r}; the knowledge layer must not depend on "
                "the network model"
            )
        assert not hasattr(module, "NetworkModel")


def test_index_cannot_assert_a_network_fact(index: KnowledgeIndex) -> None:
    """No public result is a verdict about a device; results are corpus entries."""
    for entry in index.search("show ip interface brief"):
        assert isinstance(entry, KnowledgeEntry)
        assert entry.source, "every result is documented reference material"

    for name in _PUBLIC_METHODS:
        assert not any(
            token in name.lower() for token in ("assert", "verify", "check", "validate", "diagnose")
        ), f"KnowledgeIndex.{name} looks like a verification surface"


def test_search_results_are_entries_not_verdicts(index: KnowledgeIndex) -> None:
    results = index.search("interface down")
    assert results
    assert all(isinstance(entry, KnowledgeEntry) for entry in results)
    assert all(entry.kind in KnowledgeKind for entry in results)
