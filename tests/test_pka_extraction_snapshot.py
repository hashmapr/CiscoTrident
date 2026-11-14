"""Regression tests for multi-snapshot .pka selection.

Policy under test (``trident.parsers.snapshot``):

* exactly one snapshot block is analysed;
* blocks are never merged;
* reference/answer wrappers are never read;
* when selection cannot be made safely it abstains and says so.
"""

from __future__ import annotations

from trident.parsers.snapshot import device_names_in, select_snapshot


def _device(name: str, ref: str, ip: str | None = None) -> str:
    cfg = f"<RUNNINGCONFIG><LINE>hostname {name}</LINE>"
    if ip:
        cfg += (
            "<LINE>interface GigabitEthernet0/0</LINE>"
            f"<LINE> ip address {ip} 255.255.255.0</LINE>"
        )
    cfg += "</RUNNINGCONFIG>"
    return (
        "<DEVICE><ENGINE>"
        f"<NAME>{name}</NAME><SAVE_REF_ID>{ref}</SAVE_REF_ID>{cfg}"
        "</ENGINE></DEVICE>"
    )


def _block(*devices: str) -> str:
    return "<PACKETTRACER5>" + "".join(devices) + "</PACKETTRACER5>"


def test_several_differing_blocks_abstain_with_ambiguity_reported():
    xml = _block(_device("A", "r1", "10.0.0.1")) + _block(
        _device("A", "r1", "10.0.0.1"), _device("B", "r2")
    )
    sel = select_snapshot(xml)
    assert sel.abstained is True
    assert sel.ambiguous is True
    assert sel.xml_text is None
    assert any("abstaining" in note for note in sel.notes), sel.notes


def test_selection_never_merges_blocks():
    """The selected text must contain exactly one block's device inventory."""
    xml = (
        _block(_device("A", "r1", "10.0.0.1"))
        + _block(_device("C", "r3", "10.0.0.3"))
        + _block(
            _device("E", "r5", "10.0.0.5"),
            _device("F", "r6", "10.0.0.6"),
            _device("G", "r7", "10.0.0.7"),
        )
    )
    sel = select_snapshot(xml)
    assert sel.abstained is False
    assert sel.reason == "first-block-initial"
    names = set(device_names_in(sel.xml_text))
    # Exactly one block's inventory; never a union of the three.
    assert names == {"A"}, names
    assert sel.xml_text.count("<DEVICE>") == 1


def test_majority_agreement_selects_one_block_and_says_not_merged():
    xml = (
        _block(_device("A", "r1", "10.0.0.1"))
        + _block(_device("A", "r1", "10.0.0.1"))
        + _block(_device("A", "r1", "10.0.0.1"), _device("Z", "rz", "10.9.9.9"))
    )
    sel = select_snapshot(xml)
    assert sel.abstained is False
    assert sel.reason == "majority-agreement"
    assert "not merged" in " ".join(sel.notes)
    assert set(device_names_in(sel.xml_text)) == {"A"}


def test_reference_wrapper_is_never_read():
    xml = _block(_device("A", "r1", "10.0.0.1")) + "<COMPARISONS>" + _block(
        _device("ANSWER", "ra", "99.9.9.9")
    ) + "</COMPARISONS>"
    sel = select_snapshot(xml)
    assert sel.abstained is False
    assert "ANSWER" not in device_names_in(sel.xml_text)
    assert any("never read" in note for note in sel.notes), sel.notes


def test_first_block_is_initial_only_when_later_block_progressed():
    # First block has no address, later block has two -> progressed state.
    xml = _block(_device("A", "r1")) + _block(
        _device("A", "r1", "10.0.0.1"), _device("B", "r2", "10.0.1.1")
    )
    sel = select_snapshot(xml)
    assert sel.abstained is False
    assert sel.reason == "first-block-initial"
    assert set(device_names_in(sel.xml_text)) == {"A"}


def test_identical_blocks_are_safe_and_never_merged():
    one = _block(_device("A", "r1", "10.0.0.1"))
    sel = select_snapshot(one + one)
    assert sel.abstained is False
    assert sel.reason == "identical"
    assert sel.xml_text.count("<DEVICE>") == 1
