from ..api_rtti import _bcd_labels, _inheritance_labels, _signed32, rtti_vtable_slot
from ..framework import test


@test()
def test_rtti_signed32():
    assert _signed32(0) == 0
    assert _signed32(0x7FFFFFFF) == 0x7FFFFFFF
    assert _signed32(0xFFFFFFFF) == -1


@test()
def test_rtti_attribute_labels():
    assert _inheritance_labels(0) == ["single"]
    assert _inheritance_labels(3) == ["multiple", "virtual"]
    assert _bcd_labels(0x12) == ["ambiguous", "virtual_base"]


@test()
def test_rtti_slot_invalid_target_fails_cleanly():
    result = rtti_vtable_slot("0x1", 0)
    assert "error" in result
