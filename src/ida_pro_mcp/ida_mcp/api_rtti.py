"""Read-only Microsoft C++ RTTI and virtual-table inspection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, NotRequired, TypedDict

import ida_auto
import ida_bytes
import ida_ida
import ida_idaapi
import ida_name
import ida_nalt
import ida_segment
import ida_typeinf
import ida_xref
import idautils

from .rpc import tool
from .sync import idasync
from .utils import parse_address, parse_decls_ctypes, pattern_filter


CHD_MULTINH = 0x01
CHD_VIRTINH = 0x02
CHD_AMBIGUOUS = 0x04

BCD_NOTVISIBLE = 0x01
BCD_AMBIGUOUS = 0x02
BCD_PRIVORPROTINCOMPOBJ = 0x04
BCD_PRIVORPROTBASE = 0x08
BCD_VBOFCONTOBJ = 0x10
BCD_NONPOLYMORPHIC = 0x20
BCD_HASPCHD = 0x40

_MAX_BASES = 4096
_MAX_METHODS = 4096


class RttiBase(TypedDict):
    name: str
    type_descriptor: str
    descriptor: str
    num_contained_bases: int
    mdisp: int
    pdisp: int
    vdisp: int
    attributes: int
    attribute_names: list[str]


class VtableMethod(TypedDict):
    slot: int
    offset: str
    entry: str
    addr: str
    name: str


class VtableSummary(TypedDict):
    addr: str
    rva: str
    class_name: str
    subobject: str
    method_count: int
    inheritance: list[str]
    hierarchy: list[str]


class VtableDetail(VtableSummary):
    complete_object_locator: str
    type_descriptor: str
    class_hierarchy_descriptor: str
    object_offset: int
    constructor_displacement: int
    bases: list[RttiBase]
    methods: list[VtableMethod]
    next_method_offset: int | None
    declaration: NotRequired[str]


class VtablePage(TypedDict):
    data: list[VtableSummary]
    next_offset: int | None
    total: int


class VtableSlotResult(TypedDict):
    vtable: str
    class_name: str
    slot: int
    offset: str
    entry: str
    addr: str
    name: str


class VtableTypeResult(TypedDict):
    ok: bool
    vtable: str
    type_name: str
    declaration: str
    created: bool


class RttiError(TypedDict):
    error: str


@dataclass(frozen=True)
class _Col:
    ea: int
    image_base: int
    offset: int
    cd_offset: int
    type_descriptor: int
    hierarchy_descriptor: int


@dataclass(frozen=True)
class _Vtable:
    ea: int
    col: _Col
    class_name: str
    subobject: str
    bases: tuple[tuple[str, int, int, int, int, int, int], ...]
    chd_attributes: int
    method_count: int


_cache: list[_Vtable] | None = None
_cache_is_deep = False


def invalidate_rtti_cache() -> None:
    global _cache, _cache_is_deep
    _cache = None
    _cache_is_deep = False


def _ptr_size() -> int:
    return 8 if ida_ida.inf_is_64bit() else 4


def _read_u32(ea: int) -> int | None:
    data = ida_bytes.get_bytes(ea, 4)
    return int.from_bytes(data, "little") if data and len(data) == 4 else None


def _signed32(value: int) -> int:
    return value - 0x100000000 if value & 0x80000000 else value


def _read_ptr(ea: int) -> int | None:
    size = _ptr_size()
    data = ida_bytes.get_bytes(ea, size)
    return int.from_bytes(data, "little") if data and len(data) == size else None


def _mapped(ea: int, size: int = 1) -> bool:
    return ea != ida_idaapi.BADADDR and ida_bytes.is_mapped(ea) and ida_bytes.is_mapped(ea + size - 1)


def _relative_or_pointer(field_ea: int, image_base: int) -> int | None:
    if _ptr_size() == 8:
        value = _read_u32(field_ea)
        return image_base + _signed32(value) if value is not None else None
    return _read_ptr(field_ea)


def _read_c_string(ea: int, limit: int = 2048) -> str | None:
    raw = ida_bytes.get_strlit_contents(ea, limit, ida_nalt.STRTYPE_C)
    if not raw:
        return None
    return raw.decode("utf-8", errors="replace")


def _type_name(type_descriptor: int) -> str | None:
    raw = _read_c_string(type_descriptor + (_ptr_size() * 2))
    if not raw or not raw.startswith(".?"):
        return None
    decorated = raw[1:]
    demangled = ida_name.demangle_name(decorated, ida_name.MNG_SHORT_FORM)
    if demangled:
        for prefix in ("class ", "struct ", "union "):
            if demangled.startswith(prefix):
                return demangled[len(prefix) :]
        return demangled
    # Useful fallback for simple .?AVName@@ / .?AUName@@ descriptors.
    if len(raw) > 6 and raw[2:4] in ("AV", "AU") and raw.endswith("@@"):
        return raw[4:-2].replace("@", "::")
    return raw


def _valid_type_descriptor(ea: int) -> bool:
    if not _mapped(ea, (_ptr_size() * 2) + 5):
        return False
    vfptr = _read_ptr(ea)
    spare = _read_ptr(ea + _ptr_size())
    return bool(vfptr and _mapped(vfptr) and spare == 0 and _type_name(ea))


def _parse_col(ea: int) -> _Col | None:
    if not _mapped(ea, 24 if _ptr_size() == 8 else 20):
        return None
    signature = _read_u32(ea)
    offset = _read_u32(ea + 4)
    cd_offset = _read_u32(ea + 8)
    if signature is None or offset is None or cd_offset is None:
        return None
    if _ptr_size() == 8:
        if signature != 1:
            return None
        object_base = _read_u32(ea + 20)
        if object_base is None:
            return None
        image_base = ea - _signed32(object_base)
    else:
        if signature != 0:
            return None
        image_base = 0
    type_descriptor = _relative_or_pointer(ea + 12, image_base)
    hierarchy = _relative_or_pointer(ea + 16, image_base)
    if type_descriptor is None or hierarchy is None:
        return None
    if not _valid_type_descriptor(type_descriptor) or not _valid_chd(hierarchy, image_base):
        return None
    return _Col(ea, image_base, offset, cd_offset, type_descriptor, hierarchy)


def _valid_chd(ea: int, image_base: int) -> bool:
    if not _mapped(ea, 16):
        return False
    signature = _read_u32(ea)
    attributes = _read_u32(ea + 4)
    count = _read_u32(ea + 8)
    bca = _relative_or_pointer(ea + 12, image_base)
    if signature != 0 or attributes is None or attributes & ~0x0F:
        return False
    if count is None or not 1 <= count <= _MAX_BASES or bca is None or not _mapped(bca, 4):
        return False
    first_bcd = _relative_or_pointer(bca, image_base)
    return first_bcd is not None and _valid_bcd(first_bcd, image_base)


def _valid_bcd(ea: int, image_base: int) -> bool:
    if not _mapped(ea, 24):
        return False
    attributes = _read_u32(ea + 20)
    td = _relative_or_pointer(ea, image_base)
    return attributes is not None and not attributes & 0xFFFFFF00 and td is not None and _valid_type_descriptor(td)


def _parse_bases(col: _Col) -> tuple[tuple[str, int, int, int, int, int, int], ...] | None:
    chd = col.hierarchy_descriptor
    count = _read_u32(chd + 8)
    bca = _relative_or_pointer(chd + 12, col.image_base)
    if count is None or bca is None or not 1 <= count <= _MAX_BASES:
        return None
    result = []
    for index in range(count):
        bcd = _relative_or_pointer(bca + index * 4, col.image_base)
        if bcd is None or not _valid_bcd(bcd, col.image_base):
            return None
        td = _relative_or_pointer(bcd, col.image_base)
        contained = _read_u32(bcd + 4)
        mdisp = _read_u32(bcd + 8)
        pdisp = _read_u32(bcd + 12)
        vdisp = _read_u32(bcd + 16)
        attrs = _read_u32(bcd + 20)
        if None in (td, contained, mdisp, pdisp, vdisp, attrs):
            return None
        name = _type_name(td)
        if not name:
            return None
        result.append(
            (
                name,
                bcd,
                contained,
                _signed32(mdisp),
                _signed32(pdisp),
                _signed32(vdisp),
                attrs,
            )
        )
    return tuple(result)


def _is_code(ea: int) -> bool:
    seg = ida_segment.getseg(ea)
    return seg is not None and seg.type == ida_segment.SEG_CODE


def _has_data_xref(ea: int) -> bool:
    return ida_xref.get_first_dref_to(ea) != ida_idaapi.BADADDR


def _method_count(vtable: int) -> int:
    size = _ptr_size()
    count = 0
    for slot in range(_MAX_METHODS):
        entry = vtable + slot * size
        target = _read_ptr(entry)
        if not target or not _is_code(target):
            break
        if slot and _has_data_xref(entry):
            break
        count += 1
    return count


def _inheritance_labels(attributes: int) -> list[str]:
    labels = []
    if attributes & CHD_MULTINH:
        labels.append("multiple")
    if attributes & CHD_VIRTINH:
        labels.append("virtual")
    if attributes & CHD_AMBIGUOUS:
        labels.append("ambiguous")
    return labels or ["single"]


def _matches(value: str, pattern: str) -> bool:
    return bool(pattern_filter([{"value": value}], pattern, "value"))


def _bcd_labels(attributes: int) -> list[str]:
    names = []
    for flag, name in (
        (BCD_NOTVISIBLE, "not_visible"),
        (BCD_AMBIGUOUS, "ambiguous"),
        (BCD_PRIVORPROTINCOMPOBJ, "private_or_protected_in_complete_object"),
        (BCD_PRIVORPROTBASE, "private_or_protected_base"),
        (BCD_VBOFCONTOBJ, "virtual_base"),
        (BCD_NONPOLYMORPHIC, "non_polymorphic"),
        (BCD_HASPCHD, "has_class_hierarchy_descriptor"),
    ):
        if attributes & flag:
            names.append(name)
    return names


def _vtable_from_col_pointer(pointer_ea: int) -> _Vtable | None:
    col_ea = _read_ptr(pointer_ea)
    if col_ea is None:
        return None
    col = _parse_col(col_ea)
    if col is None:
        return None
    vtable = pointer_ea + _ptr_size()
    count = _method_count(vtable)
    bases = _parse_bases(col)
    class_name = _type_name(col.type_descriptor)
    attrs = _read_u32(col.hierarchy_descriptor + 4)
    if not count or bases is None or not class_name or attrs is None:
        return None
    subobject = class_name
    if col.offset:
        for base in bases:
            if base[3] == col.offset:
                subobject = base[0]
                break
    return _Vtable(vtable, col, class_name, subobject, bases, attrs, count)


def _scan_vtables(deep_scan: bool = False) -> list[_Vtable]:
    ida_auto.auto_wait()
    candidates: set[int] = set()

    # IDA 9's built-in RTTI analysis usually provides these names already.
    for ea, name in idautils.Names():
        if name.startswith("??_R4"):
            for xref in idautils.DataRefsTo(ea):
                candidates.add(xref)

    if deep_scan:
        # Fallback for fresh or partially analyzed IDBs: find valid COL pointers
        # followed by a code pointer in data segments.
        size = _ptr_size()
        for index in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(index)
            if seg is None or seg.type != ida_segment.SEG_DATA:
                continue
            start = (seg.start_ea + size - 1) & ~(size - 1)
            for pointer_ea in range(start, seg.end_ea - (size * 2) + 1, size):
                target = _read_ptr(pointer_ea + size)
                if target and _is_code(target):
                    candidates.add(pointer_ea)

    found = []
    seen = set()
    for pointer_ea in sorted(candidates):
        vtable = _vtable_from_col_pointer(pointer_ea)
        if vtable and vtable.ea not in seen:
            found.append(vtable)
            seen.add(vtable.ea)
    return found


def _get_vtables(refresh: bool = False, deep_scan: bool = False) -> list[_Vtable]:
    global _cache, _cache_is_deep
    if refresh or _cache is None or (deep_scan and not _cache_is_deep):
        _cache = _scan_vtables(deep_scan)
        _cache_is_deep = deep_scan
    return _cache


def _summary(vtable: _Vtable) -> VtableSummary:
    imagebase = ida_nalt.get_imagebase()
    return {
        "addr": hex(vtable.ea),
        "rva": hex(vtable.ea - imagebase),
        "class_name": vtable.class_name,
        "subobject": vtable.subobject,
        "method_count": vtable.method_count,
        "inheritance": _inheritance_labels(vtable.chd_attributes),
        "hierarchy": [base[0] for base in vtable.bases],
    }


def _resolve_vtable(target: str | int) -> _Vtable:
    if isinstance(target, int) or str(target).lower().startswith(("0x", "sub_")) or str(target).isdigit():
        ea = parse_address(target)
        for vtable in _get_vtables():
            if vtable.ea == ea:
                return vtable
        direct = _vtable_from_col_pointer(ea - _ptr_size())
        if direct:
            return direct
        raise ValueError(f"No MSVC RTTI vtable at {target}")
    matches = [
        item
        for item in _get_vtables()
        if _matches(item.class_name, str(target)) or _matches(item.subobject, str(target))
    ]
    if not matches:
        raise ValueError(f"No MSVC RTTI class matches {target!r}")
    if len(matches) > 1:
        raise ValueError(f"Multiple vtables match {target!r}; use a vtable address")
    return matches[0]


def _method(vtable: _Vtable, slot: int) -> VtableMethod:
    if slot < 0 or slot >= vtable.method_count:
        raise ValueError(f"Slot {slot} outside vtable range 0..{vtable.method_count - 1}")
    entry = vtable.ea + slot * _ptr_size()
    target = _read_ptr(entry)
    if target is None:
        raise ValueError(f"Unable to read vtable slot {slot}")
    return {
        "slot": slot,
        "offset": hex(slot * _ptr_size()),
        "entry": hex(entry),
        "addr": hex(target),
        "name": ida_name.get_name(target) or "",
    }


def _declaration(vtable: _Vtable) -> str:
    safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in vtable.subobject)
    fields = "\n".join(f"    void (*slot_{slot:04d})(void);" for slot in range(vtable.method_count))
    return f"struct {safe_name}_vftable {{\n{fields}\n}};"


def _default_type_name(vtable: _Vtable) -> str:
    safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in vtable.subobject)
    return f"{safe_name}_vftable"


@tool
@idasync
def rtti_vtables(
    query: Annotated[str, "Optional wildcard filter for class or subobject name"] = "",
    offset: Annotated[int, "Result offset"] = 0,
    limit: Annotated[int, "Maximum results (1-1000)"] = 100,
    refresh: Annotated[bool, "Rescan RTTI instead of using the per-IDB cache"] = False,
    deep_scan: Annotated[bool, "Scan data segments for RTTI missing IDA labels"] = False,
) -> VtablePage | RttiError:
    """List MSVC RTTI vtables with class hierarchy and method counts."""
    try:
        if offset < 0 or limit < 1 or limit > 1000:
            raise ValueError("offset must be >= 0 and limit must be between 1 and 1000")
        items = _get_vtables(refresh, deep_scan)
        if query:
            items = [
                item
                for item in items
                if _matches(item.class_name, query) or _matches(item.subobject, query)
            ]
        page = items[offset : offset + limit]
        next_offset = offset + len(page) if offset + len(page) < len(items) else None
        return {"data": [_summary(item) for item in page], "next_offset": next_offset, "total": len(items)}
    except Exception as exc:
        return {"error": str(exc)}


@tool
@idasync
def rtti_vtable(
    target: Annotated[str | int, "Vtable address or unique class/subobject wildcard"],
    method_offset: Annotated[int, "First virtual method slot to return"] = 0,
    method_limit: Annotated[int, "Maximum methods to return (1-1000)"] = 100,
    include_declaration: Annotated[bool, "Include a complete C vtable declaration"] = False,
) -> VtableDetail | RttiError:
    """Get one MSVC RTTI vtable with hierarchy and paginated methods."""
    try:
        vtable = _resolve_vtable(target)
        if method_offset < 0 or method_limit < 1 or method_limit > 1000:
            raise ValueError("method_offset must be >= 0 and method_limit must be between 1 and 1000")
        method_end = min(vtable.method_count, method_offset + method_limit)
        next_method_offset = method_end if method_end < vtable.method_count else None
        result: VtableDetail = {
            **_summary(vtable),
            "complete_object_locator": hex(vtable.col.ea),
            "type_descriptor": hex(vtable.col.type_descriptor),
            "class_hierarchy_descriptor": hex(vtable.col.hierarchy_descriptor),
            "object_offset": vtable.col.offset,
            "constructor_displacement": vtable.col.cd_offset,
            "bases": [],
            "methods": [_method(vtable, slot) for slot in range(method_offset, method_end)],
            "next_method_offset": next_method_offset,
        }
        if include_declaration:
            result["declaration"] = _declaration(vtable)
        for name, bcd, contained, mdisp, pdisp, vdisp, attrs in vtable.bases:
            td = _relative_or_pointer(bcd, vtable.col.image_base)
            result["bases"].append(
                {
                    "name": name,
                    "type_descriptor": hex(td) if td is not None else "",
                    "descriptor": hex(bcd),
                    "num_contained_bases": contained,
                    "mdisp": mdisp,
                    "pdisp": pdisp,
                    "vdisp": vdisp,
                    "attributes": attrs,
                    "attribute_names": _bcd_labels(attrs),
                }
            )
        return result
    except Exception as exc:
        return {"error": str(exc)}


@tool
@idasync
def rtti_vtable_slot(
    target: Annotated[str | int, "Vtable address or unique class/subobject wildcard"],
    slot: Annotated[int, "Zero-based virtual method slot"],
) -> VtableSlotResult | RttiError:
    """Resolve a zero-based slot to its entry address and virtual function."""
    try:
        vtable = _resolve_vtable(target)
        method = _method(vtable, slot)
        return {"vtable": hex(vtable.ea), "class_name": vtable.class_name, **method}
    except Exception as exc:
        return {"error": str(exc)}


@tool
@idasync
def rtti_apply_vtable_type(
    target: Annotated[str | int, "Vtable address or unique class/subobject wildcard"],
    type_name: Annotated[str, "Optional local struct name"] = "",
) -> VtableTypeResult | RttiError:
    """Create an idempotent vtable struct and apply it at the table address."""
    try:
        vtable = _resolve_vtable(target)
        resolved_name = type_name.strip() or _default_type_name(vtable)
        if not resolved_name.replace("_", "a").isalnum() or resolved_name[0].isdigit():
            raise ValueError("type_name must be a valid C identifier")

        declaration = _declaration(vtable).replace(
            f"struct {_default_type_name(vtable)}", f"struct {resolved_name}", 1
        )
        tif = ida_typeinf.tinfo_t()
        created = not tif.get_named_type(None, resolved_name)
        if created:
            flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
            errors, messages = parse_decls_ctypes(declaration, flags)
            if errors:
                raise ValueError("Failed to declare vtable type: " + "; ".join(messages))
            if not tif.get_named_type(None, resolved_name):
                raise ValueError(f"Declared type {resolved_name!r} could not be loaded")

        expected_size = vtable.method_count * _ptr_size()
        if tif.get_size() != expected_size:
            raise ValueError(
                f"Existing type {resolved_name!r} has size {tif.get_size()}, expected {expected_size}"
            )
        if not ida_typeinf.apply_tinfo(vtable.ea, tif, ida_typeinf.TINFO_DEFINITE):
            raise ValueError(f"Failed to apply {resolved_name!r} at {hex(vtable.ea)}")
        return {
            "ok": True,
            "vtable": hex(vtable.ea),
            "type_name": resolved_name,
            "declaration": declaration,
            "created": created,
        }
    except Exception as exc:
        return {"error": str(exc)}
