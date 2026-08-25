# MSVC RTTI and Vtables

Use these MCP tools for PE/MSVC class, hierarchy, vtable, and virtual-slot
analysis. Prefer them over manually recreating the RTTI parser with IDAPython.

## Workflow

1. Call `rtti_vtables` with a class or subobject wildcard.
2. Call `rtti_vtable` on the unique result to retrieve hierarchy metadata,
   method count, and a paginated method list.
3. Call `rtti_vtable_slot` when the desired zero-based slot is known.
4. Verify resolved functions with decompilation, disassembly, and xrefs.
5. Call `rtti_apply_vtable_type` only if the user wants a generated vtable
   structure applied to the database.

The active IDB is authoritative for its own build. Do not require an offsets
header or Class Informer export before analyzing RTTI in the open database.

## Tool routing

### `rtti_vtables`

Lists discovered vtables with class name, subobject, hierarchy, RVA, and method
count.

- `query`: optional wildcard for a class or subobject name.
- `offset` and `limit`: paginate matches; `limit` is 1-1000.
- `refresh=true`: rebuild the per-IDB RTTI cache after analysis or names change.
- `deep_scan=true`: scan data segments when IDA RTTI labels are absent or the
  fast results appear incomplete. Start with the default fast labeled scan.

### `rtti_vtable`

Returns one table selected by address or a unique class/subobject wildcard. Use
`method_offset` and `method_limit` to paginate methods. Set
`include_declaration=true` only when the generated C declaration is useful.

### `rtti_vtable_slot`

Resolves a zero-based slot to its table-entry address, target address, and IDA
name. Confirm the target's behavior before assigning semantic names or types.

### `rtti_apply_vtable_type`

Creates or reuses an idempotent local vtable structure and applies it at the
table address. This mutates the IDB. Use it only with user authorization and
save the database when requested.

## Evidence and fallbacks

Class Informer output is optional corroborating evidence. Request it only when
native parsing fails, results remain incomplete after a deep scan, or the user
explicitly requests a comparison. Build-specific offset headers are relevant to
cross-build comparisons, not as a prerequisite for current-IDB RTTI discovery.

Never reuse addresses, RVAs, method counts, or slots from a different build
without verifying them against the active IDB.

If a query matches multiple vtables, refine the class/subobject wildcard or use
the returned vtable address. For large classes, paginate methods rather than
requesting the entire table at once.
