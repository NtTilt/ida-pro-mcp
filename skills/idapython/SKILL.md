---
name: idapython
description: IDA Pro reverse-engineering conventions for any IDA MCP or IDAPython session: which typed MCP tool fits a given task, when raw py_eval is justified instead, modern ida_* module usage, RTTI and vtable recovery, cross-reference analysis, types, and Hex-Rays. Load this before the first IDA action in any session that opens, reads, annotates, or patches an IDB, including sessions that only use typed MCP tools and write no Python at all, since it defines the tool-versus-py_eval boundary and the ida_* over idc convention. Use whenever the user mentions IDA, IDB, .i64, disassembly, decompilation, Hex-Rays, or reversing a binary, crackme, malware, firmware, or CTF target, even if they never mention Python or scripting.
---

# IDAPython

Use modern `ida_*` modules. Avoid legacy `idc` module.

## Raw Python Execution

- Prefer the typed MCP tool whenever one exists. `rename`, `set_comments`,
  `set_type`, `declare_type`, `enum_upsert`, `get_bytes`, `patch`, `disasm`,
  `decompile`, `xrefs_to`, `xref_query`, `find_bytes`, and `list_funcs` cover
  most routine work. Their arguments and results are structured and each call is
  individually reviewable, which raw Python output is not; a session that drifts
  into doing everything through `py_eval` loses that reviewability and tends to
  accumulate unverified database state.
- Use `py_eval` for IDAPython the tools do not expose, for compact multi-step
  repairs, for bulk operations over a range, and for diagnostic probes that must
  execute inside the selected IDB.
- Use `py_exec_file` for a reviewed reusable script when inline `py_eval` would
  be unwieldy. Both tools require the MCP server to start with `--unsafe`.
- Always target the intended database/session explicitly. Prefer
  `force_headless` when raw Python availability must not depend on an adopted
  GUI server.
- Start with a read-only probe, validate addresses and existing objects, then
  perform the smallest mutation. Reanalyze, decompile, inspect the result, and
  save the IDB after successful verification.
- Capture and report `result`, `stdout`, and `stderr`; correct script/API errors
  instead of silently switching execution paths.
- If `py_eval`/`py_exec_file` is not exposed, state that the server lacks
  `--unsafe`. Do not manipulate the IDA GUI as a fallback unless the user
  explicitly requests GUI automation.

## MSVC RTTI and Vtables

For PE/MSVC RTTI work, read `docs/rtti.md` and use the native `rtti_*` MCP tools
before manual IDAPython or external Class Informer output. The active IDB is the
authoritative RTTI source for its own build.

## Cross-References

For targeted read/write/reference analysis, read `docs/xrefs.md` and use
`xref_query` filters before inspecting every referencing instruction.

## Module Router

| Task | Module | Key Items |
|------|--------|-----------|
| Bytes/memory | `ida_bytes` | `get_bytes`, `patch_bytes`, `get_flags`, `create_*` |
| Functions | `ida_funcs` | `func_t`, `get_func`, `add_func`, `get_func_name` |
| Names | `ida_name` | `set_name`, `get_name`, `demangle_name` |
| Types | `ida_typeinf` | `tinfo_t`, `apply_tinfo`, `parse_decl` |
| Decompiler | `ida_hexrays` | `decompile`, `cfunc_t`, `lvar_t`, ctree visitor |
| Segments | `ida_segment` | `segment_t`, `getseg`, `add_segm` |
| Xrefs | `ida_xref` | `xrefblk_t`, `add_cref`, `add_dref` |
| Instructions | `ida_ua` | `insn_t`, `op_t`, `decode_insn` |
| Stack frames | `ida_frame` | `get_frame`, `define_stkvar` |
| Iteration | `idautils` | `Functions()`, `Heads()`, `XrefsTo()`, `Strings()` |
| UI/dialogs | `ida_kernwin` | `msg`, `ask_*`, `jumpto`, `Choose` |
| Database info | `ida_ida` | `inf_get_*`, `inf_is_64bit()` |
| Analysis | `ida_auto` | `auto_wait`, `plan_and_wait` |
| Flow graphs | `ida_gdl` | `FlowChart`, `BasicBlock` |
| Register tracking | `ida_regfinder` | `find_reg_value`, `reg_value_info_t` |

## Core Patterns

### Iterate functions
```python
for ea in idautils.Functions():
    name = ida_funcs.get_func_name(ea)
    func = ida_funcs.get_func(ea)
```

### Iterate instructions in function
```python
for head in idautils.FuncItems(func_ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, head):
        print(f"{head:#x}: {insn.itype}")
```

### Cross-references
```python
for xref in idautils.XrefsTo(ea):
    print(f"{xref.frm:#x} -> {xref.to:#x} type={xref.type}")
```

### Read/write bytes
```python
data = ida_bytes.get_bytes(ea, size)
ida_bytes.patch_bytes(ea, b"\x90\x90")
```

### Names
```python
name = ida_name.get_name(ea)
ida_name.set_name(ea, "new_name", ida_name.SN_NOCHECK)
```

### Decompile function
```python
cfunc = ida_hexrays.decompile(ea)
if cfunc:
    print(cfunc)  # pseudocode
    for lvar in cfunc.lvars:
        print(f"{lvar.name}: {lvar.type()}")
```

### Walk ctree (decompiled AST)
```python
class MyVisitor(ida_hexrays.ctree_visitor_t):
    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_call:
            print(f"Call at {e.ea:#x}")
        return 0

cfunc = ida_hexrays.decompile(ea)
MyVisitor().apply_to(cfunc.body, None)
```

### Apply type
```python
tif = ida_typeinf.tinfo_t()
if ida_typeinf.parse_decl(tif, None, "int (*)(char *, int)", 0):
    ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
```

### Create structure
```python
udt = ida_typeinf.udt_type_data_t()
m = ida_typeinf.udm_t()
m.name = "field1"
m.type = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
m.offset = 0
m.size = 4
udt.push_back(m)
tif = ida_typeinf.tinfo_t()
tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
tif.set_named_type(ida_typeinf.get_idati(), "MyStruct")
```

### Strings list
```python
for s in idautils.Strings():
    print(f"{s.ea:#x}: {str(s)}")
```

### Wait for analysis
```python
ida_auto.auto_wait()  # Block until autoanalysis completes
```

## Key Constants

| Constant | Value/Use |
|----------|-----------|
| `BADADDR` | Invalid address sentinel |
| `ida_name.SN_NOCHECK` | Skip name validation |
| `ida_typeinf.TINFO_DEFINITE` | Force type application |
| `o_reg`, `o_mem`, `o_imm`, `o_displ`, `o_near` | Operand types |
| `dt_byte`, `dt_word`, `dt_dword`, `dt_qword` | Data types |
| `fl_CF`, `fl_CN`, `fl_JF`, `fl_JN`, `fl_F` | Code xref types |
| `dr_R`, `dr_W`, `dr_O` | Data xref types |

## Critical Rules

1. **NEVER convert hex/decimal manually** — use `int_convert` MCP tool
2. **Wait for analysis**: Call `ida_auto.auto_wait()` before reading results
3. **Thread safety**: IDA SDK calls must run on main thread (use `@idasync`)
4. **64-bit addresses**: Always assume `ea_t` can be 64-bit

## MCP Call Efficiency

- Reuse successful tool results; do not repeat identical calls unless relevant
  IDB state changed, the result was truncated, or a refresh is required.
- Keep discovery proportional to the task. Skip broad binary surveys when the
  active database and target are already established.
- Request only the needed page or range, and save the IDB once after related
  mutations are complete.

## Anti-Patterns

| Avoid | Do Instead |
|-------|------------|
| `idc.*` functions | Use `ida_*` modules |
| Hardcoded addresses | Use names, patterns, or xrefs |
| Manual hex conversion | Use `int_convert` tool |
| Blocking main thread | Use `execute_sync()` for long ops |
| Guessing at types | Derive from disassembly/decompilation |
| Requiring Class Informer for MSVC RTTI | Use `rtti_vtables` and related RTTI tools first |
| Reusing another build's RTTI addresses | Derive RTTI from the active IDB |

## Detailed API Reference

For comprehensive documentation on any module, read `docs/<module>.md`:
- **High-use**: `ida_bytes`, `ida_funcs`, `ida_hexrays`, `ida_typeinf`, `ida_name`, `idautils`
- **Medium-use**: `ida_segment`, `ida_xref`, `ida_ua`, `ida_frame`, `ida_kernwin`
- **Specialized**: `ida_dbg` (debugger), `ida_nalt` (netnode storage), `ida_regfinder` (register tracking)
- **Workflow**: `rtti` (native MSVC RTTI and vtable MCP tools)
- **Workflow**: `xrefs` (filtered and prioritized cross-reference analysis)

Full RST sources from hex-rays.com available at `docs/<module>.rst`.
