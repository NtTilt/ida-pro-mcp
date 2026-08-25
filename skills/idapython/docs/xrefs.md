# Cross-Reference Analysis

Use `xref_query` when direction, reference kind, ordering, or pagination matters.
Use `xrefs_to` for a simple bounded incoming-reference lookup.

## Detailed classification

Every returned xref retains the broad `type` (`code` or `data`) and also exposes:

- `kind`: detailed classification
- `type_code`: raw IDA xref type
- `type_name`: IDA's readable type name

Detailed kinds are `write`, `offset`, `read`, `text`, `informational`, `call`,
`jump`, `flow`, and `other`.

`offset` means an address/reference relationship. It does not by itself prove a
runtime memory read or write.

## Filtering

Set `xref_type` to one broad or detailed value. Use `xref_types` for an OR-list
of values. Existing `any`, `code`, and `data` filters remain supported.

For example, request `xref_type="write"` when looking for assignments to a
global instead of retrieving every data xref. Request
`xref_types=["write", "read"]` when both access modes matter.

Invalid filters return an error; they do not silently fall back to `any`.
Filtering happens before pagination, so `total` and `next_offset` describe the
filtered result set.

## Sorting and direction

Use `direction="to"`, `"from"`, or `"both"`. Use `sort_by="kind"` to group
results by this priority:

1. write
2. offset
3. read
4. text
5. informational
6. call
7. jump
8. flow
9. other

Addresses provide deterministic secondary ordering within each kind. The
default `sort_by="addr"` is retained for backward compatibility.

## Interpretation

IDA xrefs reflect references recognized by analysis. A detailed filter avoids
unnecessary follow-up calls, but absence of a kind is not proof that a runtime
access cannot occur. Verify important results with decompilation or disassembly.
