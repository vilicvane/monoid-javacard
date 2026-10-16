---
name: project-memory-cbor-reading
description: Monoid Java Card CBOR payload assembly, field lookup order, cursor and snapshot semantics, and parser performance measurements. Use when changing CBORReader or command request parsing.
---

# Monoid CBOR reading

Source: `../records.md`, records [112](../112.md) and [113](../113.md). Treat those
records as authoritative and keep them current when changing this snapshot.

- The user wants payload assembly and consumption considered together, aiming
  to read the complete request with as few backward scans as practical. After
  requesting a same-payload sequential probe, authorized implementation if the
  results were effective. Field order remains a recommendation, not a requirement.
- `cbor-field-order.json` at the repository root is the machine-readable order
  for future APP serializers, covering all thirteen current CBOR commands from
  Command.get(). Empty-request commands have an empty root list; GET RESPONSE
  0xC0 is transport control and has no entry. Command INS keys select maps by `$` (request root),
  `$.derivation` and `$.taproot`. Reorder existing fields only; append unlisted
  fields in their original relative order and leave unconfigured maps, arrays
  and scalars unchanged. The config is not a request schema or whitelist.
  Root `seed`, `curve` and `path` in Java's lookup arrays exist for rejection;
  do not export them as recommended input fields. Protocol documentation links
  to this configuration instead of duplicating its lists. APP integration is
  outside this Java Card change.
- The copyable JS helper is doc/examples/order-cbor-request.js. It accepts numeric
  INS, a plain-object request and the parsed config. Use it immediately before
  CBOR encoding with insertion order preserved (no canonical key sorting).
  Its Node tests cover the configured commands and value/reference preservation.
- Other commands' recommendations follow their current first-read order:
  Authenticate reads safe before pin; SetPIN reads pin before safe; Create reads
  data, key, alias before choosing type or index; CreateRandomKey reads type and
  length (required for entropy/seed/master). Config coverage does not mean that
  these commands use CBORMap or have measured performance improvements.
- Legacy CBORReader `key()`/`requireKey()` search from the active map's start;
  `index()` similarly restarts from the array start. Ordering calls like encoded
  fields currently does not avoid rescanning prefixes. The initial sequential
  `key()` in `3af1f4d` was intentionally changed by `cd1fade` on 2025-07-17.
- Consider absent-field checks as well as successful lookups. Baseline direct
  ECDSA Sign has four encoded fields but nine lookups and five full failed scans:
  30 candidate-key visits in the common `index,type,cipher,digest` encoding.
  Nested derivation handling adds further searches. This describes the baseline
  before Sign/ViewKey adopted CBORMap. Preserve approved validation
  semantics when considering one-pass parsing or a forward-search fast path.
- Inspect cursor behavior before composing sequential reads. Allocating
  `bytes()`/`text()` leave the cursor at the content start; their output-buffer
  overloads advance past the content. `bytesLength()` intentionally leaves the
  cursor at the message start for ByteSource signing. Do not make these uniform
  blindly or remove `key()`'s rewind in isolation.
- Preserve nested-map/array bounds and snapshot/restore behavior. Snapshot map
  offsets intentionally capture the current offset. Missing optional fields,
  nested values and repeated lookups need explicit treatment in any sequential
  design; starting in the middle with the full map count is not a valid bound.
- Existing command inputs permit reordered fields, including nested derivation
  fields. Maintain that behavior unless the user explicitly approves a protocol
  change. Coordinate a common writer/reader order as a fast path where useful;
  do not turn it into an undocumented interoperability requirement.
- Sign/ViewKey now use `reader.map(fields)` to create an operation-local CBORMap:
  one field scan records selected value offsets in a transient short array,
  followed by direct positioning and the existing conditional value reads.
  Root and derivation views are independent; these commands no longer need
  snapshots to return to root fields. Keep the schema next to each command.
  Taproot's single-field map and commands without repeated searches retain the
  legacy reader. Do not introduce indexing allocations without useful reuse.
- CBORMap records the first duplicate field, ignores unknown fields, and defers
  value-type checks until a field is consumed. For example, ECDSA ignores an
  irrelevant message value and BIP32 ignores context. Preserve those semantics.
  Indexing structurally scans the map, so malformed trailing CBOR can be rejected
  before an individual requested value is read. Do not promise identical error
  precedence for malformed encodings.
- Indexing is not a claim that every payload byte is visited exactly once:
  parent scanning skips nested container metadata, a selected nested map is
  indexed separately, and consumed value headers are decoded again. Byte/text
  bodies are skipped by length. Ed25519 still borrows the Message through
  ByteSource; no full-message copy is introduced.
- CBORMap's wrapper is an ordinary short-lived object with persistent reference
  initialization; only its offsets use transient RAM. Do not retain a view in a
  Command field or across operations. Include allocation and cleanup costs in
  real-card performance comparisons instead of assuming the wrapper is free.
- Distinguish scanning metadata from reading payload bodies. `skip()` jumps
  over byte/text bodies by length, while nested containers require traversal.
  Do not claim every failed lookup rereads an entire Message body.
- Reader cursors and snapshots use CLEAR_ON_DESELECT RAM (record 112); explicit
  command-start reset still initializes sentinels. No parser state needs to
  survive an operation. Do not reintroduce persistent hot-path cursor writes.
- Report Reader timing separately from complete Sign/ViewKey timing. A physical
  receive-only control with identical request bytes can estimate incremental
  parsing cost; label included allocation/cleanup work and measurement limits.
  Full-command speedups are not measurements of remaining pure parsing cost.
- Record 113's second same-card diagnostic compares receive-only, legacy lookup,
  and an eager sequential loop over identical payloads: parsing increments are
  about 287 to 108ms (direct ECDSA), 479 to 161ms (BIP32), 496 to 164ms
  (Monoid-001), and 471 to 143ms (SLIP-0010 locating a 300B Message). Eleven
  measured triples per case, with root/nested reversed cases, passed 336
  operations. These include value allocation, type checks, extra checksum work
  and GC effects; they exclude auth, Safe, cryptography and Message-body reads.
  This eager diagnostic differs from production's indexed lazy reads; use the
  separate full-command A/B results in record 113 for production speedups.
- Record 113's production comparison uses the transient-reader build as baseline:
  direct k1/P-256 ECDSA 630/635 to 517/511ms, BIP340 853 to 713ms, BIP86
  1004 to 856ms, cached BIP32 Sign 879 to 679ms, Monoid-001 Sign 901 to 688ms,
  BIP32 ViewKey 705 to 624ms, and Ed25519 empty/300B 2710/2748 to 2473/2534ms.
  Seven samples per case (Ed25519 five), excluding warmup. All 192 simulator
  tests and 278 physical operations passed with 156 independently checked
  signatures; operation-end warmed free reset/deselect RAM stays 1786/1776B.
  This is not a peak RAM measurement. Temporary packages were removed and
  the original registry/state preserved. Full ranges and scope are in record 113.
