---
name: project-memory-cbor-reading
description: Shared monoidlib CBOR parsing and encoding, Monoid/CTAP profiles, storage and cursor variants, field order, and measured parser behavior. Use when changing CBOR readers, writers or request parsing.
---

# Monoid CBOR reading

Source: `../records.md`, records [112](../112.md), [113](../113.md), [153](../153.md), [166](../166.md), [175](../175.md), [176](../176.md), [178](../178.md), [179](../179.md), [180](../180.md) and [189](../189.md). Treat those
records as authoritative and keep them current when changing this snapshot.

- Record175 supersedes the separate Reader/Writer implementations described in
  record166. `monoidlib.cap` is a library package without an Applet instance,
  package AID `F06D6F6E6F696404`. Monoid and Security Key import its `CBOR`,
  `CBORReader`, `CBORBufferReader`, `CBORMap`, `CBORWriter` and `ByteSource`.
  Record176 also moves `CBORApduReader`, `CBORBufferWriter`, `CBORApduWriter`
  and `CBORResponse` into the library. Record189 also shares Monoid/OTP short-APDU
  framing through `monoidlib.ApduTransport`; Security Key retains CTAP framing.
  Monoid no longer subclasses the APDU reader to gate individual reads by READY;
  the transport only executes a command after the complete request arrives.
  Identity remains independent. Load the library before its clients; replacing it
  requires removing dependent OTP, Security Key and Monoid packages first.
- The shared transport's protected reader/writer constructor and `supports(byte)` /
  `execute(byte)` hooks leave command dispatch in two thin Monoid/OTP subclasses.
  `clear/clearRequest/isReceiving/process/receive` are public final. Header3,
  state1short and reader/writer references are per instance, not shared statics.
  Unknown INS is rejected before receiving data; chain validation, GET RESPONSE,
  cleanup and GC retain their existing wire behavior. Record189 passes670 tests/
  78suites and fiveCAPs locally, including interleaved independent-instance chains;
  ACR39U/J3R452 contact-transport-1 passes40 physical checks/175events with136 source
  hashes matching the tested snapshot. RAM boundaries match186:1417/1408B fresh,
  1353/1344B after16accounts and562/560B warm, not peaks. Prepare's nine-run mean
  is582.44ms versus610.04ms; other timings and combined-change attribution limits
  are in189. All five temporaryCAPs/fourinstances are removed, registry matches
  baseline with vendor/system apps preserved, and the reader is released. No formal deployment.
- `CBORReader(buffer, offset, length)` selects `PROFILE_CTAP`; the four-argument
  constructor explicitly selects `PROFILE_CTAP` or `PROFILE_MONOID`.
  `CBORBufferReader(buffer)` selects Monoid's profile. The protected no-argument
  constructor serves the library's chunk-based `CBORApduReader`; subclasses provide
  logical bounds and ByteSource access, without assembling another full buffer.
  Contiguous input uses direct array reads/copies. Do not replace it with virtual
  per-byte chunk dispatch or flatten chunked input just to share parsing code.
- The profiles preserve different protocol semantics. CTAP checks shortest
  argument encodings, UTF-8 and nesting limits, rejects indefinite containers
  and duplicate selected map fields, and reports CTAP status values. Monoid
  retains its indefinite array/map support, first-selected-duplicate behavior and
  `SW_WRONG_DATA` errors. Shared implementation does not make the profiles
  interchangeable or make all unknown-field/type rules identical.
- Reader cursor/end use a two-short CLEAR_ON_DESELECT array. Monoid navigation
  uses six further shorts; snapshot storage is allocated only when used. CTAP's
  ordinary forward/indexed reads do not allocate Monoid navigation or snapshots.
  Map offsets also remain transient. Initialize command-start sentinels explicitly
  and do not reintroduce persistent hot-path cursor writes.
- Storage and cursor behavior are now explicit method variants:

  | Read method                           | Result storage                          | Cursor after success |
  | ------------------------------------- | --------------------------------------- | -------------------- |
  | `bytes()`, `text()`                   | New private persistent array            | After the content    |
  | `bytesTransient()`, `textTransient()` | CLEAR_ON_DESELECT array                 | At content start     |
  | `bytesGlobal()`                       | Call-scoped global array                | At content start     |
  | `bytes(out, ...)`, `text(out, ...)`   | Caller-provided array                   | After the content    |
  | `bytesLength()`                       | No copy; returns length                 | At content start     |
  | `bytesOffset()`, `textOffset()`       | No copy; returns logical content offset | After the content    |

  Expected-length variants retain their base method's storage/cursor behavior.
  Keep mostly read-only private data persistent; choose global arrays where an
  immediate cross-Applet call requires them, rather than treating global as the
  default. A logical offset is not necessarily an index in one contiguous array:
  use ByteSource for chunked input. Do not add cursor increments based on the old
  meaning of `bytes()`/`text()`; old Monoid callers now explicitly use the
  non-advancing transient/global variants where needed.

- Record189 uses `bytesGlobal(41/64)` for OTP Prepare's signed time data and
  signature, passing them straight to Identity instead of persistent intermediate
  copies followed by global copies. The retained challenge still needs a global
  copy for verification; time8 and indices remain persistent across SELECT.
  Finish copying request fields before client `connect()` borrows APDU scratch.

- Common APDU reception supports borrowed complete short input, on-demand
  persistent 256B chunks, or a fixed persistent request buffer. Record178 removes
  the former first512B transient tier. On J3R452/ACR39U, the same666B request's
  first two fragments previously reduced available RESET RAM519→263→7B; the new
  chunks keep519B available, consume544B persistent space, and let600B Create
  complete. The following Get600 failed in178; record179 then moves the response
  chunks/window to persistent storage, enabling600/1536B reads/writes and List in
  the standalone layout. Record180 resolves the subsequent full-layout cold Hello
  and Ed25519 allocation failures: one four-CAP installation passes initialization,
  FIDO, direct/SLIP-0010 Ed25519 through1536B, reads/writes and communication.
  These are boundary samples, not peaks. The reader
  end offset also holds the received length; protocol layers decide first/last
  frames, header matching and error status. Do not retain an APDU buffer reference.
  Keep byte-level chunk access direct: record176 found that layered buffer/chunk
  getters raised small Create overhead to111ms; direct inherited fields reduced
  that to25ms. The final transport composition removes the Monoid read overrides
  and keeps readiness checks at the command boundary; small Create then measured
  about27ms faster than the original baseline, with the same parsing/storage policy.
- The common writer owns encoding, buffers and segmented sending. Dynamic Monoid
  output borrows APDU scratch then uses persistent chunks or a persistent streaming
  window, emitting up to four units per APDU. Record179 removes its RAM tier:
  the600B response keeps519/512B RESET/DESELECT available across three frames,
  with548B total temporary persistent allocation recovered after the last frame.
  Do not attribute all548B to the512B window itself. Short response borrowing and
  fixed CTAP storage remain unchanged;
  fixed CTAP output uses a 64B write window or direct APDU response. A fragmented
  direct response is copied before GET RESPONSE overwrites the borrowed buffer.
  Allocate only the structures needed by the selected mode. Buffers and callbacks
  still belong to the calling applet context; library code is shared, not its data.
  `bytesLength(n)` starts one byte string; `rawBytes(...)` supplies its body
  without emitting additional headers. Keep CTAP's definite-container encoding
  at its call sites; availability of indefinite writer methods is not permission
  to change CTAP responses. APDU buffers remain borrowed locally and must not be
  retained in a persistent/global reference.
- Record180 applies the same storage policy to low-write private decoded inputs,
  outputs and crypto metadata; authorization, session and parser cursor state keep
  their transient lifecycle. When an Identity result's destination is already the
  APDU buffer, copy directly through SIO instead of allocating another global
  intermediate array. This does not retain the APDU reference or alter framing.
  The final full layout passes600/1536B CRUD, small continuation reads, three-member
  Bundle responses and signing after communication. Warm signing boundaries have
  1164/1168B RESET/DESELECT available; initialized communication resources leave
  771/784B, stable across later observed operations. Get600 retains548B temporary
  persistent storage until its final frame while RAM remains unchanged. These
  measurements do not establish peak memory or arbitrary payload-size support.
- Record166's historical trial parsing short credential records directly from
  APDU scratch was slower and was reverted. The shared library keeps ordinary
  private-record reading; common source is not a reason to repeat that storage
  change without new evidence. Record175's comparison uses the accepted uniform
  CTAP tail-GC baseline from174, not the earlier selective-GC build. Use the
  actual same-card/same-reader results recorded there; do not mix contact timings
  with prior ACR1552/NFC results or claim command-boundary RAM as peak RAM.
  Record176's final `unified-transport` shared-APDU comparison adds about6ms to
  warm FIDO login and11ms to PIN negotiation, keeps FIDO RAM availability
  unchanged, and adds422B of LOAD components versus its original baseline.
  These replace the intermediate `unified-direct` figures of3/7ms and538B;
  the final version saves96B of warm persistent space versus that intermediate.
  Treat the small timing samples as descriptive results, not significance estimates.
  Record175's complete-layout600B Ed25519 RAM limit is historical: record180
  verifies direct and SLIP-0010 messages through1536B with Security Key installed
  and warmed, including signing after Identity transfer/Bundle work. Keep those
  results separate from175's standalone Ed test. Contact reset can change later
  communication timings;180 records the ATR and probe evidence. Do not attribute
  those whole-operation differences solely to CBOR or persistent storage.

- Record153: document toolchain workarounds at every affected call site. The
  explicit CBORReader casts on setOffset calls avoid a CAP converter failure
  resolving the inherited method through CBORApduReader; explain that reason
  locally rather than leaving an apparently redundant cast unexplained.
- The user wants payload assembly and consumption considered together, aiming
  to read the complete request with as few backward scans as practical. After
  requesting a same-payload sequential probe, authorized implementation if the
  results were effective. Field order remains a recommendation, not a requirement.
- `cbor-field-order.json` at the repository root is the machine-readable order
  for APP serializers, covering the current CBOR commands from
  Command.get(). Empty-request commands have an empty root list; GET RESPONSE
  0xC0 is transport control and has no entry. Command INS keys select maps by `$` (request root),
  `$.derivation` and `$.taproot`. Explicit `[]` paths such as `$.keys[]` configure
  array element maps and `$.keys[].derivation` their nested maps. Traverse arrays
  only when that element-map path is configured. Reorder existing fields only;
  append unlisted fields in their original relative order and leave unconfigured
  maps, arrays, byte buffers and scalars unchanged. The config is not a request
  schema or whitelist.
  Root `seed`, `curve` and `path` in Java's lookup arrays exist for rejection;
  do not export them as recommended input fields. Protocol documentation links
  to this configuration instead of duplicating its lists. APP integration is
  outside this Java Card change.
- The copyable JS helper is doc/examples/order-cbor-request.js. It accepts numeric
  INS, a plain-object request and the parsed config. Use it immediately before
  CBOR encoding with insertion order preserved (no canonical key sorting).
  Its Node tests cover the configured commands and value/reference preservation.
- Other commands' recommendations follow their current first-read order:
  Authenticate reads secret before pin; SetPIN reads pin before secret; Create reads
  data, key, alias before choosing type or index; CreateRandomKey reads type and
  length (required for entropy/seed). Config coverage does not mean that
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
- Inspect cursor behavior before composing sequential reads. Before175,
  Monoid's allocating `bytes()`/`text()` left the cursor at the content start;
  current explicit transient/global variants preserve that behavior, while the
  persistent variants advance. `bytesLength()` still leaves the cursor at the
  message start for ByteSource signing. Do not remove `key()`'s rewind in isolation.
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
- In the Monoid profile, CBORMap records the first duplicate field, ignores
  unknown fields, and defers value-type checks until a field is consumed. For
  example, ECDSA ignores an irrelevant message value and BIP32 ignores context.
  CTAP instead rejects duplicate selected fields. Preserve each profile's semantics.
  Indexing structurally scans the map, so malformed trailing CBOR can be rejected
  before an individual requested value is read. Do not promise identical error
  precedence for malformed encodings.
- Indexing is not a claim that every payload byte is visited exactly once:
  parent scanning skips nested container metadata, a selected nested map is
  indexed separately, and consumed value headers are decoded again. Byte/text
  bodies are skipped by length. Ed25519 still borrows the Message through
  ByteSource; no full-message copy is introduced.
- CBORMap's wrapper is an ordinary persistent object; only its offsets use
  transient RAM. Monoid's operation-local indexed views remain short-lived.
  CTAP may reuse a map created from a fixed `short[]` or `Object[]` schema by
  calling `read(reader)`, which resets offsets and rescans the new input; do not
  reuse previous offsets as valid across requests. Include allocation and cleanup
  costs when comparing a new view with reuse, rather than assuming wrappers are free.
- Distinguish scanning metadata from reading payload bodies. `skip()` jumps
  over byte/text bodies by length, while nested containers require traversal.
  Do not claim every failed lookup rereads an entire Message body.
- Reader cursors and snapshots use CLEAR_ON_DESELECT RAM (record112, retained
  in175); no previous request's parser positions are valid for a new operation.
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
