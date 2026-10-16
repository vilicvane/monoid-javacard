# APDU transport

Monoid exchanges CBOR requests and responses over short APDUs. The client transport
layer handles fragmentation and response assembly; callers use the complete
[command definitions](../README.md#iso-7816-commands) regardless of message size.
Extended APDUs are not supported.

## Requests

Encode the complete request as CBOR, then split it into frames containing 1–255
data bytes each. The complete encoded request must not exceed 8192 bytes, including
keys and other metadata. This is a transport ceiling; individual commands and
cards can have lower capacity limits. Even an empty request map is encoded as
CBOR data (`A0`), not an APDU with no data.

Recommended CBOR field order is defined in
[cbor-field-order.json](../cbor-field-order.json), keyed by command INS. `$` denotes
the request map; `$.derivation` and `$.taproot` denote its named child maps.
All current CBOR commands are included; an empty field list denotes an empty
request map. GET RESPONSE (`0xC0`) has no CBOR request and is not listed.

Serialize existing fields in the configured order, then append unlisted fields
in their original relative order. Do not add absent fields. Leave unconfigured
maps, arrays and scalar values unchanged, including boolean `taproot` values.
This configuration is a sorting hint, not a request schema. Other field orders
remain supported; this is not a canonical CBOR encoding requirement.

The [JavaScript template](examples/order-cbor-request.js) accepts a numeric INS,
a plain-object request and the parsed field-order configuration:

```js
const ordered = orderCborRequest(0x41, request, fieldOrders);
const payload = encode(ordered); // Your CBOR encoder.
```

Copy the template and configuration into the client. Call it immediately before
CBOR encoding, then fragment the encoded bytes as usual. The encoder must preserve
object property order; disable canonical key sorting. The helper leaves the input
unchanged and preserves byte arrays and other unconfigured values by reference.

| Frame  | CLA  | Behavior                                                          |
| ------ | ---- | ----------------------------------------------------------------- |
| Single | `00` | Replace any unfinished request and execute this complete request. |
| First  | `90` | Replace any unfinished request and begin receiving a new one.     |
| Middle | `B0` | Append to the active request.                                     |
| Last   | `A0` | Append to the active request and execute it.                      |

Every frame carries the command's INS, P1 and P2. Middle and last frames must match
the first frame's header. Fragment boundaries may split CBOR fields; individual
frames do not need to contain valid CBOR values.

First and middle frames return an empty `9000` acknowledgement. The command runs
only after a single or last frame. A two-frame request uses first then last; a
longer request inserts middle frames between them. Do not send GET RESPONSE for
these intermediate acknowledgements.

## Responses

Response data is returned in chunks of up to 256 bytes. Append each response's
data, excluding its two status bytes, to the complete response buffer:

- `9000`: the response is complete; decode the assembled CBOR.
- `61xx`: more data remains; send `00 C0 00 00 Le` to fetch the next chunk.
  Set `Le` to `xx`; `00` represents 256 bytes. Repeat until `9000`.

Always use CLA `00` for GET RESPONSE, including after a last request frame with
CLA `A0`. Disable or adapt middleware that automatically reuses the preceding
request's CLA. For Java SmartcardIO, set
`sun.security.smartcardio.t1GetResponse=false` when handling continuation yourself.

## Cancellation and errors

A new single or first frame cancels an unfinished request, including a retry of
the same command. A new command request also discards any unread response.
Selecting or deselecting the applet, or resetting the card, cancels pending
transfers.

| Status | Meaning                                                                                            |
| ------ | -------------------------------------------------------------------------------------------------- |
| `6700` | Empty or oversized input, including a request exceeding 8192 bytes.                                |
| `6883` | Middle/last frame without a matching active request, or GET RESPONSE during an unfinished request. |
| `6985` | GET RESPONSE with no pending response.                                                             |
| `6A86` | GET RESPONSE with nonzero P1 or P2.                                                                |
| `6D00` | Unsupported INS.                                                                                   |
| `6E00` | Unsupported CLA; GET RESPONSE requires `00`.                                                       |

Request reception errors discard the unfinished request; retry with a single or
first frame. GET RESPONSE header and state validation errors preserve pending
transfers, so an unfinished request can still receive its next frame and an unread
response can still be retrieved with a valid GET RESPONSE. A failure while sending
response data cancels the remaining response.

Transport completion does not imply command success. Commands can return a CBOR
`{error: {code: ...}}` response with `9000`; inspect the assembled response too.
