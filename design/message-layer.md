# ShieldNet message layer

> **Design notes — informative.** The specification is
> [`spec/message-layer.md`](../spec/message-layer.md) (ShieldNet Message Layer).
> This document is the reasoning behind it: what each rule is for, and what was
> considered and rejected. Where the two differ, the specification governs.
> Where these notes say a rule is required, the specification is what requires
> it.

These notes explain the **application message layer**: the length-prefixed,
AEAD-sealed, optionally LZ4-compressed messages that flow inside an established
ShieldNet session, together with
[`transport.md`](transport.md).

It is the layer the transport design declares out of scope and cites rather than
restates (transport §13). The two carve-outs on it — no compression of control
messages, and fixed-size padding classes — are stated by `spec/message-layer.md`
§6 (the rules and the categories) and, for each kind's category, by
`spec/application.md` Section 3.5; transport §13 keeps their rationale, and they
are not repeated here.

All multi-byte integers are **big-endian**.

Session establishment, the key schedule and the golden vectors for both belong to
the transport (§3 and §4 below are pointers into it), so these notes discuss
only what happens once a session exists.

---

## 1. Placement

From the wire up:

1. **UDP**, then the **admission** exchange and the authenticated **envelope**
   around every KCP datagram —
   [`transport.md`](transport.md) §3–§8.
2. **KCP** — an ARQ protocol providing reliable, ordered delivery of a byte
   stream in each direction, as implemented by `ikcp.c`
   (transport §8.7). The KCP object is created only at promotion
   (transport §8.5), so it never sees an unauthenticated byte.
3. **Data messages** — this document. They may flow in both directions:
   client→server under `k_c2s` and server→client under `k_s2c` (§4). A send-only
   client (e.g. a media/frame push) simply never uses the reverse direction; a
   request/response protocol uses both.

### 1.1 KCP stream mode is mandatory on every endpoint

`spec/message-layer.md` 3.1 requires stream mode (`stream = 1`) on both peers
(`spec/transport.md` §13 item 2 refers to it). A message of this layer is
length-prefixed and may span many MTU-sized KCP receive items, and a message-mode
sender is not interoperable with a bounded receive buffer that reads exact byte
counts.

This is the message layer's requirement; `spec/transport.md` §13 item 2 refers to
it, and nothing in the admission or envelope path needs a stream.

Receive-window sizing is **not** part of this layer. Window sizes are local to a
device, a device-memory question; the figures are in `spec/transport.md`
Appendix B, and the reasoning in transport §9.5 and §11. Stream mode is what
makes small windows reachable: upstream KCP's `ikcp_wndsize` raises any receive
window below 128 to 128 (`IKCP_WND_RCV`), and a device using a smaller window
must remove that clamp (`spec/transport.md` Appendix B). Stream mode is what
makes that safe, because message-mode reassembly needs a window larger than the
largest fragment count. Why the window bounds only authenticated traffic is
transport §9.5's.

### 1.2 Read failures are not interchangeable

The wire format carries no resynchronisation marker, so the specification
requires a receiver to distinguish three outcomes and not to collapse them into
one error:

| outcome | stream state | behaviour the specification requires |
|---|---|---|
| **No progress** — the read failed having consumed no bytes of a frame | still on a frame boundary | Reusable. An idle timeout with nothing in flight is the normal case, not an error. |
| **Frame rejected** — a frame was read *in full* and then refused (failed AEAD open, sizes disagreed, would not decompress) | still on a frame boundary | The session survives. Reading continues. |
| **Partial frame** — some but not all of a frame's bytes were consumed | unrecoverable | The session is closed. Every later read would parse payload bytes as a header. |

The middle row matters most and is the one implementations get wrong. A frame
that fails here came from the authenticated peer — the transport envelope lets no
one else put a byte into KCP (transport §8.1) — so it is a peer defect or a
replayed number (§6.2), not an attack, and one bad frame is not a reason to throw
away a session that costs an admission to replace. Rejecting the frame and reading
on is what makes the AEAD a filter rather than a fuse.

**"Still on a frame boundary" is an assumption in this row, not a proof.** The
`Size` that located the boundary is authenticated only by the open that just
failed. If it was wrong, the next 20 octets are not a header: they fail §7's
pre-read bounds, which is the third row, or they declare a body that never
arrives. The specification therefore has a receiver bound how long a partly-read frame
may stall and treat expiry as the third row, so a misaligned stream ends the session
instead of hanging it.

Rejecting a header *before* its payload is read — an implausible `Size`, or one
exceeding a receiver's bounded buffer (§7.1) — belongs in the third row, not the
second: the header was consumed and its body was not.

**A fragment the receiver still holds has not been lost.** The third row is about
bytes that are *gone* — taken off the stream and unrecoverable. A receiver that
reads into a per-session staging buffer and resumes the same frame on its next
call has consumed nothing it cannot complete, so a read that stops mid-frame
because the receiver's **own** deadline expired is the first row, not the third.
The distinction is not pedantic: a caller has legitimate reasons to bound a read —
a device polling for its session to be replaced, a controller bounding the time it waits for a reply — and a 20-byte header or a body
spans two KCP segments routinely. Without staging, every such deadline landing
between them destroys a healthy session, and the one error that means "this
session cannot be recovered" stops meaning it. An implementation that does not
stage still reports the third row, because for it the bytes really are lost.

## 2. Cryptographic primitives

- **AEAD:** XChaCha20-Poly1305 (24-byte nonce, 16-byte Poly1305 tag). Note this
  differs from the transport envelope, which uses ChaCha20-Poly1305-IETF with a
  12-byte nonce (transport §3.6). The two are separate constructions under
  separate keys and are not interchangeable.
- **Compression:** LZ4 block format, subject to the prohibition on compressing
  control messages (`spec/message-layer.md` §6; each kind's category is in
  `spec/application.md` Section 3.5).

Key material is derived by the transport, not here — see §4.

## 3. Session establishment

**Not this layer.** Sessions are established by the transport's
INIT/RETRY/FINISH/ADMIT admission exchange (transport §3, §6, §7). This layer has
no handshake of its own and no establishment state: it begins at the first message
sent on a session, and that first message **is** the promoting PUSH — the
transport cannot promote without one (transport §7.4 step 5), so *take control*
carries it and it is `MessageNum` 1.

## 4. Keys and direction

Derived by the transport (transport §4.5).
This layer consumes two of the five outputs of that schedule:

- `k_c2s` — seals **client→server** data messages.
- `k_s2c` — seals **server→client** data messages.

The other three never appear at this layer: `k_kcp_c2s` and `k_kcp_s2c` key the
envelope, and `admit` authenticates ADMIT.

**Direction rule:** each direction has its own key and its own `MessageNum`
counter. Deriving two distinct directional keys is what defeats reflection — a
frame replayed back at its sender authenticates under the other direction's key
and fails. Because the keys are fresh per session (transport §4.5), a ciphertext
captured in one session cannot be opened under another's; see §8.

## 5. Data messages

A data message is sealed with the sender's directional key (§4): client→server
under `k_c2s`, server→client under `k_s2c`; the peer opens it with the same key.
Each `MessageNum` counter is per-direction and strictly increasing (§6.2). Each
data message is a 20-byte header followed by the payload:

```
offset  size  field
0       4     Size          u32  on-wire payload length (ciphertext + 16-byte tag)
4       4     OriginalSize  u32  plaintext length before compression or padding
8       4     MessageType   u32  bit 31 is FlagCompressed; bits 0-30 are the application's
12      8     MessageNum    u64  strictly-increasing per-session counter
20      Size  payload
```

- `FlagCompressed = 0x80000000`. When set, the (decrypted) payload is LZ4-
  compressed and `OriginalSize` is the decompressed length.
- Bits 0–30 of `MessageType` belong to the layer above. This layer authenticates
  them (they are in the AAD) and delivers them unchanged; it neither interprets
  nor rejects any value. What they mean, and what a receiver does with bits it
  does not use, is that layer's rule (`spec/application.md` Section 3.1).
- The **20-byte header is the AEAD additional authenticated data (AAD)**,
  serialized big-endian exactly as above, with `Size` being the on-wire
  (encrypted) length.

Send:

1. Choose the sealed body: the plaintext; or its LZ4 compression, used only if
   smaller, with `FlagCompressed` set; or the plaintext followed by zero octets up
   to its padding size class (`spec/message-layer.md` 6.2). Never both compressed
   and padded.
2. Build the header: `OriginalSize` = plaintext length, `Size` = sealed body
   length + 16, `MessageNum` = the next counter value (§6.2).
3. Compute `nonce` from `MessageNum` (below).
4. `Seal(key, nonce, aad = 20-byte header, plaintext = sealed body)` →
   on-wire payload = `ciphertext || tag`, whose length is `Size`.
5. Write header, then payload.

Receive:

1. Read the 20-byte header; validate (§7).
2. Recompute `nonce` from `MessageNum`.
3. `Open(key, nonce, aad = header, ciphertext||tag)`.
4. If `FlagCompressed`, LZ4-decompress to `OriginalSize` bytes; otherwise keep
   the first `OriginalSize` bytes (§7).

**Deterministic nonce** (24 bytes), derived from the header's `MessageNum` and
NOT transmitted:

```
nonce = 8 zero bytes || MessageNum (8 bytes, big-endian) || 8 zero bytes
```

i.e. `nonce[0:8] = 0`, `nonce[8:16] = BE(MessageNum)`, `nonce[16:24] = 0`.

## 6. Invariants

1. **Minimum ciphertext length is 16 (tag only).** The nonce is not on
   the wire. Reject any encrypted payload shorter than 16 bytes.
2. **Data-phase `MessageNum` starts at ≥ 1 and is strictly increasing.**
   - Sender: first data message is `MessageNum = 1`; each subsequent message
     uses a strictly greater value. The sequence need not be contiguous — a
     send that fails before any byte reaches the wire still consumes a
     number, leaving a gap — but it must never repeat or go backwards.
   - Receiver: keep `lastAccepted` (init 0); accept only `MessageNum >
     lastAccepted`, drop anything `≤`. Gaps are expected and are not an error.
     This is the in-session replay defence; because KCP delivers in order and
     reliably, a single counter suffices (no sliding window).
   - `lastAccepted` does not advance on a frame whose AEAD open failed, and the
     specification forbids it — the number is not authentic until it does. The comparison itself may run before
     the open, which only saves the open on a replay. Whether a frame that
     authenticates and is then refused by §7's post-open rules consumes its number
     is the receiver's choice: a conforming sender never reuses one either way.
3. **`MessageNum = 0`, and so the all-zero nonce, is never used.** No data
   message may take it; guaranteed by (2). The value stays reserved so that a
   counter reaching it (4) is unambiguously an error rather than a legal wrap, and
   so that no key at this layer ever authenticates under an all-zero nonce
   (transport §4.6).
4. **The counter does not wrap.** The specification has a sender that has used
   `2^64 - 1` refuse to send again on that key rather than advance: the next value is `0`, the
   nonce reserved by (3), and the values after it repeat counters this
   directional key has already consumed. Recovery is a new session — a fresh
   admission derives fresh directional keys (transport §4.5) and restarts both
   counters — never a retry on the same one. This is unreachable in practice and cheap to enforce;
   an implementation that omits the check silently degrades to nonce reuse at
   the one point where it is catastrophic.

Using `MessageNum = 0` for data would repeat a `(key, nonce)` pair under a
directional key and break the AEAD (keystream reuse → forgery).

## 7. Header validation

Every data message is AEAD-sealed (§5); there is no plaintext framing mode at
all. Reject a message when:

- `Size > 16 MiB` (`MaxPayloadSize`), or `OriginalSize > 64 MiB`
  (`MaxOriginalSize`).
- `Size < 16` (minimum encrypted payload — the tag alone).
- `FlagCompressed` set but `OriginalSize == 0`.
- Uncompressed and the **decrypted** plaintext length is neither `OriginalSize`
  nor its padding size class (`spec/message-layer.md` 6.2). The class is a
  function of `OriginalSize` alone; no ceiling of either peer enters into it. A
  plaintext of the class length is padded: the receiver delivers its first
  `OriginalSize` bytes and does not inspect the rest.
- Compressed and the decompressed length `!=` `OriginalSize`. LZ4 block
  decoding reports how many bytes it produced; a block that yields fewer than
  `OriginalSize` has not satisfied the header, and dispatching the short result
  hands the application a truncated payload it has no way to detect.

The last two are checked *after* AEAD open, not from the header alone. For an
encrypted message the header cannot be fully validated before the payload is
read, because `Size` counts ciphertext plus the 16-byte tag while `OriginalSize`
counts plaintext. A receiver that validates only the header will accept frames a
conforming implementation rejects.

A failure from any of these rules is a **rejected frame**, not a desynchronised
one: the frame was consumed whole, so the stream stays aligned and the session
survives (§1.2). Only a rule applied *before* the payload is read — the size
bounds above, or a receiver's own tighter bound (§7.1) — leaves the stream
misaligned.

(An implementation may also carry the header-only form of the size rules for its
own pre-encryption checks, where `Size == OriginalSize` holds because neither
compression nor sealing has been applied yet. That is an internal step, not a
wire mode.)

### 7.1 Pre-read bounds (known limitation)

Three size limits meet here and they are different things. `MaxPayloadSize` and
`MaxOriginalSize` (§7) are this layer's protocol-wide ceilings. A sender's
`MAX_MSG_PAYLOAD` (transport §2) is what it will *emit*, and is far below them on
a small device. A **receiver's bound** is what it will *read*: any value up to
`MaxPayloadSize`, chosen by the receiver, applied to `Size` before the body is
read. A sender must stay within the receiver's bound as well as its own, and this
layer has no field that carries it — the layer above advertises it where a sender
needs to know.

Because the `Size`↔`OriginalSize` relationship is only checkable after
decryption, a receiver that allocates `Size` bytes before reading the payload
commits up to `MaxPayloadSize` (16 MiB) of memory on the strength of a 20-byte
header. A deployment that needs a
tighter bound has the receiver set its own bound, which is the lever
(`spec/message-layer.md` 7.3), and bounds the number of concurrent sessions.

A device takes the tighter bound; the bound, how the device advertises it, and
what a refusal does to the session are in `spec/application.md` (Section 3.6 and
`DEVICE_INFO`'s `envelope` field, Section 5.3).

**Where a receiver applies a rule decides which §1.2 row it lands in.** For
`Size` in 0..15 — below the AEAD tag, so no frame can be that short — a receiver
that checks *before* reading the body reports a desync and closes the session,
while one that has already consumed the body reports a survivable drop. Both are
self-consistent: each closes exactly when it left the stream misaligned. Neither
is a conformance failure, and a conforming sender never emits such a frame.

## 8. Replay

Two mechanisms, at two scopes:

- **Within a session**, the monotonic `MessageNum` rule of §6.2. Because KCP
  delivers in order and reliably, a single high-water counter per direction
  suffices — no sliding window.
- **Across sessions**, the freshness of `k_c2s`/`k_s2c`. They are derived from
  the transport's transcript, which binds both ephemeral X25519 public keys
  (transport §4.5), so every session's directional keys are new and a ciphertext
  captured under one cannot be opened under another.

Note that the envelope beneath this layer runs its own, independent replay window
over `seq_full` (transport §8.2). It protects the datagram; §6.2 protects the
message. Neither substitutes for the other, and an implementation needs both.

This is a PSK/LAN threat model. Certificate identity and 0-RTT are explicit
non-goals. There is no rekeying, so no forward-secrecy boundary inside a live
session (`spec/transport.md` 17.3).

## 9. XChaCha note for 12-byte-nonce AEAD libraries

XChaCha20-Poly1305 uses a 24-byte nonce. A library that only offers the IETF
12-byte-nonce ChaCha20-Poly1305 (e.g. a microcontroller's AEAD library) must derive the
XChaCha subkey manually:

1. `subkey = HChaCha20(key, nonce[0:16])`.
2. IETF 12-byte nonce = `0x00000000 || nonce[16:24]`.
3. Run ChaCha20-Poly1305 with `subkey` and the 12-byte nonce.

Every nonce at this layer has `nonce[16:24]` all zero (§5), so the IETF nonce is
always 12 zero bytes and uniqueness comes entirely from the subkey, which is a
function of `MessageNum`. This is why (6.2) and the no-wrap rule (6.4) are
required for confidentiality, not merely defensive. Libraries that
expose XChaCha directly (e.g. a general-purpose crypto library)
need no manual subkey step.

## 10. Golden vectors

The key schedule that produces the `k_c2s`/`k_s2c` this layer consumes is pinned
byte-for-byte by `spec/transport.md` Appendix A, not here.

The frame itself is pinned by `spec/message-layer.md` Appendix A: a plain frame,
an empty padded one, a padded one and a compressed one (decode only, because LZ4
compressors are not canonical and a conforming sender may emit a different block
for the same plaintext). The vectors are also published in
[`vectors/shieldnet-msglayer-vectors.json`](../vectors/shieldnet-msglayer-vectors.json),
generated by [`vectors/gen_msglayer_vectors.py`](../vectors/gen_msglayer_vectors.py)
independently of any implementation, with XChaCha20-Poly1305 built from
HChaCha20 as §9 describes.

Byte-exact vectors for *payloads* carried over this layer are in
`spec/application.md` Appendix A.
