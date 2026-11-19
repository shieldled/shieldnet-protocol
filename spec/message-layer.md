# ShieldNet Message Layer

| | |
| --- | --- |
| Document | Specification of the ShieldNet message layer: how messages are framed, sealed, compressed and padded inside a session |
| Protocol version | 1 |
| Status | Published |
| Copyright | © 2025-2026 BlackShield LDA. Apache License 2.0 |

## Abstract

This document specifies the ShieldNet message layer: the length-prefixed,
individually sealed messages that two parties exchange over the reliable byte
stream of an admitted ShieldNet session. It defines the message header, the
authenticated encryption of each message, the message counter that prevents
replay, optional compression and padding, and how a receiver must treat a message
it cannot accept.

## Status of this document

This is the authoritative specification of the ShieldNet message layer, version 1.
An implementation conforms by meeting the requirements of section 10. Where
this document and any implementation disagree, this document governs.

The design notes ([`../design/message-layer.md`](../design/message-layer.md),
and section 13 of [`../design/transport.md`](../design/transport.md) for
compression and padding) are informative.

---

## 1. Introduction

### 1.1 Scope

This document specifies what is carried on the KCP stream of a session
established by [SN-TRANSPORT]. It has no handshake and no state of its own
beyond two counters and, while a message is partly read, the buffer that holds
it and the timer that bounds it (section 8): it begins with the first message of
a session.

It does not assign meaning to messages. The application protocol above it — for
example [SLED] — defines message types and payloads.

> **Note** — KCP is a small protocol that gives reliable, ordered delivery over
> datagrams ([SN-TRANSPORT] section 13). To this layer it is a reliable, ordered
> byte stream in each direction.

### 1.2 Position

```
application protocol        message types and payloads
ShieldNet message layer     this document
KCP stream                  [SN-TRANSPORT], one ordered byte stream per direction
```

[SN-TRANSPORT] delivers two keys, `k_c2s` and `k_s2c`, and a reliable, ordered
byte stream in each direction. Its envelope has already authenticated every
datagram that contributed to the stream.

### 1.3 Roles

A **sender** emits messages in one direction and a **receiver** consumes them.
Each party is both, once per direction. Where direction matters, **client** and
**device** are the roles of [SN-TRANSPORT].

### 1.4 How it works

Read this first; the rest of the document makes it precise.

By the time this layer is involved, the hard part is done. The transport has
authenticated the two parties, agreed fresh keys, and provides a reliable,
ordered stream of bytes in each direction that nobody else can inject into.
What remains is to turn that stream of bytes back into separate messages, and to
protect each message on its own.

**Framing.** A stream has no boundaries, so each message starts with a 20-octet
header that says how long it is. A receiver reads 20 octets, learns the length,
reads that many more, and has one message.

```
 ┌───────────────── header: 20 octets, in clear ──────────────────┬───── Size octets ─────┐
 │ Size (4) │ OriginalSize (4) │ MessageType (4) │ MessageNum (8) │ ciphertext │ tag (16) │
 └──────────┴──────────────────┴─────────────────┴────────────────┴────────────┴──────────┘
   length of  length of the      what kind of      this message's
   what       real payload       message it is     number:
   follows                                         1, 2, 3, …
```

**Sealing.** The payload is encrypted and authenticated with XChaCha20-Poly1305
under the key for its direction. The header travels in clear, because the
receiver needs the length before it can decrypt anything, but it is covered by
the authentication tag: change one bit of it and the message is rejected.

**Numbering.** Every message carries a number that only ever goes up, starting
at 1. The encryption nonce is derived from the number, so the number has two
jobs: a receiver drops any message whose number is not higher than the last it
accepted, which stops replay, and no two messages are ever encrypted under the
same nonce.

**Size.** Two optional transformations change how long a message is on the wire.
*Compression* (LZ4) makes large payloads smaller. *Padding* rounds a payload up
to one of an open-ended ladder of sizes, so that an observer learns only which
size it was rounded to and not its exact length. They pull in opposite
directions and are never combined; section 6 says which kinds of message may use
which.

**When something is wrong.** There is no marker in the stream to resynchronise
on. If a message is read completely and then turns out to be bad, the receiver
is still at a message boundary: it drops that message and carries on. If the
receiver loses its place *within* a message, every byte after that would be
misread, and the only safe course is to end the session. Section 8 draws that
line exactly, because getting it wrong either kills healthy sessions or lets a
broken one limp on.

---

## 2. Conventions and terminology

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in [RFC2119] and
[RFC8174] when, and only when, they appear in capitals. Text in a block beginning
**Why** or **Note** is explanation, not requirement; so is every picture (a diagram drawn with lines, boxes or arrows), section 1.4,
and every appendix headed "(informative)". The layouts (tables and `||`
expressions), the formulas and the definitions are normative even where they use
no key word. Elsewhere a sentence is a requirement where it uses
a key word in capitals, wherever in a section it appears.

All multi-octet integers are **big-endian**. `a || b` is concatenation.

- **Message**: one header followed by one sealed payload.
- **Plaintext**: the application's payload, before compression or padding.
- **Body**: what is encrypted — the plaintext, or its compressed form, or the
  plaintext followed by padding.
- **Size class**: section 6.2.

> **Note** — terms used before their definition. The *sealed payload* is the body
> after encryption: ciphertext followed by the 16-octet tag (section 4.2). A
> *category* is one of the three classes of message in section 6.3, to one of
> which the application protocol assigns each of its message types. The *primary*
> is [SN-TRANSPORT]'s term for the session a device currently serves.

---

## 3. Stream and keys

What this layer is given by the transport, and what it requires of it.

### 3.1 Stream mode

KCP MUST operate in stream mode on both parties. In stream mode KCP delivers one
continuous byte stream, with no boundary between one write and the next. A
message may span any number of KCP segments, a segment may carry parts of more
than one message, and a receiver MUST NOT assume that a read returns a whole
message.

> **Why stream mode.** KCP's message mode reassembles a message from its
> fragments only when all of them are held, so a message larger than the receive
> window could never be delivered. Stream mode has no such limit, and this layer
> finds its own message boundaries from `Size`.

### 3.2 Keys and direction

| Direction | Key |
| --- | --- |
| client to device | `k_c2s` |
| device to client | `k_s2c` |

Each direction has its own key and its own `MessageNum` counter. The keys are
derived by [SN-TRANSPORT] and are new for every session.

### 3.3 The first message

The first message begins in the first KCP PUSH (`sn = 0`), whose datagram
promotes the session ([SN-TRANSPORT] sections 10.2 and 12.2, "Taking control"
and "Promotion"); it may span several datagrams. It is an ordinary message of
this layer and carries `MessageNum` 1.

---

## 4. Message format

The layout of one message, how it is encrypted, and the steps a sender and a
receiver follow.

### 4.1 Header

A message is a 20-octet header followed by `Size` octets of sealed payload.

| Offset | Field | Length | Meaning |
| ---: | --- | ---: | --- |
| 0 | `Size` | 4 | length of the sealed payload: body plus 16-octet tag |
| 4 | `OriginalSize` | 4 | length of the plaintext |
| 8 | `MessageType` | 4 | bit 31: `FlagCompressed`. Bits 0-30: the application's |
| 12 | `MessageNum` | 8 | this direction's message counter |

`FlagCompressed` is `0x80000000`.

Bits 0-30 of `MessageType` belong to the application protocol. This layer
authenticates them and delivers them unchanged. It MUST NOT interpret or reject
any value of them.

### 4.2 Sealing

The AEAD is XChaCha20-Poly1305 [XCHACHA]: a 32-octet key, a 24-octet nonce and a
16-octet tag.

```
nonce          = 00 x 8 || MessageNum (8 octets) || 00 x 8
sealed payload = XChaCha20-Poly1305(key, nonce, aad = header, plaintext = body)
               = ciphertext || tag
```

The additional authenticated data is the complete 20-octet header exactly as
transmitted. The nonce is not transmitted.

There is no unencrypted form of a message.

> **Note** — in the formula above `plaintext` is the input of the AEAD, which is the
> message's body. It is not the term Plaintext of section 2, the application's
> payload before compression or padding.

> **Note (informative).** XChaCha20-Poly1305 derives a subkey with HChaCha20 from
> the key and the first 16 octets of the nonce, then runs ChaCha20-Poly1305
> [RFC8439] with that subkey and a 12-octet nonce made of four zero octets and
> the last 8 octets of the 24-octet nonce. Here those last 8 octets are always
> zero, so every message is sealed under a 12-octet zero nonce and a subkey that
> depends on `MessageNum`. Uniqueness therefore rests entirely on section 5.

> **Note** — the nonce of section 4.2 drawn as a picture, with the 24 octets going
> where the previous note says.
>
> ```
> nonce, 24 octets    00 x 8          MessageNum (8)       00 x 8
>                     └──────── first 16 octets ────────┘  └ last 8 octets ┘
>                               │                               │
>  key (32 octets) ───► HChaCha20                      4 zero octets || those 8
>                               │                               │
>                     subkey (32 octets)               12-octet nonce
>                               └──────► ChaCha20-Poly1305 ◄────┘
> ```
>
> For vector A.3 (`MessageNum` 2) and the key `a0 a1 a2 … bf`, the subkey is
> `516108bde74de01334878627917a1755dc2dfcd06f72fb0829897a9b8e4b6920`.

### 4.3 Sending

A sender MUST:

1. Choose the body (section 6): the plaintext; or its compressed form, with
   `FlagCompressed` set; or the plaintext followed by zero octets up to its size
   class. A body is never both compressed and padded.
2. Set `OriginalSize` to the plaintext length, `Size` to the body length plus 16,
   and `MessageNum` to the next counter value (section 5).
3. Seal the body as in section 4.2 and write the header followed by the sealed
   payload.

The layer reports the `MessageNum` it assigned to the caller.

### 4.4 Receiving

A receiver MUST:

1. Read the 20-octet header and apply the checks of section 7.1.
2. Read `Size` octets.
3. Apply the counter rule of section 5.2. This step MAY instead follow step 4.
4. Open the sealed payload with the nonce derived from `MessageNum` and the
   header as additional authenticated data.
5. Apply the checks of section 7.2, and deliver `MessageType` with bit 31 cleared,
   `MessageNum` and the plaintext.

The transport authenticates every datagram, so a message that fails to open can
only come from a peer defect (wrong keys or a wrong counter), not from an
attacker or from the network. The receiver discards the message (section 8); the
application notices only if it expects a reply.

> **Note** — the receive steps drawn as a picture, with the outcome of section 8 at
> each point.
>
> ```
>  1  read 20 octets                  fewer than 20 held: NO PROGRESS, retain them
>     7.1 header checks ── fail ───►  PARTIAL MESSAGE (a receiver that has already
>         │ pass                      read the payload can reject instead)
>         ▼
>  2  read Size octets                fewer than Size held: NO PROGRESS, retain
>     under the time bound            the time bound expires: PARTIAL MESSAGE
>         │
>         ▼
>  3  5.2 counter check ── fail ───►  MESSAGE REJECTED
>     (this check can also follow step 4, as 4.4 allows)
>         │ pass
>         ▼
>  4  open the AEAD ────── fail ───►  MESSAGE REJECTED
>         │ opens
>         ▼
>  5  7.2 checks ───────── fail ───►  MESSAGE REJECTED
>         │ pass
>         ▼
>     advance the counter; deliver type (bit 31 cleared), number and plaintext
> ```

---

## 5. Message counter

`MessageNum` — one counter per direction — is the only protocol state this layer
keeps from one message to the next; a partly-read message and the timer that
bounds it (section 8) are held only while the message is being read. The counter
is the nonce for encryption and the defence against replay, so its rules are
short and none of them is optional.

### 5.1 Sender

1. The first message in each direction of a session has `MessageNum` 1.
2. Each later message MUST have a strictly greater `MessageNum`. The values need
   not be consecutive: a number assigned to a message that is then not sent is
   not reused.
3. `MessageNum` 0 MUST NOT be used. The receiver's last accepted value starts at
   0, so the first message must exceed it, and 0 would give the all-zero nonce.
4. A sender that has used `2^64 - 1` MUST NOT send again under that key. The only
   recovery is a new session.

### 5.2 Receiver

A receiver keeps, per direction, the last accepted `MessageNum`, initially 0.

1. A message whose `MessageNum` is 0, or not greater than the last accepted, MUST
   be rejected (section 8, "message rejected").
2. Gaps are not an error.
3. The last accepted value advances to the `MessageNum` of each message that is
   delivered. It MUST NOT advance on a message whose AEAD did not open. Whether
   it advances on a message that opens and is then rejected under section 7.2 is
   the receiver's choice; a conforming sender never reuses a number either way.

> **Note** — the "last accepted" value of this section is the `MessageNum` of the
> last message delivered (item 3), except in the one case item 3 leaves to the
> receiver.

> **Note (informative).** A single counter suffices because the stream is
> reliable and ordered. This protects messages within a session; fresh keys
> protect across sessions; and the transport's own replay window protects
> datagrams. None of the three replaces another.

---

## 6. Compression and padding

Both change the length of a message on the wire, for opposite reasons.
Compression saves bandwidth, and leaks something about the content through the
resulting length. Padding hides the length, and costs bandwidth. Which is right
depends on what the message is, so the rule is stated per category of message.

### 6.1 Compression

A compressed body is the plaintext in LZ4 block format [LZ4]. `OriginalSize` is
the decompressed length.

A compressed body is exactly one LZ4 block. A sender MUST NOT send a compressed
body that is not shorter than the plaintext; it sends the plaintext instead. A
sender MUST produce blocks that satisfy the LZ4 block format's end-of-block
rules; a receiver MAY reject a block that violates them.

A receiver MUST accept a compressed message whatever its type — the category is
the sender's obligation — and MUST reject one whose body is not consumed in full
by decoding, or does not decode to exactly `OriginalSize` octets.

### 6.2 Padding

Padding rounds a payload up to one of an open-ended ladder of sizes. An observer
then learns only which size a message was rounded to, not its exact length. Small
control messages mostly share the smallest size, so for them an observer learns
only that its plaintext was 64 octets or shorter.

| Plaintext length | Size class | `Size` on the wire |
| ---: | ---: | ---: |
| 0 to 64 | 64 | 80 |
| 65 to 128 | 128 | 144 |
| 129 to 256 | 256 | 272 |
| 257 to 512 | 512 | 528 |
| … | each next power of two | class + 16 |

The **size classes** are the powers of two from 64 upward. The size class of a
plaintext is the smallest class not less than its length; a plaintext of 0 to 64
octets has class 64.

A padded body is the plaintext followed by zero octets up to its size class.

1. A sender pads only to classes it can send: the class plus 16 MUST NOT exceed
   its own `MAX_MSG_PAYLOAD` or, where it knows it, the receiver's bound
   (section 7.3; while that bound is unknown and the application protocol
   defines a minimum, that minimum). A sender MAY use a lower largest class.
2. A plaintext above that largest class MUST be sent **unpadded**, if it fits
   those bounds at all; it MUST NOT be refused for lack of a class.
3. A receiver MUST accept an uncompressed body whose length is either
   `OriginalSize` or the size class of `OriginalSize`, of any size class within
   the receiver's bound, and
   deliver its first `OriginalSize` octets. It MUST NOT depend on the content of
   the padding.
4. A message MUST NOT be both compressed and padded. A sender MUST NOT set
   `FlagCompressed` on a padded body.

> **Note (informative).** The header has two length fields. A padded, compressed
> message would need three.

### 6.3 Categories

The application protocol assigns each of its message types to one category and
is bound by it.

| Category | What it is | Compression | Padding |
| --- | --- | --- | --- |
| Control and configuration | a command, its parameters, a query, a response | MUST NOT | SHOULD |
| Bulk content | one self-contained object transferred whole | MAY | SHOULD when not compressed |
| Streaming data | the high-rate data plane | MAY | MUST NOT |

A deployment for which the size of a bulk object is itself sensitive SHOULD send
that object uncompressed and padded when it fits the largest class.

> **Why bulk content differs from control messages.** The length attack that forbids
> compressing control messages needs attacker-chosen data compressed together with
> a secret; a bulk object is one object sent whole, with nothing secret mixed in.
> What compression still reveals is which object was sent, by its size, and the
> recommendation above lets a deployment reduce that to the size class.

> **Note (informative).** Compression before encryption exposes redundancy in the
> plaintext through the ciphertext length. For control messages, whose length
> would then depend on a parameter value, that is not acceptable. Padding hides
> which control message was sent, at the cost of revealing its size class.

---

## 7. Validation and limits

What a receiver checks, and when. The split between "before the payload is read"
and "after it is decrypted" matters: it decides whether a bad message costs one
message or the whole session (section 8).

### 7.1 Before the payload is read

A receiver MUST treat the stream as unrecoverable (section 8, "partial message")
if a header has:

- `Size` less than 16;
- `Size` greater than `MaxPayloadSize`, 16 MiB (16 777 216), or greater than the
  receiver's own bound (section 7.3);
- `OriginalSize` greater than `MaxOriginalSize`, 64 MiB (67 108 864).

A receiver that has already read the payload when it makes one of these checks
MAY instead reject the message (section 8, "message rejected"), since it is then
still on a message boundary.

> **Note** — `MaxPayloadSize` and `MaxOriginalSize` are the protocol's ceilings on
> `Size` and `OriginalSize`; section 7.3 distinguishes them from the other limits.

### 7.2 After the AEAD opens

A receiver MUST reject the message if:

- `FlagCompressed` is set and `OriginalSize` is 0;
- `FlagCompressed` is set and the body fails the decoding rule of section 6.1;
- `FlagCompressed` is clear and the body length is neither `OriginalSize` nor the
  size class of `OriginalSize`.

A receiver MAY also reject a compressed message whose `OriginalSize` exceeds its
bound minus 16.

### 7.3 Size limits

Four limits apply and they are distinct.

- **`MaxPayloadSize` and `MaxOriginalSize`** are the protocol's ceilings on
  `Size` and `OriginalSize`.
- **`MAX_MSG_PAYLOAD`** is a sender's own limit on the `Size` it emits. A message
  — its 20-octet header and `MAX_MSG_PAYLOAD` octets — MUST fit the sender's
  empty send queue, where the sender bounds one ([SN-TRANSPORT],
  `SEND_QUEUE_MAX`), measured as the implementation enforces that bound
  ([SN-TRANSPORT] section 12.5 item 3); a message that cannot fit an empty queue
  could never be written.
- **A receiver's bound** is the largest `Size` it will read, any value up to
  `MaxPayloadSize`. It is applied to the header before the payload is read.

A sender MUST respect the receiver's bound as well as its own. This layer does
not carry the receiver's bound; an application protocol whose senders need the
receiver's bound MUST provide a way to learn it and a minimum for each direction
where it applies (the ShieldLED Device Protocol [SLED] sets the device's minimum
to a `Size` of 80 and limits the first command to the smallest class). A sender
MUST NOT send a compressed message whose `OriginalSize` exceeds the receiver's
bound minus 16, where it knows that bound.

---

## 8. Outcomes of a read

A receiver reading a stream can end up in one of three places, and they call for
three different responses. The picture:

```
   nothing consumed yet,          a whole message consumed,       part of a message
   or everything consumed         then found to be bad            consumed and lost
   is still held
          │                               │                               │
          ▼                               ▼                               ▼
     NO PROGRESS                   MESSAGE REJECTED                PARTIAL MESSAGE
   try again later               drop it, keep reading              end the session
```

> **Why "message rejected" must not end the session.** A session costs a full
> admission to replace. One bad message from a peer that is otherwise working is
> not a reason to throw that away, and the receiver has consumed a whole message,
> so as far as it can tell it is at the start of the next one. (The note at the
> end of this section says what happens if it is not.)

There is no resynchronisation marker in the stream. A receiver MUST distinguish
three outcomes of an attempt to read a message, and MUST NOT report them as one.

| Outcome | Condition | Required behaviour |
| --- | --- | --- |
| **No progress** | nothing of a message was consumed, or what was consumed is retained and the read will continue from it | The session continues. This is the normal result of a read that times out. |
| **Message rejected** | a whole message was consumed and then refused: section 5.2, an AEAD failure, or section 7.2 | The message is dropped. The session MUST continue and reading MUST continue. |
| **Partial message** | part of a message was consumed and cannot be completed: section 7.1, or the stream ended or timed out while a message was partly read | The session MUST be ended. |

1. A receiver that retains a partly-read message across reads has made no
   irrecoverable progress, and a read deadline of its own expiring mid-message is
   "no progress". A receiver that does not retain it MUST report "partial
   message".
2. A receiver MUST bound the time for which a message may remain partly read, and
   MUST treat expiry as "partial message". The bound SHOULD be no shorter than
   `SESSION_DEAD_MS` ([SN-TRANSPORT] section 4.1); a shorter bound ends healthy
   sessions during a transient outage.
3. Ending a session at this layer MUST leave the party able to be admitted, or
   to admit, again. On a device this releases the primary ([SN-TRANSPORT]
   section 12.5, "No idle timeout; bounded send path").

> **Note (informative).** After an AEAD failure the receiver assumes it is still
> on a message boundary, but the `Size` that located the boundary was
> authenticated only by the open that failed. If it was wrong, the next header
> either fails section 7.1 or declares a payload that never arrives; item 2 turns
> the second case into an ended session instead of a hung one.

---

## 9. Security considerations

- **Nonce uniqueness** is the whole of this layer's cryptographic safety, and it
  rests on section 5.1: a repeated `MessageNum` under one key reveals the
  keystream and permits forgery. Items 2, 3 and 4 of that section are not optional
  hardening.
- **Message type and lengths are authenticated** — they are in the header, and
  the header is the additional authenticated data — but only once the AEAD has
  opened. A receiver MUST NOT act on anything in a header before that, except the
  size checks of section 7.1 and the counter comparison of section 5.2, which can
  only reject.
- **Memory.** A receiver that allocates `Size` octets on the strength of a header
  commits up to its bound before authenticating anything. The stream is reachable
  only by the authenticated peer, but a receiver SHOULD choose a bound that
  reflects what it expects to receive. The same holds for the `OriginalSize` of a
  compressed message, which a receiver MAY reject above its bound minus 16
  (section 7.2) before decompressing.
- **Compression** leaks plaintext redundancy through length, and **padding
  classes** leak the class. Section 6.3 states where each is permitted.
- **Traffic shape.** Message sizes and timing remain visible through the
  transport. Streaming data is unpadded, and its size is visible.
- Authentication of the peer, forward secrecy and replay across sessions are
  provided by [SN-TRANSPORT], not here.

---

## 10. Conformance

A conforming implementation, in each direction it uses:

**As a sender** — formats and seals messages as in section 4; assigns
`MessageNum` as in section 5.1; never emits a message that is both compressed and
padded, or a compressed body that is not shorter than its plaintext (section
6.1); pads only to size classes as in section 6.2 and sends a plaintext above its
largest class unpadded; observes the category of
each message type (section 6.3); respects its own and the receiver's size limits
(section 7.3).

**As a receiver** — implements section 4.4; enforces section 5.2;
accepts compressed messages and padded messages of any size class within the
receiver's bound; applies sections 7.1 and 7.2; distinguishes the three outcomes
of section 8, retains or reports a partly-read message as in item 1, bounds its
time as in item 2 and leaves the party able to be admitted as in item 3.

Both — operate KCP in stream mode (section 3.1). Senders reproduce A.1–A.3;
receivers decode A.1–A.4.

---

## 11. References

### 11.1 Normative

- **[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119.
- **[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key
  Words", BCP 14, RFC 8174.
- **[RFC8439]** Nir, Y., Langley, A., "ChaCha20 and Poly1305 for IETF Protocols",
  RFC 8439.
- **[XCHACHA]** Arciszewski, S., "XChaCha: eXtended-nonce ChaCha and
  AEAD_XChaCha20_Poly1305", draft-irtf-cfrg-xchacha-03.
- **[LZ4]** Collet, Y., "LZ4 Block Format Description",
  <https://github.com/lz4/lz4/blob/v1.10.0/doc/lz4_Block_format.md>.
- **[SN-TRANSPORT]** "ShieldNet Transport Protocol", [`transport.md`](transport.md).

### 11.2 Informative

- **[SLED]** "ShieldLED Device Protocol", [`application.md`](application.md).
- **[DESIGN]** "ShieldNet message layer" (design notes),
  [`../design/message-layer.md`](../design/message-layer.md).

---

## Appendix A. Test vectors

The vectors are published with this specification in
[`../vectors/shieldnet-msglayer-vectors.json`](../vectors/shieldnet-msglayer-vectors.json),
produced by [`../vectors/gen_msglayer_vectors.py`](../vectors/gen_msglayer_vectors.py)
from an implementation independent of any ShieldNet implementation. They are
reproduced here.

All four use the 32-octet key `a0 a1 a2 … bf` (octet `i` is `0xA0 + i`). Each
message is shown whole: the 20-octet header, then ciphertext and tag.

Each vector starts with a fresh receiver. In the JSON, `message_type` is the full
32 bits including bit 31; `message_num` is the counter; `nonce` is the 24-octet
nonce; `plaintext` is the application's payload; `sealed_body` is the body before
sealing (the plaintext, the padded plaintext or the LZ4 block); `header_aad` is
the 20-octet header; and `frame` is the header followed by the sealed payload.

### A.1 Plain

`MessageType` `0x00112233`, `MessageNum` `0x0102030405060708`. Plaintext: the 45
ASCII octets `shieldnet message layer golden vector payload`. Neither compressed
nor padded. `Size` 61, `OriginalSize` 45; 81 octets.

```
0000003d0000002d0011223301020304050607087b58b84f53d0efa1f5de1ad8d89965f8e607b3bb04709fe4a6db66913eeef71645a73ed824426e970c6f0328036f481744c2ef6db7ecf447dfc9de0bc8
```

> **Note** — `MessageType` `0x00112233` has bits set above the low byte. Bits 0-30
> belong to the application protocol, and this layer delivers them unchanged
> (section 4.1).

### A.2 Padded, empty plaintext

`MessageType` `0x00000007`, `MessageNum` 1. Empty plaintext, padded to class 64.
`Size` 80, `OriginalSize` 0; 100 octets.

```
0000005000000000000000070000000000000001773071f1efdbefcc1c9913f021189b9c8e3bd104005f6adc780fbe5597954067b37fb8a4fde146ec150354b6c90e5c842044533f85d8a4981794373c0de7eebc15a8e770e299fb7e1ac7d5304da13da0
```

### A.3 Padded

`MessageType` `0x00000060` (application type `0x60`, private use), `MessageNum` 2. The 45-octet plaintext of A.1
followed by 19 zero octets (class 64). `Size` 80, `OriginalSize` 45; 100 octets.

```
000000500000002d000000600000000000000002b89477c02f655b035beafb9750f331b283d54b4fd07f89f67135cf72158cd5ba385b2a5e47d6c64d6c595ea718457a301d6632f3c4275f5d9aa34589cfaec4a50e27845b70c964597fe4de7182900a7b
```

### A.4 Compressed (for receivers)

`MessageType` `0x80000000`, `MessageNum` 3. The body is the 42-octet LZ4 block
`f0 19` followed by forty octets `0x41`, which decompresses to forty octets
`0x41`. `Size` 58, `OriginalSize` 40; 78 octets.

```
0000003a00000028800000000000000000000003e92a24e604a775126bc505b54045435dc308e96f5cdad81eb08a5bbb8910dd2c2c8f9f0bf60ec10645f7d461e3c53cd0913689da3d7d31380b3b
```

A receiver MUST accept this message and deliver the forty octets. It is a vector
for receivers only: LZ4 encoders differ, and a conforming sender would not send
this block, which is not shorter than its plaintext (section 6.1).

> **Note** — decoding A.4. The token `f0` has 15 in its high nibble, the literal
> length, which the next octet extends: `0x19` is 25, so there are 15 + 25 = 40
> literal octets, and no match follows them. `MessageType` `0x80000000` is
> application type 0 with `FlagCompressed` (bit 31) set.

## Appendix B. A worked message (informative)

One message taken apart, using vector A.3: a 45-octet payload, padded.

The sender has a 45-octet payload, the ASCII text
`shieldnet message layer golden vector payload`, of application type `0x60` (private use), and
this is the second message it has sent in this direction.

1. **Pad.** The smallest size class that holds 45 octets is 64, so the body is
   the 45 octets followed by 19 zero octets: 64 octets.
2. **Header.** `Size` is the body plus the 16-octet tag, 80. `OriginalSize` is
   the real length, 45. `MessageNum` is 2.

   ```
   00000050            Size          = 80
   0000002d            OriginalSize  = 45
   00000060            MessageType   = 0x60, not compressed
   0000000000000002    MessageNum    = 2
   ```
3. **Nonce.** Eight zero octets, the eight octets of `MessageNum`, eight zero
   octets:

   ```
   0000000000000000 0000000000000002 0000000000000000
   ```
4. **Seal.** XChaCha20-Poly1305 under the direction's key ([SN-TRANSPORT]
   section 6.3: `k_c2s` or `k_s2c`; in this vector it is the vector key
   `a0 a1 a2 … bf`, not a derived key), with that nonce, the 20 header octets as
   additional data and the 64-octet body as plaintext. Inside the AEAD the key
   and the first 16 octets of the nonce give the subkey
   `516108bde74de01334878627917a1755dc2dfcd06f72fb0829897a9b8e4b6920`. The result
   is 64 octets of ciphertext and a 16-octet tag:

   ```
   ciphertext  b89477c02f655b035beafb9750f331b283d54b4fd07f89f67135cf72158cd5ba385b2a5e47d6c64d6c595ea718457a301d6632f3c4275f5d9aa34589cfaec4a5
   tag         0e27845b70c964597fe4de7182900a7b
   ```
5. **Send** the header and then those 80 octets: 100 octets on the stream.

The receiver reads 20 octets and sees `Size` 80, which is within its limits. It
reads 80 more. `MessageNum` 2 is higher than the last it accepted, so it rebuilds
the nonce and opens the payload, with the header it just read as additional
data. It gets 64 octets. The message is not compressed, 64 is the size class of
45, so it is a padded message: the receiver delivers the first 45 octets with
type `0x60`, and records 2 as the last number accepted.

Had the tag not verified, the receiver would have dropped these 100 octets and
read the next header, exactly 100 octets further on. Had the header said `Size`
is 3 — less than a tag — or 3 gigabytes, the receiver would have ended the
session without reading further: no valid message has such a header, so
whatever it is reading is not the stream it expects.
