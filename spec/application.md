# ShieldLED Device Protocol

| | |
| --- | --- |
| Document | Specification of the ShieldLED Device Protocol: the commands and responses between a controller and a device, pixel frames and their timing, device description and discovery |
| Protocol version | 1 |
| Status | Published |
| Copyright | © 2025-2026 BlackShield LDA. Apache License 2.0 |

## Abstract

The ShieldLED Device Protocol is the application protocol spoken between a
controller and a ShieldLED device. It defines the commands a controller sends,
the responses a device returns, the pixel-frame data plane with its optional
scheduled presentation, the device's self-description, and the rules that let
either side be extended without breaking the other. It has a **core**, which
every implementation provides, and an optional **program extension**, defined by
BlackShield and specified separately; this document reserves its values
(Section 9). It is carried as messages of the ShieldNet message layer [SN-MSG]
inside a session established by the ShieldNet transport [SN-TRANSPORT].

## Status of this document

This is the authoritative specification of the ShieldLED Device Protocol. Where
it and any implementation, or the design notes, disagree, this document governs.

The design rationale behind these rules is kept in
[`../design/application.md`](../design/application.md). That document is
informative: it explains why, and nothing in it adds to or overrides a
requirement stated here.

---

## 1. Introduction

### 1.1 Scope

This document specifies:

- the command and response kinds, and the byte layout of every payload;
- request/response correlation;
- the pixel-frame payload and the frame timing rules;
- the device's self-description (`DEVICE_INFO`) and capability advertisement;
- the forward-compatibility rules both peers MUST follow;
- the discovery record a device advertises;
- the values reserved for the optional program extension (Section 9).
  Sections 3 to 8 are the core and stand without it.

It does not specify:

- session establishment, keys, authentication or datagram protection, which are
  [SN-TRANSPORT];
- message framing, sealing, compression and padding mechanics, which are
  [SN-MSG];
- how a device finds a time server when no controller names one.

### 1.2 Layering

From the wire up: UDP; the ShieldNet transport (admission and the authenticated
envelope around every KCP datagram) [SN-TRANSPORT]; a reliable ordered byte
stream; ShieldNet messages [SN-MSG]; this protocol.

Each application message of this protocol is exactly one message of [SN-MSG].
This protocol reads that message's `MessageType` and `MessageNum` fields and its
payload, and constrains its size (Section 3.6).

### 1.3 Roles

- **Controller** — the transport client. It sends commands and receives
  responses.
- **Device** — the transport device. It receives commands and sends responses.

"Sender" and "receiver" refer to one message and apply to either role.

### 1.4 Core protocol and the program extension

This document has two parts.

The **core** — Sections 3 to 8 — is what every conforming controller and every
conforming device implements: the command framework, output control, status, the
device's self-description, the extensibility rules and discovery. Within the
core, **pixel output** (Section 6) is OPTIONAL for a device: not every device
drives LEDs — some drive other things, such as animatronics.

- A device accepts pixel frames if and only if it advertises the `pixel`
  capability (Section 5.3). A device that does not MUST discard a `PIXEL_FRAME`
  without response and count it in `dropped` (Section 5.2).
- A controller MUST NOT send a `PIXEL_FRAME` to a device that does not advertise
  `pixel`.
- A controller that sends pixel frames implements Section 6. One that never does
  need not.
- A device MAY advertise `pixel` or not. Without it, it is still reachable for
  status and output control.

The **program extension** is OPTIONAL. It is defined by BlackShield and
specified separately; this document reserves its values (Section 9), mode 0
among them.

- A device implements the program extension if and only if it advertises the
  `vm` capability.
- A device that does not implement it MUST answer every command kind reserved
  for it with `ERR_UNKNOWN_KIND` (Section 7.1) and does not have mode 0; if it
  advertises `pixel`, pixel frames drive its output while it is in `PIXEL` mode
  and no automatic pixel source owns the output (Section 6.1).
- A controller MUST NOT send a command kind reserved for it to a device that
  does not advertise `vm`.
- A controller that does not implement the extension MUST skip its response
  kinds (Section 7.2).
- The values Section 9 reserves (command kinds, response kinds, ACK status
  codes, `DEVICE_INFO` names, mode 0 and the `STATUS` extension block) MUST NOT
  be reused for anything else, by a device or a controller that does not
  implement the extension.

Section 10 lists every assigned value and says which part each belongs to.

### 1.5 How a controller drives a device

Read this section first. It follows one session from beginning to end in plain
terms; the rest of the document makes each step precise.

**Finding the device.** A device announces itself on the local network with a
multicast DNS record giving its address, its model and a list of what it can do.
Nothing authenticates that record, so a controller uses it for one purpose only:
deciding what to dial (Section 8).

**Getting in.** The controller is admitted by the ShieldNet transport, which
authenticates it and sets up an encrypted, reliable stream in each direction.
The transport completes admission on the controller's first message, so the
first command of the session travels with the admission itself (Section 3.4).

**Asking the device what it is.** That first command is normally
`GET_DEVICE_INFO`. The answer, `DEVICE_INFO`, is a short list of name/value
pairs: how many strips the device drives, how many LEDs are on each, how large a
message it can receive, and which optional features it has (Section 5.3). A
controller reads it before it sends a single pixel, because the two numbers that
bound a frame — the geometry and the receive limit — exist nowhere else that can
be trusted, and a message larger than the device can receive does not lose one
frame: it ends the session.

**Commands and their replies.** Most commands are answered. The device sends
back an `ACK` saying whether the command was accepted, and for a query it sends
the data first and the `ACK` after it. Each `ACK` names the number of the
message it answers, and the controller matches replies to commands by that
number, never by the order in which they arrive: a device may send a message
nobody asked for, and a reply to an earlier command may still be in the stream
(Section 3.3).

**Pixels.** The data plane is one command, `PIXEL_FRAME`, and it is never
answered: frames arrive many times a second and a reply to each would double the
traffic for nothing. A frame carries its pixels at four bytes each — red, green,
blue, white — in the physical order of the LEDs, the first strip from its first
LED to its last, then the second strip, and so on. A frame may be shorter than
the display; the LEDs it does not reach keep what the last frame to reach them
set (Section 6.1).

**Many devices, one picture.** A large display is several devices, and they have
to change image at the same instant. No clock travels in this protocol. Each
device and the controller keep time with NTP, and every frame carries two
timestamps: the instant before which it is not to be shown and the instant after
which it is too late to show it (Sections 6.3 and 6.4). A device that supports
this says so with the `pts` capability.

**When one side does not understand the other.** There is no version number to
negotiate. A fixed set of rules says what a receiver does with anything it does
not recognise: an unknown command is refused with a specific status, an unknown
reply is skipped, extra bytes at the end of a fixed-layout payload are ignored,
reserved fields are sent as zero and never examined, and an unknown value is
never guessed at (Section 7). A newer controller and an older device, or the
reverse, therefore keep working, each using what the other understands.

**Extensions.** An optional program extension is specified separately;
Section 9 reserves its values and says what a party without it does.

**Not every device has pixels.** Pixel output is optional; Section 1.4 says which
devices accept frames and which controllers send them.

```
 controller                                      device
 │   (discovery record: a hint, not trusted)    │
 │── admission, carrying GET_DEVICE_INFO ──────►│  [SN-TRANSPORT]
 │◄────────────────────────────── DEVICE_INFO ──│  geometry, limits, capabilities
 │◄───────────────────────────────── ACK (OK) ──│
 │                                              │
 │── SET_FPS 30 ───────────────────────────────►│
 │◄───────────────────────────────── ACK (OK) ──│
 │                                              │
 │── PIXEL_FRAME ──────────────────────────────►│  no reply
 │── PIXEL_FRAME ──────────────────────────────►│  no reply
 │── PIXEL_FRAME ──────────────────────────────►│  no reply
 │                                              │
 │── GET_STATUS ───────────────────────────────►│
 │◄─────────────────────────────────── STATUS ──│  counters, mode, output state
 │◄───────────────────────────────── ACK (OK) ──│
```

### 1.6 How to read this document

- **To understand the protocol**, read Section 1.5, then Section 3 (how commands
  and replies fit together), Section 6 (pixels and their timing) and Section 7
  (what happens to the unknown). Appendix B takes a short session apart byte by
  byte.
- **To implement a controller or a device**, work through Sections 3 to 8 in
  order. Each opens by saying what it is for, then states the rules. Section 11
  lists what each role has to implement, and Appendix A gives the vectors that
  show when an encoder or a decoder is right.
- **Rules and reasons.** Requirements use the capitalised key words of
  Section 2.1. A paragraph beginning **Why** or **Note** explains a rule; it is
  there so that the rule is not "simplified" away, and it adds no requirement of
  its own.
- **Looking something up.** Section 10 has every assigned number and name in one
  place.

---

## 2. Conventions and terminology

### 2.1 Requirement keywords

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, NOT RECOMMENDED, MAY and OPTIONAL are to be interpreted as described
in [RFC2119] and [RFC8174] when, and only when, they appear in capitals.

Text in a block beginning **Why** or **Note** is explanation, not requirement.
So are the pictures of message flows and layouts, Section 1.5, and every section
or appendix headed "(informative)" or "worked". Elsewhere a sentence is a
requirement where it uses a key word in capitals, wherever in a section it
appears; where an explanation and a requirement appear to differ, the
requirement governs.

### 2.2 Notation

- All multi-byte integers are **big-endian**.
- `u8`, `u16`, `be16`, `be32`, `be64` are unsigned integers of that width;
  `u16` and `be16` are the same encoding. "signed" marks a two's-complement
  value.
- A layout is written as a sequence of bracketed fields:
  `[u8 addr_type][u8 len][be16 port]`. `×N` repeats a field N times.
  Offsets are zero-based from the start of the payload.
- **`rsv`** marks a reserved field (Section 7.4).
- **Payload** means the plaintext payload of one [SN-MSG] message, after that
  layer has removed any padding and reversed any compression.
- **Kind** is the 8-bit command or response identifier (Section 3.1).

---

## 3. Message model

How the messages of this protocol fit together: what identifies a message, which
messages are answered and which are not, how an answer is matched to its
question, and how large a message may be. Sections 4 to 6 then define the
individual messages.

### 3.1 Kind and `MessageType`

Every message is identified by one number, its kind. The layer below provides a
type field whose bits 0–30 belong to the application ([SN-MSG]); this protocol
uses the lowest eight bits of it and leaves the rest alone.

The kind of a message is the **low byte** of the [SN-MSG] `MessageType` field.

- Bit 31 of `MessageType` is the compression flag and belongs to [SN-MSG].
- Bits 8–30 are reserved. A sender MUST transmit them as zero. A receiver MUST
  ignore them and MUST take the kind from the low byte alone.

Kinds `0x00`–`0x7F` are commands, sent by the controller. Kinds `0x80`–`0xFF`
are responses, sent by the device. A controller MUST NOT send a response kind
and a device MUST NOT send a command kind. A device that receives a response
kind treats it as a command kind it does not recognise (Section 7.1); a
controller that receives a command kind skips it (Section 7.2). Within each half
the highest 32 values — `0x60`–`0x7F` and `0xE0`–`0xFF` — are for private use
(Section 7.8).

A receiver MUST dispatch on the exact kind. Beyond the direction just stated, it
MUST NOT infer anything about a kind — whether it mutates state, whether it is
answered, what it costs — from its numeric value, its range, or any bit of it.

> **Why the exact kind and nothing else.** The numbers are grouped loosely, as an
> aid to whoever reads a hex dump or allocates the next one. A receiver that
> tested "is this below `0x20`?" or "is this an even number?" would be making a
> promise about every kind not yet defined, and the first new kind that broke
> the pattern would be mishandled by every such receiver already deployed.

### 3.2 Commands and responses

Messages from the controller are commands and messages from the device are
responses. Most commands are answered and a few are not; which is which is a
property of the kind, stated where the kind is defined.

A controller sends **commands**; a device sends **responses**. Every message in
either direction carries the strictly increasing per-direction `MessageNum` of
[SN-MSG].

Commands are of two sorts:

- **Answered commands.** The device replies with zero or more **typed
  responses** followed by exactly one **ACK** (Section 5.1). Every command not
  listed as response-free is an answered command.
- **Response-free commands.** `PIXEL_FRAME` and `NTP_SERVER`, and any command
  that an extension defines as response-free (Section 7.8). A device that
  recognises the kind MUST NOT send any response to it — no typed response and no
  ACK — whether it acts on the message, rejects its payload, or does not support
  the feature behind it.

For a query (a command that elicits a typed response), the device MUST send the
typed response first and the ACK after it.

```
 controller                                      device
 │── GET_STATUS          MessageNum = 7 ───────────►│
 │                                                  │
 │◄─────────── STATUS    the typed response ────────│
 │◄─────────── ACK       orig_kind        = 0x08 ───│
 │                       orig_message_num = 7       │
 │                       status           = OK      │
```

The ACK closes the exchange: once the controller has the ACK for its command, it
has everything the device will send in answer to it.

### 3.3 Correlation

A controller has to know which command a reply belongs to. The rule is that the
reply says so itself.

A response is tied to its command by the ACK's `orig_message_num` field, which
carries the `MessageNum` of the command being answered. Correlation is by that
field and never by message order.

A controller awaiting the answer to a command:

1. MUST read until it receives the ACK whose `orig_message_num` equals the
   `MessageNum` of that command.
2. MUST skip, without error, any ACK whose `orig_message_num` is a different
   value. Such an ACK answers an earlier command whose reply was never read, or
   a response-free command sent to a device that predates it (Section 7.1).
3. MUST skip, without error, any response kind it does not recognise or is not
   waiting for (Section 7.2), and MUST NOT count skipped messages against any
   bound it places on how many messages one exchange may consume.
4. MUST treat a matching ACK whose `status` is not `OK` as failure of the
   command.

A device MAY send responses that no command solicited.

> **Why by message number and not by order.** Order looks sufficient until
> something else is in the stream. A device may send a message nobody asked for;
> a controller may have abandoned an earlier command whose reply is still on its
> way; a response-free command sent to an older device is answered with an error
> the sender did not expect. A controller that took "the next ACK" as its answer
> would, in each case, credit one command with another's result.

### 3.4 The first command of a session

The first command is special only in how it travels: it rides in with admission.

The transport cannot complete admission without a first message from the
controller ([SN-TRANSPORT], "Taking control"; [SN-MSG], "The first message"). A
controller MUST supply one: an ordinary command of this protocol, which carries
`MessageNum` 1.

A controller SHOULD use `GET_DEVICE_INFO` as that first command, since it MUST
read `DEVICE_INFO` before sending a pixel frame (Section 6.2).

### 3.5 Compression and padding categories

The message layer can compress a message or pad it to a fixed size, and leaves
it to the protocol above to say which messages may use which. Compression saves
bandwidth where the payload is large and repetitive; padding hides which small
command was sent. This section assigns each core kind to a category.

[SN-MSG] ("Categories") states where compression and padding are permitted, by
message category, and requires the layer above to assign each of its kinds to
one. The assignment for the core is:

| Category | Kinds | Compression | Padding |
| --- | --- | --- | --- |
| Streaming data (pixel frames) | `PIXEL_FRAME` | MAY; a sender SHOULD compress where it shrinks the payload | MUST NOT |
| Control and configuration | every other core command, and every core response | MUST NOT | SHOULD, per [SN-MSG] |

- The program extension assigns categories to its own kinds in its own
  specification. An extension's responses follow its own categories.
- Compression and padding are mutually exclusive on one message ([SN-MSG]).
- Every core response is control and configuration, so a device MUST NOT set the
  compression flag on one. A controller MUST nevertheless handle a compressed
  message if one arrives.

### 3.6 Size limit

A device is a small machine with a fixed receive buffer. It says how large that
buffer is, and a controller is expected to stay inside it — strictly, because of
what happens otherwise.

A device reads messages into a bounded buffer and advertises the bound as the
`envelope` field of `DEVICE_INFO` (Section 5.3).

A controller MUST NOT send a message whose [SN-MSG] `Size` (sealed body plus the
16-byte tag) exceeds the device's `envelope`; an unpadded, uncompressed payload
is therefore at most `envelope − 16` bytes. For a compressed message the same
limit applies to the payload **before** compression as well: its `OriginalSize`
MUST NOT exceed `envelope − 16`.

Padding counts. A controller MUST NOT pad a message to a size class whose `Size`
would exceed `envelope`; it sends that message unpadded instead. The first
command of a session is sent before `envelope` is known: its payload MUST NOT
exceed 64 bytes, and it MUST NOT be padded beyond the smallest class.

The lower bound of `envelope` is 80: the `Size` of a message padded to the
smallest class. Every device can therefore receive the first command, and any
later command whose payload is at most 64 bytes, padded or not.

A device MUST accept every message that respects the `envelope` it advertises.

A device refuses a message header declaring more than it can buffer **without
reading its body**. Under [SN-MSG] that leaves the stream misaligned and ends the
session; it does not drop one message.

> **Why an oversized message ends the session and does not cost one message.**
> The device learns a message's length from its header, before the body
> arrives. If the length is more than it can hold, it has nowhere to put the
> body and does not read it — but the body is still in the stream, and there is
> no marker to find the next header by. Every byte after that point would be
> misread, so the session is closed. A controller that keeps sending the same
> oversized message gets a loop of reconnections, not a stream of dropped
> frames.

> **Note (informative).** A device may hold a small amount of slack above the
> advertised `envelope`. That slack is the device's own and a sender must not
> rely on it.

---

## 4. Commands

The commands every device understands. They fall into four groups: the pixel
data plane, which is one command with a section of its own (Section 6); a
handful of commands that control and query the device (Section 4.1); one that
names a time server (Section 4.2); and the two that choose and report what
drives the output (Section 4.3).

The core command kinds are listed below. The values `0x03` and `0x20` to `0x28`
are reserved for the program extension (Section 9). Section 10.1 lists every
assigned value.

| Kind | Value | Payload | Answer |
| --- | --- | --- | --- |
| `PIXEL_FRAME` | `0x00` | Section 6.1 | none (response-free) |
| `SET_BRIGHTNESS` | `0x01` | `[u8 value]` | ACK |
| `SET_FPS` | `0x02` | `[u8 fps]` | ACK |
| `SET_MODE` | `0x04` | `[u8 mode]` | ACK |
| `ON` | `0x05` | empty | ACK |
| `OFF` | `0x06` | empty | ACK |
| `PING` | `0x07` | empty | ACK |
| `GET_STATUS` | `0x08` | empty | `STATUS`, then ACK |
| `GET_MODE` | `0x09` | empty | ACK carrying the mode (Section 4.3) |
| `GET_DEVICE_INFO` | `0x0A` | empty | `DEVICE_INFO`, then ACK |
| `NTP_SERVER` | `0x0B` | Section 4.2 | none (response-free) |

General validation, applying to every command:

- A payload **shorter** than the layout for its kind is an error and MUST NOT be
  applied in part (Section 7.3).
- A payload **longer** than the layout is valid; the receiver parses the prefix
  it understands and ignores the rest (Section 7.3), except where a length is
  declared (Section 6.1).
- An unrecognised value of an enumerated field in an answered command MUST be
  answered `ERR_INVALID_ARG` (Section 7.5).

### 4.1 Output control

Small commands with a fixed payload or none. Each is answered with an ACK, and
the two queries are answered with their data first.

**`SET_BRIGHTNESS` (`0x01`)** — `[u8 value]`, 0–255. A single dimmer for the
whole output. Every colour channel the device outputs is scaled by
`value / 255`, so 255 leaves it unchanged and 0 is dark. It applies in every
mode (Section 4.3) and to everything the device outputs, pixel frames included
(Section 6.1). The value is live: `STATUS` reports it (Section 5.2).

**`SET_FPS` (`0x02`)** — `[u8 fps]`, 1–255. Sets the device's configured output
frame rate. A device MUST answer 0 with `ERR_INVALID_ARG`.

**`ON` (`0x05`)**, **`OFF` (`0x06`)** — empty payload. Turn the output on or
off. The state at start-up is the device's choice (Section 5.2).

**`PING` (`0x07`)** — empty payload. Elicits an ACK and has no other effect.

**`GET_STATUS` (`0x08`)** — empty payload. Answered with `STATUS`
(Section 5.2), then an ACK.

**`GET_DEVICE_INFO` (`0x0A`)** — empty payload. Answered with `DEVICE_INFO`
(Section 5.3), then an ACK.

### 4.2 `NTP_SERVER` (`0x0B`)

Devices that schedule frames need the time, and the controller is often the one
party that knows where a time server is. This command passes that address on.

Tells a device which time server to use. It carries an address, not a time. It
is OPTIONAL in both directions: a controller need not send it and a device need
not act on it. It is response-free (Section 3.2).

```
[u8 addr_type][u8 len][be16 port][len bytes of address]
```

| `addr_type` | `len` | Address |
| --- | --- | --- |
| 1 | 1 – 253 | a host name: ASCII letters, digits, `.` and `-` |
| 4 | 4 | an IPv4 address |
| 6 | 16 | an IPv6 address; a link-local one is on the interface the session uses |

Sender rules:

- `port` MUST be 1 to 65535. There is no default; a controller that means 123
  writes 123.
- A host name MUST use only the characters above.
- A controller MUST send `NTP_SERVER` only to a device that advertises the `pts`
  capability (Section 6.5). A controller that sends it sends it once in each
  session, after reading `DEVICE_INFO`, and again whenever the address changes.
- A controller that can resolve a name SHOULD send the address and not the name.
  A name SHOULD map to exactly one address.

Receiver rules:

- A device MUST ignore a message whose `addr_type` it does not know, whose `len`
  does not fit its `addr_type`, whose `port` is 0, whose host name holds a
  character outside those permitted, or whose payload is shorter than `4 + len`.
- `len` is a count (Section 7.3): bytes after the address are ignored.
- A device MUST NOT answer the message in any case, including when it ignores
  it. This is the case of Section 7.5 item 5, and overrides item 1 for `addr_type`.
- The same server sent again — the same four fields, byte for byte — changes
  nothing.
- A device MAY use the named server or ignore it. What it prefers when it also
  has a server of its own is the device's choice.
- What the message names lasts until another `NTP_SERVER` replaces it or the
  device restarts. The end of the session does not cancel it, and a device does
  not keep it across a restart.
- A device that changes server keeps its clock until the new server has
  answered; from that first answer, what it learned from the previous server is
  no longer used.

> **Note (informative).** A controller that takes over a device names a server
> too, since the previous controller's choice survives the session; one that says
> nothing leaves the device on the server it had.

### 4.3 Mode

A device always reports exactly one mode, and the mode decides what drives its
output.

| `mode` | Name | What drives the output |
| --- | --- | --- |
| 0 | — | reserved for the program extension (Section 9) |
| 1 | `PIXEL` | pixel frames (Section 6), unless an automatic pixel source owns the output (Section 6.1) |
| 2 – 255 | — | left to implementations |

Which modes a device has:

- A device that advertises `pixel` has `PIXEL` mode.
- A device that implements the program extension may have mode 0, as that
  extension's specification defines.
- A device MAY define further modes of its own with the values 2 to 255. This
  document will never assign them. Such a mode means something only on the
  device that defines it, so a controller MUST NOT send one to a device unless
  the device advertises a private capability (Section 7.8) that defines it.
- A device that has no mode — it does not advertise `pixel`, implements no
  extension that gives it one, and defines none of its own — reports mode `1`
  in `STATUS` and `GET_MODE`, because the field has no value for "none", and
  answers every `SET_MODE` `ERR_INVALID_ARG`. A controller recognises such a
  device by the absence of `pixel`, of `vm`, and of any private capability that
  defines a mode.
- The mode at start-up is the device's choice; a controller that depends on it
  reads it with `GET_MODE`.

**`SET_MODE` (`0x04`)** — `[u8 mode]`. Puts the device in `mode`. A device MUST
compare `mode` against each mode it has and MUST answer any other value
`ERR_INVALID_ARG`, changing nothing. It MUST NOT decode the field as a boolean
(Section 7.5). `SET_MODE` naming a mode the device has and is already in
succeeds (`OK`) and changes nothing.

**`GET_MODE` (`0x09`)** — empty payload. The device answers with an ACK and no
typed response. A device sends `detail` as exactly two bytes,
`[u8 mode][u8 output_enabled]`. A controller reads the first two and ignores any
further bytes (Section 7.3). This is the one ACK whose `detail` is binary and
not text (Section 5.1).

Outside `PIXEL` mode a device discards pixel frames (Section 6.1). A controller
that reads a mode it does not know, from `GET_MODE` or `STATUS`, surfaces it as
unknown (Section 7.5).

> **Note** — mode and output, and the commands that change each, drawn as a
> picture.
>
> ```
>             mode                                  output
>    (what drives the output)                    (on or off)
>  ┌──────────────────────────────┐         ┌───────────────────────────┐
>  │ exactly one mode at a time:  │         │ on   (output_enabled = 1) │
>  │   1        PIXEL             │         │ off  (output_enabled = 0) │
>  │   0        the program       │         └───────────────────────────┘
>  │            extension         │
>  │   2 – 255  the device's own  │
>  └──────────────────────────────┘
>   changed by  SET_MODE                      changed by  ON and OFF
>   read by     GET_MODE and STATUS           read by     GET_MODE and STATUS
>   (the output also goes off for a reason of the device's own)
>   at start-up: the device's choice, for both
> ```

> **Why 2 to 255 are left open.** A device may drive its output from something
> this document knows nothing about — a built-in test pattern, a local input. A
> range of its own lets a vendor add such a mode without waiting for a revision
> of this document, and a later revision can never assign the same value to
> something else.

---

## 5. Responses

What a device sends back. There are three in the core: the ACK that closes every
answered command, and two blocks of data that answer the two queries.

| Kind | Value | Sent in answer to |
| --- | --- | --- |
| `ACK` | `0x80` | every answered command |
| `STATUS` | `0x81` | `GET_STATUS` |
| `DEVICE_INFO` | `0x84` | `GET_DEVICE_INFO` |

`0x82` and `0x83` are reserved for the program extension (Section 9).

### 5.1 `ACK` (`0x80`)

The ACK says which command it answers and whether that command was accepted. It
can carry a short text explaining a refusal, meant for a person reading a log.

```
[u8 orig_kind][u8 status][u8 rsv×2][be64 orig_message_num][be16 detail_len][detail bytes]
```

| Offset | Field | Length |
| ---: | --- | ---: |
| 0 | `orig_kind` — the kind of the command being answered | 1 |
| 1 | `status` — an ACK status code, below | 1 |
| 2 | `rsv` | 2 |
| 4 | `orig_message_num` — the `MessageNum` of the command being answered | 8 |
| 12 | `detail_len` | 2 |
| 14 | `detail` | `detail_len` |

`detail` is an optional UTF-8 diagnostic of at most 128 bytes. A sender whose
diagnostic is longer MUST truncate it to 128 bytes and set `detail_len` to the
truncated length; it MUST NOT withhold the response. A sender SHOULD truncate at
a UTF-8 character boundary. A receiver MUST accept a `detail_len` above 128 and
MAY truncate what it shows. `detail` is text except in the answer to `GET_MODE`
(Section 4.3), and where an extension defines otherwise for the answer to one of
its own commands.

ACK status codes:

| Value | Name | Part |
| ---: | --- | --- |
| 0 | `OK` | core |
| 1 | `ERR_INVALID_ARG` | core |
| 2 | — | reserved (program extension, Section 9) |
| 3 | — | reserved (program extension, Section 9) |
| 4 | — | reserved (program extension, Section 9) |
| 5 | `ERR_OOM` | core |
| 6 | `ERR_UNKNOWN_KIND` | core |
| 7 | `ERR_MODE_MISMATCH` — reserved, never returned in this version; the name is kept so the value is never given a different meaning | reserved |
| 8 | — | reserved (program extension, Section 9) |

A device MUST select the status of a refused command as follows. The first row
that applies governs.

| Condition | Status |
| --- | --- |
| The kind is not recognised, or the device does not support it | `ERR_UNKNOWN_KIND` |
| The payload is shorter than the command's layout | `ERR_INVALID_ARG` |
| An enumerated field holds a value the device does not recognise or does not have | `ERR_INVALID_ARG` |
| A value is out of range: an index the device does not have; a count above its limit; an argument the command's section refuses | `ERR_INVALID_ARG` |
| The device has no memory for the request | `ERR_OOM` |
| The command is valid and the device could not carry it out for another reason | `ERR_INVALID_ARG` |

A device MUST NOT send status 7.

An extension MAY add rows for refusals of its own commands and state where they
fall in this order; for every other command this table governs.

Only `0` is success. A controller MUST treat every other value, including one it
does not recognise, as failure (Section 7.5).

> **Why only 0 is success.** New ways of failing will be added, and a controller
> built before one of them has to do the safe thing with it. If success is one
> value and everything else is failure, an unknown code is handled correctly by
> every controller ever written. A second success code would be read as failure
> by all of them, which is why none will be assigned.

### 5.2 `STATUS` (`0x81`)

A snapshot of the device's counters and current settings, for monitoring. It is
the only response of more than a few bytes whose payload is one fixed binary
layout, and that layout is the same on every device, whether or not the device implements the program
extension.

A single fixed layout of **78 bytes**.

```
[be64 frames][be64 commands][be64 dropped][be32 refresh_errors]
[u8 mode][u8 connected][u8 output_enabled][u8 rsv]
[u8 ext×44]
[u8 brightness][u8 target_fps]
```

| Offset | Field | Length |
| ---: | --- | ---: |
| 0 | `frames` | 8 |
| 8 | `commands` | 8 |
| 16 | `dropped` — pixel frames rejected (Section 6.1) | 8 |
| 24 | `refresh_errors` | 4 |
| 28 | `mode` — the current mode (Section 4.3) | 1 |
| 29 | `connected` | 1 |
| 30 | `output_enabled` | 1 |
| 31 | `rsv` | 1 |
| 32 | ext — the extension block | 44 |
| 76 | `brightness` — the value set by `SET_BRIGHTNESS` (Section 4.1) | 1 |
| 77 | `target_fps` — the *configured* frame rate set by `SET_FPS` | 1 |

- `frames` — successful output refreshes since the device started, whatever
  drove them; a device MAY leave out refreshes that only blank the output.
- `commands` — messages received since the device started other than
  `PIXEL_FRAME`, including the `GET_STATUS` being answered.
- `dropped` — pixel frames rejected (Section 6.1) since the device started.
- `refresh_errors` — output refreshes that failed since the device started; a
  device that cannot detect a failed refresh reports 0.
- `connected` — `1` when the device has an established session, so a `STATUS`
  sent over a session carries `1`; kept so the layout is stable.
- `output_enabled` — `1` while the output is on, `0` while it is off, after
  `OFF` or for a reason of the device's own; the state at start-up is the
  device's choice.

A device MUST send `0` or `1` in `connected` and `output_enabled` (here and in
`GET_MODE`). These two fields are flags, not enumerations; Section 7.5 does not
apply to them. Counters wrap modulo their width.

`target_fps` is the *configured* frame rate and `brightness` the configured
dimmer. Both are live values, not boot-time defaults.

**Extension block.** Bytes 32 to 75 belong to the program extension
(Section 9). A device that does not implement it MUST send them as zero; a
controller that does not implement it MUST ignore them. Their content is defined
by the extension's specification.

A payload shorter than 78 bytes is malformed; it is not an older peer and there
is no shorter tier to fall back to. A later revision MAY add a tier above 78
bytes (Section 7.6).

### 5.3 `DEVICE_INFO` (`0x84`)

The device's authenticated self-description: what it is, how large it is and
what it can do. A controller reads it at the start of every session and takes
its limits from nowhere else.

It is the protocol's only self-describing payload: a sequence of name/value
pairs with no count prefix, read until the payload ends.

```
[u8 namelen][name][u8 vallen][value] ...
```

`name` and `value` are text, with explicit lengths and no terminator.

> **Why this payload is text pairs when every other is fixed binary.** This is
> the payload most likely to grow: each new device feature wants to announce
> itself here. A fixed layout can only grow at its end and needs every reader to
> agree on offsets. Named pairs let a device add a field that an older
> controller skips without noticing, and let a vendor add its own without asking
> anyone. For this payload the rules below are the specification, not a table of
> offsets.

#### 5.3.1 Fields

| Name | Value | Range | Meaning |
| --- | --- | --- | --- |
| `envelope` | decimal | 80 – 16777216 | the device's receive limit on `Size` (Section 3.6) |
| `strips` | decimal | 1 – 65535 | number of strips. Required with `pixel` |
| `leds` | decimal | 1 – 65535 | LEDs per strip. Required with `pixel` |
| `bpp` | decimal | 3 or 4 | bytes per pixel **of the strip**: 3 = RGB, 4 = RGBW. Required with `pixel` |
| `pixel` | empty | — | capability: the device accepts pixel frames (Section 6) |
| `pts` | empty | — | capability: scheduled presentation (Section 6.5) |
| `x-*` | any | — | private use (Section 5.3.4) |

The program extension reserves three further names — `vm`, `signed-onx` and
`pins` (Section 9).

A **capability** is a field whose presence is the information. A receiver MUST
test a capability by the presence of its name, and MUST NOT require its value to
be empty.

> **Why a capability is a name with no value.** Presence is all a yes/no feature
> needs, and it leaves room to grow: a capability can later gain a parameter by
> acquiring a value, and every controller written before that still sees the
> name and still reads it as "supported". A separate list of capabilities
> alongside the fields would be a second copy of the same facts, to be kept in
> step for ever.

#### 5.3.2 Grammar

> **Note** — This subsection says how names and values are written, and what a
> receiver does with one that does not parse or is out of range.

- A name consists of the characters `[a-z0-9-]` and is case-sensitive.
- A decimal value is ASCII digits only: no sign, no leading zeros, no
  whitespace.
- A value that does not parse as a plain decimal where one is required, or that
  falls outside its field's range, is a protocol error. A receiver MUST reject
  the payload; it MUST NOT clamp, round or guess.
- `bpp` is an enumeration, not an open range. A receiver MUST reject any value
  other than 3 or 4.
- A receiver MUST reject a geometry whose `strips × leds × bpp` exceeds
  16777216, and MUST compute that product, and `strips × leds × 4`, in a type
  that cannot overflow (the field maxima give about 1.7 × 10¹⁰).

> **Why 16777216.** It is the same ceiling as the upper bound of `envelope`
> (Section 5.3.1).

#### 5.3.3 Rules

> **Note** — These rules say which fields a payload carries, and how a receiver
> treats names it does not know, repeated names and oversize payloads.

1. **Required set.** `envelope` MUST be present. `strips`, `leds` and `bpp` MUST
   be present when the device advertises `pixel`, and describe the LEDs it
   drives. A device that does not advertise `pixel` MAY omit them, and a
   receiver MUST NOT require them of it; it MAY send them, when it drives LEDs
   by other means, and they then describe those LEDs. A device MUST NOT
   advertise `pts` without `pixel`. A receiver MUST treat a missing required
   field as a protocol error and MUST NOT substitute a default.
2. **Unknown names.** A receiver MUST NOT treat an unknown name as an error. It
   MUST skip `vallen` bytes and continue with the next pair.
3. **A name's type is fixed.** A sender MUST NOT change what a name means or how
   its value is read; a new meaning takes a new name. The one permitted change
   is from empty to valued — a capability gaining a parameter. The reverse, and
   any change from one value type to another, is forbidden.
4. **Order and repetition.** Order is not significant. A receiver MUST NOT index
   by position, MUST accept a repeated name, and MUST take the last value given
   for it.
5. **Bounds.** A receiver MUST reject a `DEVICE_INFO` payload larger than 1024
   bytes or carrying more than 32 fields.

A payload that ends inside a pair is malformed and MUST be rejected.

> **Note** — Section 12 says why a receiver applies the bounds of item 5.

#### 5.3.4 Private fields

A name beginning `x-` is private use: vendor-defined, with no registry. A private
field that carries binary data MUST encode it as text (hex or base64) inside the
value.

#### 5.3.5 Example (informative)

A device with a vendor field, 63 bytes:

```
0000  08 "envelope"      05 "32768"
000f  06 "strips"        01 "4"
0018  04 "leds"          04 "1024"
0022  03 "bpp"           01 "3"
0028  05 "pixel"         00
002f  0d "x-acme-dmx512" 01 "4"
```

#### 5.3.6 Authority

> **Note** — This subsection says how far a controller can rely on `DEVICE_INFO`
> and when it reads it again.

`DEVICE_INFO` is fetched over an authenticated session and is authoritative for
the device's capabilities and limits. A controller MUST re-read it after every
admission, including re-admission to the same device.

---

## 6. Pixel frames and frame timing

The data plane. A controller that drives the LEDs directly sends a stream of
`PIXEL_FRAME` messages, each a complete or partial picture. This section defines
the frame, how large it may be, and the optional timestamps that let several
devices show the same frame at the same instant.

This section applies to a device that advertises the `pixel` capability, and to
a controller that sends it frames (Section 1.4).

### 6.1 `PIXEL_FRAME` (`0x00`)

One picture, or the first part of one. The payload is a 28-byte header — a frame
number, two timestamps and a length — followed by the pixels.

```
[be64 signed frame_number][be64 signed not_before][be64 signed not_after]
[be32 pixel_byte_length][pixel bytes]
```

```
  0              8            16          24                  28   ← offset
 ┌──────────────┬────────────┬───────────┬───────────────────┬─────────────────────┐
 │ frame_number │ not_before │ not_after │ pixel_byte_length │ R G B W  R G B W  … │
 │   8 bytes    │  8 bytes   │  8 bytes  │      4 bytes      │  4 bytes per pixel  │
 └──────────────┴────────────┴───────────┴───────────────────┴─────────────────────┘
```

| Offset | Field | Length |
| ---: | --- | ---: |
| 0 | `frame_number` — identity and logging only | 8 |
| 8 | `not_before` — Unix nanoseconds, UTC (Section 6.3) | 8 |
| 16 | `not_after` — Unix nanoseconds, UTC (Section 6.3) | 8 |
| 24 | `pixel_byte_length` | 4 |
| 28 | pixel bytes | `pixel_byte_length` |

- **Wire stride.** Pixels are always carried at **4 bytes per pixel** — R, G, B,
  W — whatever the strip is. A device driving an RGB strip drops the fourth byte
  on ingest. A full frame is therefore `strips × leds × 4` bytes for every
  device.
- A sender MUST NOT size a frame from `DEVICE_INFO`'s `bpp`. `bpp` describes the
  strip, for colour handling; it is not the wire stride.

  > **Why always four bytes, even for an RGB strip.** One encoding then serves
  > every device, and a controller driving a mixed display builds each frame the
  > same way. The cost is one unused byte per pixel on RGB strips. Sizing a
  > frame from `bpp` instead is the mistake this rule exists to prevent: a frame
  > built at three bytes per pixel is read at four, so every pixel after the
  > first is shifted and the picture is garbled — and when its length is not a
  > multiple of four it is dropped outright.
- **Declared length.** `pixel_byte_length` MUST exactly equal the number of
  bytes that follow it in the payload. This field declares a length; trailing
  bytes are **not** permitted here (Section 7.3).
- `pixel_byte_length` MUST be a whole number of 4-byte pixels, at least one, and
  MUST fit the device's geometry at that stride.
- **Pixel order.** Pixels are in physical order, strip by strip: with `leds` the
  advertised LEDs per strip, pixel `i` of the frame (counting from 0) is LED
  `i mod leds` of strip `floor(i / leds)`, LED 0 being the first on the strip's
  data line.

```
 in the frame:  pixel 0   pixel 1  …  pixel leds-1 │ pixel leds  …  pixel 2·leds-1 │ …
                ───────────── strip 0 ──────────── │ ────────── strip 1 ────────── │
 on the device: LED 0     LED 1    …  LED leds-1   │ LED 0       …  LED leds-1     │ …
```

- **As sent.** Pixels are placed as sent: a controller that wants a different
  layout arranges them itself. Brightness applies: every pixel is scaled by the
  value set by `SET_BRIGHTNESS` (Section 4.1).
- **Short frames.** A frame MAY carry fewer pixels than the geometry. It updates
  the pixels it carries; every LED after them MUST keep the value given by the
  most recent frame that covered it. Only a frame that was presented counts: one
  that was rejected, discarded (Section 6.4.2) or abandoned while held covers
  nothing. An LED that no frame has covered since the device started, or since
  it last entered `PIXEL` mode (Section 4.3), is off.

`PIXEL_FRAME` is response-free. A device MUST discard a frame, without any
response, when:

- it is in a mode other than `PIXEL` (Section 4.3);
- an automatic pixel source owns the output — a pixel source on the device
  other than the session, such as a local lighting-network input, that has taken
  the output (it may have put the device in `PIXEL` mode to do so); or
- the payload is malformed under the rules above.

Each such rejection MUST increment the `dropped` counter of `STATUS`.

### 6.2 Frame limit

Two things bound a frame: how many LEDs the device has, and how large a message
it can receive. The second is usually the smaller on a large display, and it is
the one that is fatal to exceed.

Before sending a frame, a controller MUST have read `DEVICE_INFO` in the current
session and MUST compute, from the advertised values:

```
capacity = strips × leds × 4
limit    = min(capacity, envelope − 28 − 16)
```

`28` is the `PIXEL_FRAME` header and `16` the [SN-MSG] tag. `limit` is the
largest `pixel_byte_length` the controller may send. A controller MUST NOT assume
a geometry or an `envelope` the device did not advertise.

Exceeding `envelope` does not lose one frame: it ends the session
(Section 3.6).

`limit` is rounded down to a multiple of 4.

> **Note (informative).** The lower bound of `envelope` is 80, so `envelope`
> never limits a frame to fewer than 36 bytes, nine pixels.

### 6.3 Frame timing: meaning

Several devices that together form one display must show one image. Frames
reach them over a network at slightly different times, and a display whose
panels change a few milliseconds apart visibly tears. The remedy is to send each
frame a little early and tell every device the same instant at which to show it.

This protocol carries no clock. Every device and every controller keeps its own
with NTP, and each `PIXEL_FRAME` says when it may be shown.

- `not_before` is the instant before which the frame is not to be presented.
- `not_after` is the instant after which it is not to be presented at all.
- To **present** a frame is to start writing it to the output. Where that takes
  time and cannot be interrupted (an LED strip refresh), a frame to be presented
  during a refresh starts when the refresh ends, and is superseded if a newer
  frame is to be presented before then.

This section and the rules for a receiver in Sections 6.4.1 to 6.4.8 (6.4.5 is
the sender's) bind a device that advertises `pts`. A device that does not
advertise it follows Section 6.4.9.

### 6.4 Frame timing: rules

What a device does with the two timestamps, what a sender puts in them, and what
keeps a display working when a clock is wrong. The rules are written so that
every failure — a clock not yet set, an unreachable time server, a lead (Section
6.4.5) that is too short — ends in the same harmless place: the device shows
frames as they arrive.

#### 6.4.1 Zero, and what is ignored

A timestamp can be switched off, and several conditions switch it off
automatically. A timestamp that is off plays no part in the decision of
Section 6.4.2.

A timestamp is **in use** only when its value is in `[1, 2^62)`.

- `0` switches the timestamp off.
- Any other value outside that range counts as `0`.
- A non-zero `not_after` earlier than `not_before` counts as `0`.
- A `not_before` more than **1 s** after the frame's arrival counts as `0` for
  that frame.
- A receiver whose clock is not synced (Section 6.4.6) treats both timestamps as
  `0` in every frame.

#### 6.4.2 The decision

What happens to a frame depends only on when it arrives relative to its two
timestamps:

```
                          not_before                    not_after
 ─────────────────────────────┼─────────────────────────────┼───────────────────► time
   a frame that arrives here  │  a frame that arrives here  │  a frame that arrives
   is HELD, and is presented  │  is PRESENTED AT ONCE       │  here is DISCARDED: the
   at not_before              │                             │  output stays as it is
```

The decision is made on arrival, from the timestamps alone, before the pixels
are processed:

1. If `not_after` is in use and has passed, the frame is **discarded**. Its
   pixels are not processed and the output is not updated; the device goes on
   showing what it shows. A device MUST NOT blank the output.
2. Otherwise, if `not_before` is in use and has not come, the frame is **held**
   and presented at `not_before`.
3. Otherwise the frame is presented at once.

> **Why a late frame is discarded and not shown late.** Refreshing an LED strip
> takes most of a frame period, which leaves a few milliseconds of slack per
> frame. A frame shown late pushes back every frame behind it, and they catch
> up only a little at a time. Discarding it costs that panel one repeated image
> and leaves the next frame on time.

> **Why the output is left alone and not blanked.** A dark panel is far more
> visible than a repeated image, and blanking is itself a refresh, which would
> delay the next frame.

> **Note** — a numeric example of the decision. Take a frame whose `not_before`
> is T and whose `not_after` is T + 10 ms (the 10 ms window of Appendix B.3),
> both in use, received by a receiver whose clock is synced. If it arrives at T
> + 5 ms, `not_after` has not passed (step 1) and `not_before` has come (step
> 2), so it is presented at once (step 3). The same frame arriving at T + 15 ms
> finds `not_after` passed, so step 1 discards it, since no run of 3
> discards precedes it (Section 6.4.4): its pixels are not processed and the
> output stays as it is.

#### 6.4.3 One held frame, arrival order

A device does not queue frames. It has room to hold one frame that is waiting
for its moment, which is all a small device can spare and all that a lead of one
frame period (Section 6.4.5) needs.

A receiver holds **at most one** frame.

When a frame arrives while one is held, the held frame stops waiting before the
new frame is handled:

| The new frame is | The frame already held is |
| --- | --- |
| accepted for presentation later | presented at once; it never waits behind a newer frame |
| presented at once | superseded, not presented |
| discarded (Section 6.4.2) or rejected (Section 6.1) | still held |

- Frames therefore reach the output in arrival order, and a frame never waits
  behind a newer one.
- A discarded frame (Section 6.4.2) or a rejected one (Section 6.1) does not
  disturb a held frame.
- A held frame MUST be abandoned, not presented, if before its `not_before` the
  device leaves `PIXEL` mode (Section 4.3), an automatic pixel source takes the
  output, or the output is turned off.
- The end of the session does not abandon a held frame.

An abandoned frame is not counted in `dropped` (Section 6.4.10).

#### 6.4.4 A panel never freezes

After **3** frames discarded in a row, the receiver stops discarding: it
presents frames whose `not_after` has passed on arrival, until a frame arrives
that Section 6.4.2 does not discard. Any frame presented or held under
Section 6.4.2 ends a run of discards.

> **Why a panel must never freeze.** With a wrong clock, or a lead shorter than
> the link's delay, every frame arrives past its `not_after`. Section 6.4.2
> alone would then discard them all and leave the panel on one image for ever.
> Three is small enough that a wrong clock trips the fallback within a tenth of
> a second, and large enough that a brief stall, which delivers a few late
> frames together, does not.

> **Note** — the decision of Sections 6.4.2 to 6.4.4 drawn as a picture, with
> the numbers of Section 6.6.
>
> ```
>  a frame arrives
>    │
>    ├─ not_after in use and passed ──────► DISCARDED: the output is left as it is.
>    │                                      After 3 discards in a row, such frames
>    │                                      are PRESENTED AT ONCE until a frame
>    │                                      arrives that 6.4.2 does not discard (6.4.4)
>    ├─ not_before in use, not yet come ──► HELD, and presented at not_before
>    └─ otherwise ────────────────────────► PRESENTED AT ONCE
>
>  A run of discards ends with any frame presented or held under 6.4.2.
> ```
>
> ```
>  a frame is HELD (at most 1 is held) and another frame arrives
>    the new frame is accepted for presentation later ──► the held frame is
>                                                         presented at once
>    the new frame is presented at once ────────────────► the held frame is
>                                                         superseded
>    the new frame is discarded or rejected ────────────► the held frame stays held
>
>  The held frame is abandoned if, before its not_before, the device leaves PIXEL
>  mode, an automatic pixel source takes the output, or the output is turned off.
> ```

#### 6.4.5 The sender

The sender decides when a frame is due and how late is too late, and gives every
device of a display the same answer.

- A sender that schedules stamps `not_before = clock + lead` and
  `not_after = not_before + window`, and MUST put the **same two values** in
  every device's copy of a frame, computed once per frame before it is sent to
  any device.
- Its clock is NTP-synced UTC, and SHOULD take its time from the same server as
  the devices.
- The lead MUST NOT exceed 1 s. The RECOMMENDED lead is one frame period (33.3 ms
  at 30 fps). A lead longer than one period, up to the limit, is not an error.
- The RECOMMENDED window is 10 ms at 30 fps. `not_after = 0` turns discarding
  off.
- A sender that drops a frame drops it for every device of the display. When its
  frame rate changes, its lead follows.
- A sender that stops sending frames — at the end of a stream, or for a pause —
  SHOULD send its last frame once more with both timestamps `0`.
- A sender that does not schedule, or that knows its own clock is not synced,
  MUST send both timestamps `0`.

> **Why the window is the sender's to choose.** How late is too late depends on
> the frame rate: ten milliseconds is generous at 30 frames a second and most of
> a period at 100. The sender knows the rate it is sending at and the device
> does not, so the sender states the limit in each frame.

> **Why the last frame is repeated with both timestamps zero.** A device that
> discarded the final frame of a stream would stay one image behind its
> neighbours until the stream resumed. A frame with no timestamps cannot be
> discarded, so repeating the last one brings every panel to the same image.

#### 6.4.6 Clocks

Scheduling is only as good as the clocks it compares against. This section says
when a device may trust its own clock and what it does when it cannot.

- Timestamps are compared with the receiver's own clock, which it keeps with
  NTP.
- A receiver's clock is **synced** when NTP has set it and it has synchronised
  within the last **5 minutes**. Otherwise the receiver is unsynced.
- A receiver SHOULD poll its time server at least once a minute. On a network
  with variable delay it SHOULD take the offset from the exchange with the
  smallest round-trip delay among its most recent ones, and poll a site-local
  server every few seconds.
- The clock is for presentation only. NTP is not authenticated, so the clock
  MUST NOT feed a security decision.
- A controller MAY name the device's time server with `NTP_SERVER`
  (Section 4.2).

> **Why 5 minutes.** At 20 ppm a free-running clock drifts about 6 ms in that
> time.

#### 6.4.7 Accuracy

> **Note** — This subsection says how close to its `not_before` a receiver
> presents a held frame.

A receiver SHOULD present a held frame within 2 ms of its `not_before`. It MUST
NOT present a held frame before its `not_before` except under Section 6.4.3.

> **Why 2 ms.** It is small against a frame period (33.3 ms at 30 fps).

> **Note (informative).** A receiver therefore presents when a frame arrives or
> falls due. A render loop that wakes only on its own periodic tick does not meet
> this rule.

#### 6.4.8 Ordering

> **Note** — This subsection says in what order frames reach the output when
> their timestamps and their arrival disagree.

The stream delivers in order and `MessageNum` is strictly increasing. A receiver
is not required to reorder; if timestamps go backwards, arrival order still
governs (Section 6.4.3). `frame_number` does not affect presentation.

#### 6.4.9 Receivers without `pts`

> **Note** — This subsection says what a device without `pts` does with the
> timestamps, and what a sender does for a display that includes one.

A device that does not advertise `pts` ignores both timestamps and presents on
arrival. A display is consistent only when every device of it advertises `pts`.
A sender driving a display that mixes devices with and without `pts`, or one
that includes a device unable to keep time, MUST send both timestamps `0` to all
of it.

#### 6.4.10 Counters

> **Note** — This subsection says which counts a receiver keeps for its own
> diagnosis.

A receiver SHOULD keep device-local counts of frames discarded (Section 6.4.2),
frames presented past their `not_after` (Section 6.4.4) and held frames
presented early (Section 6.4.3). They are not the `dropped` counter of `STATUS`,
which counts rejected frames, and they are not carried on the wire.

### 6.5 The `pts` capability

Scheduled presentation is optional for a device, so a device that implements it
says so.

A device that keeps an NTP-synced clock and implements Section 6.3 and the
receiver's rules of Sections 6.4.1 to 6.4.8 advertises the `pts` capability in
`DEVICE_INFO`.

- `pts` is tested by the presence of the name (Section 5.3.1).
- It also appears in the discovery record's `caps` list (Section 8).
- A controller MUST NOT assume scheduled presentation without it.

### 6.6 The numbers

Every constant of frame timing in one table.

| Parameter | Value |
| --- | --- |
| Held frames | **1** |
| Discards before the fallback | **3** |
| Hold limit (receiver) | `not_before` at most **1 s** after arrival |
| Maximum lead (sender) | **1 s** |
| Recommended lead | **one frame period** |
| Recommended window | **10 ms** at 30 fps |
| Clock considered synced | NTP sync within **5 minutes** |
| Accuracy | **≤ 2 ms** recommended |

---

## 7. Extensibility rules

This protocol has no version field and no capability handshake. Every rule below
defines what a receiver does with something it does not understand, so a sender
can add to the protocol without knowing what the peer supports.

> **Note** — Art-Net and E1.31 work the same way (Section 13.2).

These rules are normative and apply in **both directions**, because both peers
are receivers. An implementation MUST enforce them on every message it receives.

They are numbered R1 to R7. In one line each:

| Rule | A receiver that meets … | … does this |
| --- | --- | --- |
| R1 | a command kind it does not know | refuses it with `ERR_UNKNOWN_KIND` |
| R2 | a response kind it does not know | skips it and keeps reading |
| R3 | more payload than it expects | uses what it understands, ignores the rest |
| R4 | a reserved field | ignores it |
| R5 | a value it does not know | refuses the command, or reports the value as unknown |
| R6 | a longer response | reads the part it knows |
| R7 | a feature it must know about in advance | looks for its capability name |

Section 7.8 builds on them: it says how a feature that only some devices have is
added as an extension, and sets aside values for private ones.

### 7.1 R1 — Unknown command kinds

A device that receives a command it has never heard of says so, with a status
that means exactly that. A controller can then tell "this device is older" from
"this command failed".

1. A device MUST answer a command kind it does not recognise with an ACK of
   status `ERR_UNKNOWN_KIND`.
2. A device MUST NOT answer a kind it recognises as response-free
   (Section 3.2).
3. A device built before a response-free kind was defined cannot know the kind
   is response-free, and answers it `ERR_UNKNOWN_KIND` under item 1. A sender of
   a response-free command MUST therefore tolerate an `ERR_UNKNOWN_KIND` ACK for
   it; the skip rule of Section 3.3 provides this.
4. A controller MUST read `ERR_UNKNOWN_KIND` as "the peer does not have this" —
   it is older, or lacks the extension the command belongs to — not as a fault.
5. A controller MUST NOT read the absence of an answer as support. A peer that
   does not implement this protocol at all answers nothing, to any command, and
   is indistinguishable from an unreachable device.

A probe with a kind the device might not recognise therefore has three outcomes
— `OK`, `ERR_UNKNOWN_KIND`, or a timeout. The three say whether the device
recognises the kind: a device that recognises it can still refuse it with another
status (Section 5.1), only the device answers `ERR_UNKNOWN_KIND`, and a timeout
is the case of item 5. A probe is usable only for
commands that are harmless when they do take effect. For anything a controller
must know before acting, it uses capabilities (Section 7.7).

### 7.2 R2 — Unknown response kinds

The mirror of R1, for the other direction. A controller cannot refuse a response
— there is nobody to refuse it to — so it steps over what it does not know.

1. A controller MUST skip a response kind it does not recognise and MUST
   continue reading. It MUST NOT treat it as an error and MUST NOT let it disturb
   correlation (Section 3.3).
2. A device MAY introduce new response kinds, including unsolicited ones.

### 7.3 R3 — Trailing payload bytes

The way a payload grows: new fields go on the end, and a receiver that does not
know them stops reading where its own knowledge ends.

1. A receiver MUST accept a payload **longer** than the layout it knows for that
   kind, parse the prefix it understands, and ignore the remainder.
2. A sender MAY append a field to a fixed-layout payload without changing its
   kind. The absence of the field MUST mean the previous behaviour.
3. A receiver MUST reject a payload **shorter** than the layout it knows.
4. A sender MUST NOT extend an element of a repeated array. Only the tail of a
   payload is extensible.
5. A field that **declares the length** of the rest of the payload is validated
   exactly. `PIXEL_FRAME`'s `pixel_byte_length` is the only such field
   (Section 6.1).
6. Any other field that **counts** elements of fixed size, or gives the byte
   length of a trailing variable element, bounds what the receiver reads: the
   receiver requires at least the bytes those elements occupy and ignores
   anything after them. `NTP_SERVER`'s `len` and the ACK's `detail_len` are such
   fields; `DEVICE_INFO` pairs follow Section 5.3.3.

> **Why only the tail of a payload is extensible.** An element of a repeated
> array has a fixed size that the receiver uses to find the next element;
> growing it would make an old receiver read the new field as the start of the
> next element. A new per-element field is sent as a second array after the
> first.

> **Why a longer payload is accepted and a shorter one is not.** Extra bytes at
> the end are a newer sender's additions, and ignoring them is safe. Missing
> bytes are a truncated message, and acting on the part that did arrive would
> turn a transmission fault into a command applied by halves.

> **Why a count and a declared length are treated differently.** A count says
> how much to read; a declared length says how much there is. A receiver given a
> count reads that many elements and can ignore what follows, so the payload
> stays extensible. `pixel_byte_length` is the other kind: it has to equal what
> is actually there, because a mismatch means the sender and the device disagree
> about the size of the picture, and that is an error worth catching.

### 7.4 R4 — Reserved fields

Unused bytes in a layout are kept free for later. They stay usable only if
today's senders leave them empty and today's receivers do not look at them.

1. A sender MUST transmit every field marked `rsv` as zero.
2. A receiver MUST ignore every `rsv` field, whatever it contains.

The same rule governs bits 8–30 of `MessageType` (Section 3.1).

### 7.5 R5 — Unknown enumerated values

A field that takes one of a list of values will one day take a value that is not
on today's list. The rule is never to guess what it meant.

1. A device MUST answer an unrecognised value of an enumerated field in a
   command — a mode, for example — with `ERR_INVALID_ARG`. It MUST NOT guess
   what the value meant.
2. A two-valued enumeration MUST NOT be decoded as a boolean.
3. A controller MUST surface an unrecognised value in a response to its caller
   as unknown, carrying the raw value. It MUST NOT coerce it to a default or
   render it under a known name.
4. An unrecognised ACK status is not success (Section 5.1).
5. In a response-free command there is no answer: an unrecognised value is
   ignored (Section 4.2).

New error codes MAY be added. New success codes MUST NOT: success is the single
value `0`.

> **Why a two-valued enumeration must not be read as a boolean.** With values 0
> and 1 defined, `value != 0` looks the same as `value == 1`. It is not: it
> accepts every value a later revision might define, answers `OK`, and does what
> value 1 does. No controller could then tell a device that understands a new
> value from one that does not, and the field could never be extended. Comparing
> against each defined value, and refusing the rest, keeps it open.

> **Why an unknown value is shown as unknown.** A display routine that falls
> back to the name of value 0 turns a value it has never seen into a plausible
> wrong one, at the moment a person is reading it. Showing the raw number is
> less tidy and cannot mislead.

### 7.6 R6 — Length-tiered responses

R3 applied to a response that is expected to grow: each revision may add a
longer form, and a reader takes as much as it knows.

1. A response whose payload may grow declares its tiers by length.
2. A sender MUST only append when adding a tier; the meaning of every earlier
   byte is fixed.
3. A receiver MUST accept any tier it recognises and MUST ignore bytes beyond
   the largest tier it understands.

`STATUS` has one tier, of 78 bytes (Section 5.2).

### 7.7 R7 — Capability advertisement

R1 to R6 cover additions that an older peer can safely ignore. Some features are
not like that: a controller has to know whether the device has them before it
acts.

A feature whose absence changes what a controller must do is advertised as a
**capability**. A feature whose absence is survivable is not; a receiver that
ignores it still behaves correctly.

Capabilities are advertised in two carriers:

- **`DEVICE_INFO`** (Section 5.3), over an authenticated session. It is
  authoritative.
- **The discovery record's `caps` list** (Section 8), before a session exists.
  It is a selection hint only.

Rules, for both carriers:

1. A receiver MUST ignore capability names it does not know.
2. Absence of a name means the feature is not supported.
3. A controller MAY use the discovery record to choose a device. It MUST NOT act
   on a capability or a limit learned from it.
4. Where the two carriers disagree, `DEVICE_INFO` governs. The discovery list
   MAY be a strict subset of the capabilities in `DEVICE_INFO`.
5. A private capability uses the `x-` name prefix.

### 7.8 Extensions

R1 to R7 let the protocol grow without a version number. This section says how
to use them to add a feature that only some devices have — as the program
extension of Section 9 does — and gives vendors room to do the same without
waiting for a revision of this document.

An **extension** is a set of commands, responses and `DEVICE_INFO` entries that
a device implements as a whole or not at all. Every extension obeys these rules:

1. **One identifying capability.** One capability name (Section 5.3.1)
   identifies the extension. A device implements the extension if and only if it
   advertises that name. Any other `DEVICE_INFO` name the extension defines,
   further capabilities included, is meaningful only beside it.
2. **Nothing changes for a peer without it.** An extension MUST NOT change the
   layout of any message defined outside it, and MUST NOT require anything of a
   controller or device that does not implement it beyond what R1 to R7 already
   require. (The core itself reserves fields of `STATUS` for the program
   extension and says what a device without it sends there, Section 5.2. A
   private extension has no such reservation.)
3. **Devices without it refuse its commands.** A device MUST answer
   `ERR_UNKNOWN_KIND` (R1) to a command kind that no extension it implements
   defines.
4. **Controllers ask first.** A controller MUST NOT send a command of an
   extension to a device that does not advertise its capability. It skips
   response kinds of extensions it does not implement (R2).
5. **Every kind has a category.** The extension assigns each of its kinds a
   compression and padding category (Section 3.5), and says for each command
   whether it is answered or response-free.
6. **Its own conformance list.** The extension states what a controller and a
   device that implement it must do, in addition to the core.

**Extensions registered by this document** take their kinds, ACK status codes and
names from the registries of Section 10, by revision of this document; their
behaviour may be specified elsewhere. The program extension is one (Section 9).

**Private extensions** are defined by anyone, without registration:

- The capability name, and every other `DEVICE_INFO` name the extension defines,
  MUST begin `x-` (Section 5.3). The part after `x-` SHOULD begin with a name
  that identifies its author, as in `x-acme-servo`.
- Its commands MUST use kinds `0x60`–`0x7F`, its responses `0xE0`–`0xFF`, and
  any ACK status codes of its own `0xE0`–`0xFF`, and it MUST NOT use a kind,
  status code or name outside those ranges and the `x-` prefix. This document
  will never assign those values.
- A private status code is returned only in answer to a command of the private
  extension that defines it. The table of Section 5.1, and an extension's own
  table for its commands, govern every other command.
- A private value means something only together with the private capability the
  device advertises. Two vendors may use the same value for different things; a
  controller tells them apart by the capability, which is why a controller MUST
  NOT send a private kind to a device that does not advertise the capability it
  belongs to — there is no probing of private kinds. A device MUST NOT
  implement two private extensions that use the same value.
- A controller that does not recognise a device's `x-` capability treats the
  private ranges like any other unassigned value: it does not send those
  commands, it skips those responses, and it treats those status codes as
  failure.

> **Why a reserved private range.** Without one, a vendor's command would take
> the next free value, and a later revision of this document could assign the
> same value to something else. A device in the field would then answer a
> standard command with vendor behaviour. Setting the ranges aside costs a
> quarter of the kind space and makes that collision impossible.

---

## 8. Discovery

How a controller finds devices on the local network before it has a session
with any of them.

A device advertises itself with DNS-SD over multicast DNS [RFC6762], [RFC6763].

| Element | Value |
| --- | --- |
| Service type | `_sled_s1._udp` or `_sled_l1._udp`; the device's family fixes which. `_sled_x1._udp` is reserved. A controller SHOULD browse at least `_sled_s1._udp` and `_sled_l1._udp` |
| SRV port | the device's ShieldNet UDP port |
| Instance name and host name | one DNS label of letters, digits and hyphens, at most 63 octets, unique on the link and stable across restarts |
| TXT `type` | `LedMatrix` for a device that drives LEDs. Other values are defined by the device's family and carry no meaning in this document; a controller MUST NOT reject an unknown `type` |
| TXT `label` | a human-readable name chosen by the device or its owner |
| TXT `caps` | an unordered, comma-separated list of capability names (Section 7.7) |

- Where the identifier string is a canonical 36-character UUID, the transport
  `device_id` ([SN-TRANSPORT]) is the UUID's last six bytes followed by two zero
  bytes.
- A controller browsing for devices MUST ignore TXT keys it does not know.
- The record is written when the device starts. It does not carry live values
  such as brightness or frame rate.

Example (informative): instance name `0f8e2c1a-5b3d-4e6f-8a9b-a1b2c3d4e5f6`,
service `_sled_l1._udp`, SRV port 7700, TXT `type=LedMatrix`,
`label=Stage left`, `caps=pixel,pts`.

**The record is not authenticated.** Everything in it is a hint for choosing
what to dial. Section 7.7 forbids acting on its `caps`, and a controller MUST
take capabilities and limits from `DEVICE_INFO` only.

> **Why discovery is only a hint.** The transport authenticates a session, not
> an advertisement. Any host on the link can publish a record claiming to be a
> device, with whatever capabilities and whatever address it likes. A
> controller that believed it could be talked into assuming a feature or a size
> limit that is not real. Choosing which address to dial from the record is
> harmless, because the admission that follows succeeds only against a real
> device.

---

## 9. Program extension (reserved)

The program extension is an optional extension in the sense of Section 7.8,
defined by BlackShield. It is specified in a separate document that is not part
of this specification. This section reserves the values it uses, so that no
other part of this protocol, and no private extension, reuses them, and says
what a party that does not implement it does.

| What | Reserved values |
| --- | --- |
| Command kinds | `0x03`, `0x20` – `0x28` |
| Response kinds | `0x82`, `0x83` |
| ACK status codes | 2, 3, 4, 8 |
| `DEVICE_INFO` names | `vm` (its identifying capability), `signed-onx`, `pins` |
| Mode | 0 |
| `STATUS` | the extension block, bytes 32 – 75 (Section 5.2) |

- A device implements the program extension if and only if it advertises the
  `vm` capability.
- A device that does not implement it answers every reserved command kind
  `ERR_UNKNOWN_KIND` (Section 7.1), advertises none of the reserved names, does
  not have mode 0, and sends the `STATUS` extension block as zero.
- A controller that does not implement it skips the reserved response kinds
  (Section 7.2), treats the reserved status codes as failure like any other
  non-zero status (Section 5.1), and ignores the `STATUS` extension block.
- A controller MUST NOT send a reserved command kind to a device that does
  not advertise `vm`.
- The reserved values MUST NOT be used for anything else, by a device or a
  controller that does not implement the extension.

---

## 10. Registries

Each table is the complete set of assigned values, for the core and the program
extension together, and says which part each value belongs to. A value not
listed is unassigned and is handled by the rule named for that registry. A value
reserved for the extension is reserved on every device (Section 1.4).

### 10.1 Command kinds

> **Note** — This subsection lists every command kind with its part, and says
> how new kinds are allocated.

| Value | Name | Part |
| --- | --- | --- |
| `0x00` | `PIXEL_FRAME` | core |
| `0x01` | `SET_BRIGHTNESS` | core |
| `0x02` | `SET_FPS` | core |
| `0x03` | — | program extension (reserved) |
| `0x04` | `SET_MODE` | core |
| `0x05` | `ON` | core |
| `0x06` | `OFF` | core |
| `0x07` | `PING` | core |
| `0x08` | `GET_STATUS` | core |
| `0x09` | `GET_MODE` | core |
| `0x0A` | `GET_DEVICE_INFO` | core |
| `0x0B` | `NTP_SERVER` | core |
| `0x20` | — | program extension (reserved) |
| `0x21` | — | program extension (reserved) |
| `0x22` | — | program extension (reserved) |
| `0x23` | — | program extension (reserved) |
| `0x24` | — | program extension (reserved) |
| `0x25` | — | program extension (reserved) |
| `0x26` | — | program extension (reserved) |
| `0x27` | — | program extension (reserved) |
| `0x28` | — | program extension (reserved) |

Ranges: `0x00` is the pixel data plane; `0x01`–`0x1F` is device and output
control; `0x20`–`0x5F` is for extensions registered by this document. The ranges
are an aid to allocation only: which part a kind belongs to is the column above,
and beyond direction and the private range, Section 3.1 forbids a receiver from
acting on a kind's numeric value.

Allocation: a new command takes the next unassigned value in its range; reserved
values are skipped and never reassigned. Should a range fill, a revision of this
document extends it with unassigned values below `0x60`; a value reserved for an
extension is never reassigned. Commands are `0x00`–`0x7F` (Section 3.1).
`0x60`–`0x7F` is private use and is never assigned here (Section 7.8).
Unassigned values: Section 7.1.

### 10.2 Response kinds

> **Note** — This subsection lists every response kind with its part, and says
> how new kinds are allocated.

| Value | Name | Part |
| --- | --- | --- |
| `0x80` | `ACK` | core |
| `0x81` | `STATUS` | core |
| `0x82` | — | program extension (reserved) |
| `0x83` | — | program extension (reserved) |
| `0x84` | `DEVICE_INFO` | core |

Allocation: a new response kind takes the next free value. Responses are
`0x80`–`0xFF` (Section 3.1). `0xE0`–`0xFF` is private use and is never assigned
here (Section 7.8). Unassigned values: Section 7.2.

### 10.3 ACK status codes

> **Note** — This subsection points to the list of status codes in Section 5.1
> and says how new codes are allocated.

Values 0–8 as listed in Section 5.1 (7 is reserved and never returned), which
says which part each belongs to. Allocation: a new **error** code takes the next
free value. No further success code may be assigned. `0xE0`–`0xFF` is private
use and is never assigned here (Section 7.8); a private code is an error code
like any other. Unassigned values: Section 7.5.

### 10.4 `NTP_SERVER` address types

> **Note** — This subsection lists the address types of `NTP_SERVER` and says
> how new ones are allocated.

`1` = host name, `4` = IPv4, `6` = IPv6. Allocation: by revision of this
document. Unassigned values: ignored (Section 4.2).

### 10.5 `DEVICE_INFO` field names and capability names

> **Note** — This subsection lists every field and capability name with its
> part, and says how new names are allocated.

| Name | Kind | Part |
| --- | --- | --- |
| `envelope` | valued, required | core |
| `strips` | valued, required with `pixel` | core |
| `leds` | valued, required with `pixel` | core |
| `bpp` | valued, required with `pixel` | core |
| `pixel` | capability, optional | core |
| `pts` | capability, only with `pixel` | core |
| `vm` | reserved | program extension |
| `signed-onx` | reserved | program extension |
| `pins` | reserved | program extension |

Field names and capability names share one identifier space. Allocation: by
revision of this document; a name is never redefined (Section 5.3.3). Names
beginning `x-` are private use and are not registered. Unassigned names: skipped
(Section 5.3.3).

### 10.6 Modes

> **Note** — This subsection lists the modes with their part, and says how the
> remaining values are left.

| Value | Name | Part |
| --- | --- | --- |
| 0 | — | program extension (reserved) |
| 1 | `PIXEL` | core |

Allocation: values 0–1 are assigned. Values 2–255 are left to implementations
and are never assigned here (Section 4.3). A device answers a mode it does not
have `ERR_INVALID_ARG` (Section 7.5).

---

## 11. Conformance

An implementation conforms to this document in the role of **controller**,
**device**, or both, when it meets every requirement listed below for that role
and reproduces the vectors of Appendix A for the payloads it implements. The
vectors pin layouts. A.4 has two vectors: A.4.1 fills the `STATUS` extension
block with a pattern, which only a device with the program extension sends;
A.4.2 has the block zeroed, as every other device sends it (Section 5.2). A
device without the extension reproduces A.4.2; every controller MUST decode
both, ignoring the block.

The requirements below are the **core**, and are all that conformance requires.
An implementation that also implements the program extension additionally meets
that extension's own conformance list, in its separate specification.

### 11.1 Both roles

- Take the kind from the low byte of `MessageType`; send bits 8–30 as zero and
  ignore them on receipt (3.1).
- Dispatch on the exact kind (3.1).
- Honour the compression and padding category of every kind sent (3.5).
- Accept longer payloads, reject shorter ones, validate declared lengths exactly
  and treat counts and element lengths as lower bounds (7.3).
- Send `rsv` fields as zero and ignore them on receipt (7.4).
- Ignore unknown capability names and treat absence as "not supported" (7.7).
- Never reuse a value or name reserved for the program extension (1.4).

### 11.2 Controller

- Supply a first command at admission (3.4).
- Correlate by `orig_message_num`; skip non-matching ACKs and unrecognised
  response kinds without error, including those reserved for the program
  extension when it does not implement them (3.3, 7.2, 1.4).
- Treat any ACK status other than `0` as failure (5.1, 7.5).
- Handle a compressed response if one arrives (3.5).
- Never send a message whose `Size` exceeds the device's `envelope` (3.6).
- Read `DEVICE_INFO` after every admission, and before sending a pixel frame
  (5.3.6, 6.2).
- Send no `PIXEL_FRAME` to a device that does not advertise `pixel` (1.4).
- Decode `DEVICE_INFO` under its grammar and five rules, rejecting what they
  reject (5.3.2, 5.3.3).
- If it sends pixel frames: carry pixels at 4 bytes per pixel, in physical
  order, and compute the frame limit from the advertised values (6.1, 6.2).
- Send `NTP_SERVER` only to a device advertising `pts`, and tolerate an
  `ERR_UNKNOWN_KIND` ACK for a response-free command (4.2, 7.1).
- If it sends pixel frames: follow the sender rules of frame timing, and send
  both timestamps `0` when not scheduling, when unsynced, or when the display
  mixes devices with and without `pts` (6.4.5, 6.4.9).
- Surface unrecognised enumerated values as unknown (7.5).
- Read `GET_MODE`'s answer from the first two bytes of the ACK `detail`, and send
  a mode of 2 to 255 only to a device whose private capability defines it
  (4.3).
- Take capabilities and limits from `DEVICE_INFO`, never from the discovery
  record (7.7, 8).
- Send no command kind reserved for the program extension to a device that does
  not advertise `vm` (1.4, 9).

### 11.3 Device

- Answer every answered command with zero or more typed responses followed by
  exactly one ACK carrying the command's kind and `MessageNum` (3.2, 3.3, 5.1).
- Never answer a recognised response-free command (3.2).
- Answer an unrecognised command kind `ERR_UNKNOWN_KIND` (7.1).
- Answer an unrecognised enumerated value in a command `ERR_INVALID_ARG`, and
  never decode a two-valued enumeration as a boolean (7.5).
- Select the status of a refused command from the table of Section 5.1, as
  extended for its own commands by any extension the device implements.
- Never set the compression flag on a core response (3.5).
- Encode every response it sends exactly as Section 5 lays it out.
- Send `DEVICE_INFO` with the required fields, in range, and within the size and
  field-count bounds a receiver enforces (5.3).
- Accept every message within the `envelope` it advertises (3.6).
- Scale all of its output by the value set by `SET_BRIGHTNESS`, in every mode
  (4.1).
- Have the modes Section 4.3 gives it, answer any other `mode`
  `ERR_INVALID_ARG`, answer `GET_MODE` with the two-byte binary `detail`, and
  report the current mode in `STATUS` (4.3, 5.2).
- Discard pixel frames outside `PIXEL` mode, counting each in `dropped` (4.3,
  6.1).
- If it advertises `pixel`: validate `PIXEL_FRAME` as Section 6.1 requires,
  discard silently on rejection and count the rejection in `dropped`; keep the
  LEDs a short frame does not cover (6.1). If it does not: discard every
  `PIXEL_FRAME` and count it (1.4).
- If it advertises `pts`: implement the receiver's rules of Sections 6.4.1 to
  6.4.8 (6.5). If it advertises `pixel` and not `pts`: present on arrival
  (6.4.9). Never advertise `pts` without `pixel` (5.3.3).
- Never let its NTP-derived clock feed a security decision (6.4.6).
- Truncate, never withhold, an over-long ACK `detail` (5.1).
- If it does not implement the program extension: answer every reserved command
  kind `ERR_UNKNOWN_KIND`, advertise none of its reserved names, and send the
  `STATUS` extension block as zero (9, 5.2).

---

## 12. Security considerations

This protocol relies on the layers below it for all of its security. Two
sources of information are not protected by them: the discovery record and the
device's clock. A third, `DEVICE_INFO`, is authenticated but is input parsed
from a peer that may be faulty or hostile.
Each paragraph below says what is trusted, what is not, and where the rule that
contains the risk is stated.

**Authentication and confidentiality are the transport's.** This protocol adds
none. Every message is authenticated and encrypted by [SN-TRANSPORT] and
[SN-MSG]; any party that can establish a session is authorised to send every
command in this document. There is no per-command authorisation and no
distinction between controllers.

**Discovery is unauthenticated.** A forged discovery record can advertise a
capability, a label or an address that is not real. Section 7.7 confines its use
to choosing what to dial; a controller that acts on it — in particular, one that
sizes frames or skips a capability check from it — can be driven into a session
loss or into wrong behaviour by any host on the link.

**NTP is unauthenticated.** A device's clock, and the server named by
`NTP_SERVER`, can be wrong or hostile. The consequences are confined to
presentation: Sections 6.4.1 and 6.4.4 bound how long a wrong clock can hold or
suppress frames. The clock MUST NOT feed any security decision (Section 6.4.6).
`NTP_SERVER` lets an authorised controller direct a device's NTP traffic to an
arbitrary address; that is within what a session holder is trusted to do.

**Size limits are session-fatal.** A message exceeding the device's `envelope`
ends the session (Section 3.6). A controller that derives the limit from
anything other than the authenticated `DEVICE_INFO` of the current session risks
a reconnect loop.

**`DEVICE_INFO` is parsed from a peer.** Its bounds (1024 bytes, 32 fields), its
strict decimal grammar, its range checks and its overflow rule (Section 5.3)
exist so that a faulty or hostile device cannot drive a controller into an
unbounded allocation, an integer overflow, or a guessed geometry. A controller
MUST apply them even though the device is authenticated.

**Silent degradation.** The extensibility rules trade strictness for
compatibility. Section 7.5 forbids the two shortcuts that would turn that trade
into a hazard: accepting an unknown instruction as a known one, and reading an
unknown status as success.

**Traffic analysis.** Message sizes and timing are visible to an observer. The
padding and compression categories of Section 3.5 limit what sizes reveal about
control traffic and deliberately do not hide pixel-frame sizes ([SN-MSG],
"Categories").

---

## 13. References

### 13.1 Normative

- **[SN-TRANSPORT]** *ShieldNet Transport*, version 1.
  [`transport.md`](transport.md).
- **[SN-MSG]** *ShieldNet Message Layer*, version 1.
  [`message-layer.md`](message-layer.md).
- **[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119.
- **[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key
  Words", BCP 14, RFC 8174.

### 13.2 Informative

- **[RFC6762]** Cheshire, S. and M. Krochmal, "Multicast DNS", RFC 6762.
- **[RFC6763]** Cheshire, S. and M. Krochmal, "DNS-Based Service Discovery",
  RFC 6763.
- *ShieldLED device protocol — design notes.*
  [`../design/application.md`](../design/application.md).
- Artistic Licence, *Art-Net 4 Protocol Specification* — requires nodes to
  ignore unrecognised opcodes.
- ANSI E1.31, *Lightweight streaming protocol for transport of DMX512 using
  ACN* — states per field what a receiver lacking a feature does.

---

## Appendix A. Test vectors

Every vector is the exact payload, in hexadecimal, for the inputs stated. A
conforming encoder produces it and a conforming decoder accepts it. Each is the
plaintext payload of one message, before [SN-MSG] padding, compression and
sealing.

### A.1 `PIXEL_FRAME` (32 bytes)

`frame_number = 1`, `not_before = 1700000000123456789`,
`not_after = 1700000000133456789`, one pixel `01 02 03 04`.

```
000000000000000117979cfe3d85cd1517979cfe3e1e63950000000401020304
```

### A.2 `NTP_SERVER`

`10.0.0.5`, port 123 (8 bytes):

```
0404007b0a000005
```

`192.168.1.10`, port 8123 (8 bytes):

```
04041fbbc0a8010a
```

`time.local`, port 123 (14 bytes):

```
010a007b74696d652e6c6f63616c
```

`fd00::1`, port 123 (20 bytes):

```
0610007bfd000000000000000000000000000001
```

### A.3 `ACK` (36 bytes)

`SET_FPS` (`0x02`) rejected with `ERR_INVALID_ARG` for message number
`0x0102030405060708`, detail `"fps out of range 1-255"` (22 bytes).

```
0201000001020304050607080016667073206f7574206f662072616e676520312d323535
```

The ACK layout is the same for every command.

### A.4 `STATUS` (78 bytes)

#### A.4.1 With the extension block filled

```
frames=0x0102030405060708 commands=0x1112131415161718 dropped=0x2122232425262728
refresh_errors=0x31323334 mode=1(PIXEL) connected=1 output_enabled=1
ext = a0 a1 ... cb (44 bytes, the extension block; a recognisable pattern so a
misplaced field is obvious)
brightness=0x90 target_fps=0x1e(30)
```

```
0102030405060708111213141516171821222324252627283132333401010100a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacb901e
```

#### A.4.2 With the extension block zeroed

The same fields with the block zeroed: a device without the program extension.

```
01020304050607081112131415161718212223242526272831323334010101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000901e
```

### A.5 `DEVICE_INFO`

`envelope`, the three geometry fields and the `pixel` capability, in that order
(47 bytes):

```
envelope=32768 strips=4 leds=1024 bpp=3 pixel
```

```
08656e76656c6f7065053332373638067374726970730134046c656473043130323403627070013305706978656c00
```

The same device with the `pts` capability appended (`03 707473 00`) (52 bytes):

```
envelope=32768 strips=4 leds=1024 bpp=3 pixel pts
```

```
08656e76656c6f7065053332373638067374726970730134046c656473043130323403627070013305706978656c000370747300
```

Field order is not significant on the wire (Section 5.3.3); the order above is
that of a deterministic encoder, and a decoder MUST accept any order. Private
(`x-`) fields are excluded from these vectors because their position is an
encoder's choice; an implementation tests them with a decode-only case showing
that a private field reaches the caller intact.

### A.6 `SET_BRIGHTNESS`, `SET_MODE` and the `GET_MODE` answer

| Message | Inputs | Bytes |
| --- | --- | --- |
| `SET_BRIGHTNESS` payload | 128 | `80` |
| `SET_MODE` payload | `PIXEL` | `01` |
| `GET_MODE` ACK `detail` | mode `PIXEL`, output enabled | `0101` |

> **Note** — the whole `GET_MODE` ACK payload for a command whose `MessageNum`
> is `0x0102030405060708`, from a device in `PIXEL` mode with its output on,
> laid out as in Section 5.1:
>
> ```
>    0  orig_kind          09                 GET_MODE (0x09)
>    1  status             00                 0 = OK
>    2  rsv                0000
>    4  orig_message_num   0102030405060708   the command's MessageNum
>   12  detail_len         0002               2
>   14  detail             0101               mode 01 = PIXEL, output_enabled 01
> ```
>
> As one string, 16 bytes: `09000000010203040506070800020101`.

## Appendix B. A worked session (informative)

A short session taken apart, using the vectors of Appendix A. Each listing shows
the offset of a field in the payload, its name, its bytes in hexadecimal, and
what they mean. The payloads are what this protocol hands to the message layer;
the header, padding and encryption that [SN-MSG] adds are not shown. The sections
reuse the message numbers of the vectors and are not one numbered sequence:
[SN-MSG] sections 5.1 and 5.2 require the numbers within a session to increase
strictly, which separate sections of this appendix do not follow.

### B.1 The controller asks what the device is

The first command of the session is `GET_DEVICE_INFO`, kind `0x0A`, with an
empty payload. The device answers with `DEVICE_INFO`, kind `0x84`, and then an
ACK. The `DEVICE_INFO` payload of vector A.5 is 47 bytes, a run of
name/value pairs with a length byte before each name and each value:

```
   0  08 "envelope"  05 "32768"
  15  06 "strips"    01 "4"
  24  04 "leds"      04 "1024"
  34  03 "bpp"       01 "3"
  40  05 "pixel"     00 (empty: a capability)
```

Reading it from the start: a name of 8 bytes, `envelope`, then a value of 5
bytes, `32768`; a name of 6 bytes, `strips`, then a value of 1 byte, `4`; and so
on to the end of the payload. The last name has a value of length 0. It is a
capability: the device accepts pixel frames (`pixel`). There is no `pts`, so
this device shows frames when they arrive and ignores their timestamps.

### B.2 The controller works out how large a frame may be

From those values (Section 6.2):

```
capacity = strips × leds × 4      = 4 × 1024 × 4  = 16384
envelope − 28 − 16                = 32768 − 28 − 16 = 32724
limit    = the smaller of the two                  = 16384
```

The limit is 16384 bytes, 4096 pixels: here the geometry binds, and a whole
picture fits in one frame. Note what was *not* used. `bpp` is 3 — these are RGB
strips — but a frame is still 16384 bytes, four per pixel, and not 12288.

On a device with the same receive limit and 32768 LEDs the answer changes:
`capacity` would be 131072 and the limit 32724, set by `envelope`.
A controller that sent a full 131072-byte frame to that device would lose
its session.

### B.3 The controller sends a frame

Vector A.1 is a `PIXEL_FRAME` carrying one pixel. A real frame differs only in
having more pixels after the header.

```
   0  frame_number       0000000000000001                  1
   8  not_before         17979cfe3d85cd15                  1700000000123456789 ns
  16  not_after          17979cfe3e1e6395                  1700000000133456789 ns
  24  pixel_byte_length  00000004                          4
  28  pixel 0            01020304                          R=01 G=02 B=03 W=04
```

`pixel_byte_length` is 4 and exactly 4 bytes follow it, as Section 6.1 requires.
The two timestamps are 10 ms apart: the sender allowed a 10 ms window. A device
that advertises `pts` and receives this frame before `not_before` holds it until
then; one that receives it between the two instants shows it at once; one that
receives it after `not_after` discards it. The device of B.1 does not advertise
`pts`, so it shows the frame on arrival.

Nothing comes back. `PIXEL_FRAME` is never answered.

### B.4 A command is refused

Vector A.3 is the ACK for a command that the device refused. The command was the
controller's message number `0x0102030405060708`.

```
   0  orig_kind          02                                SET_FPS (0x02)
   1  status             01                                1 = ERR_INVALID_ARG
   2  rsv                0000
   4  orig_message_num   0102030405060708                  the command's MessageNum
  12  detail_len         0016                              22
  14  detail             667073206f7574206f662072616e6765  "fps out of range 1-255"
                         20312d323535
```

The controller is waiting for an ACK whose `orig_message_num` is the number of
the command it sent; this one matches, so this is its answer. `status` is not 0,
so the command failed, and `detail` says why in words. Had `orig_message_num`
been any other value, the controller would have skipped this ACK and kept
reading.

### B.5 The controller names a time server

The first vector of A.2 tells a device to take its time from `10.0.0.5`, port
123. It would be sent only to a device that advertises `pts`, which the device
of B.1 does not; the vector is shown here for its layout.

```
   0  addr_type          04                                4 = IPv4
   1  len                04                                4
   2  port               007b                              123
   4  address            0a000005                          10.0.0.5
```

`len` says the address is 4 bytes, which is the only length an IPv4 address may
have. This command, too, is never answered.

### B.6 The controller reads the device's status

`GET_STATUS`, kind `0x08`, has an empty payload and is answered with `STATUS`
and then an ACK. Vector A.4.2 is a `STATUS` payload, always 78 bytes. The vector
fills most counters with recognisable byte patterns, so that a field read from
the wrong offset is obvious.

```
   0  frames             0102030405060708
   8  commands           1112131415161718
  16  dropped            2122232425262728
  24  refresh_errors     31323334
  28  mode               01                                1 = PIXEL
  29  connected          01
  30  output_enabled     01
  31  rsv                00
  32  ext                00 x 44                           the extension block, zero (Section 9)
  76  brightness         90                                144 of 255
  77  target_fps         1e                                30
```

Bytes 32 to 75 are the extension block; a device without the program extension
sends them as zero, as this one does. `mode` and `brightness` are the core's,
and every device fills them.

### B.7 The controller sets and reads the mode

The controller puts the device in `PIXEL` mode with `SET_MODE`, kind `0x04`,
and then asks which mode the device is in with `GET_MODE`, kind `0x09`. The
values are those of A.6. The `SET_MODE` payload is one byte:

```
   0  mode               01                                1 = PIXEL
```

The device answers with an ACK (`0x80`) whose `orig_kind` is `0x04`, status `OK` and no
detail:

```
   0  orig_kind          04                                SET_MODE (0x04)
   1  status             00                                0 = OK
   2  rsv                0000
   4  orig_message_num   (8 bytes)                         the SET_MODE's MessageNum
  12  detail_len         0000                              0
```

`GET_MODE` has an empty payload and no typed response: the answer is one ACK
whose `detail` is binary, two bytes, `[u8 mode][u8 output_enabled]`. For a
`GET_MODE` whose `MessageNum` is `0x0102030405060708`, and a device in `PIXEL`
mode with its output on, the whole ACK payload is the 16 bytes of the note after
A.6:

```
   0  orig_kind          09                                GET_MODE (0x09)
   1  status             00                                0 = OK
   2  rsv                0000
   4  orig_message_num   0102030405060708                  the command's MessageNum
  12  detail_len         0002                              2
  14  detail             0101                              mode 1 = PIXEL, output on
```

## Appendix C. Behaviour this version does not define (informative)

The following are not specified by this version. A controller should not rely on
any particular behaviour, and an implementer should expect a later revision to
define them.

**Core**

- **A limit on response size.** A device advertises what it can receive; a
  controller has no way to advertise the same.
- **`DEVICE_INFO` names outside the stated grammar.** The sender's rule is
  stated; a receiver's action on a name that breaks it is not.
- **What the configured frame rate changes in `PIXEL` mode.** `SET_FPS` sets the
  rate `STATUS` reports as `target_fps`; this version does not say whether it
  paces the output or limits the frames a device presents.
- **Frames received while the output is off.** After `OFF`, this version does
  not say whether a device discards pixel frames, or keeps the latest and shows
  it after `ON`.
- **Persistence of brightness, frame rate and on/off.** This version does not say
  whether the values set by `SET_BRIGHTNESS`, `SET_FPS`, `ON` and `OFF` last
  beyond the session, or beyond a restart.

