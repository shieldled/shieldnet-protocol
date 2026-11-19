# ShieldLED Device Protocol — design notes

> **Design notes — informative.** The specification is
> [`spec/application.md`](../spec/application.md) (ShieldLED Device Protocol).
> These notes are the reasoning behind it: what each rule is for, and what was
> considered and rejected. Where the two differ, the specification governs.
> Where these notes say a rule is required, the specification is what requires
> it, and `spec/application.md` states the rule in full. Section numbers below
> are that document's.

> **The optional program extension is BlackShield's and is specified
> separately;** the specification (`spec/application.md` Section 9) reserves its
> values. These notes cover the core only.
>
> **Pixel output is optional too.** A device accepts pixel frames only if it
> advertises `pixel`, and `strips`, `leds` and `bpp` are required in
> `DEVICE_INFO` only then; a device may drive something other than LEDs.

These notes explain the application message layer spoken with the ShieldLED
runtime. It rides on the ShieldNet message layer
([`message-layer.md`](message-layer.md)), which in turn rides
on the transport ([`transport.md`](transport.md)): each
application message is one message-layer data message whose `MessageType` low
byte is the command/response **kind** (`spec/application.md` Section 3.1). The
specification has a receiver ignore bits 8–30 of `MessageType` and a sender
transmit them as zero, for the reason R4 gives for every other reserved field:
each is an extension slot only if today's receivers do not reject it.

## Command kinds (client → device)

The kinds and their values are in `spec/application.md` Section 10.1.

### Numbering

The specification has a receiver dispatch on the exact kind, never on a range or
a bit. A range boundary is an aid to whoever reads a hex dump or adds a command;
it is not a classification a receiver may act on, and nothing in a conforming
receiver tests it. A kind's numeric neighbours say nothing about whether
it mutates, whether it answers, or what it costs — R1 and R2 govern all of that
explicitly.

Values are dense within each range. Gaps were considered and rejected: dispatch
is a switch on named constants, so a gap buys no table space, and an unallocated
block is a decision deferred rather than made. A new command takes the next
unassigned value in its range. The values reserved for the program extension are
skipped and never reassigned, and a range that fills is extended with unassigned
values below `0x60`, so the allocation rule never lands on a reserved value
(`spec/application.md` Section 10.1).

### Compression category

The message layer permits compression by payload shape and requires this layer
to assign each of its kinds a category; the assignment is in
`spec/application.md` Section 3.5.

The specification recommends that a sender compress `PIXEL_FRAME` where it shrinks the
payload. Frames are the highest-volume traffic this protocol carries and LED
content is full of uniform and repeating regions, so the saving is large and
lands on the one path where link capacity actually binds; the message layer
permits it, and its residual — roughly how uniform the scene is — is already
visible to anyone who can see the lights. A frame that does not compress is sent
plain, so the rule costs nothing when it does not pay.

Control and configuration messages, in both directions, are additionally
**padded** to a size class. Compression and padding are mutually exclusive on
one message, so each message is compressed or padded, never both: a message
whose size is worth hiding is padded, and one whose bandwidth matters more than
its size is compressed. This protocol's core has no kind that is both large and
worth hiding, which is why no category needs a choice between the two.

Responses are all control: no device→controller message in this layer is a bulk
upload, so a conforming device never sets `FlagCompressed`. A controller still
handles a compressed one if it arrives, because that is a receiver rule and not
a prediction about any particular device.

### `PIXEL_FRAME`

The frame's layout, its discard list and its vector are in
`spec/application.md` Sections 6.1–6.2 and Appendix A.1. Two points of reasoning
stay here.

The wire stride is fixed at 4 bytes per pixel (R, G, B, W) whatever the strip
is. On an RGB strip the device drops the fourth byte on ingest, so a frame is
sized `strips × leds × 4` for every device and one controller encoding serves
both strip types. `DEVICE_INFO`'s `bpp` therefore describes the **strip**, for
colour handling; it is not the wire stride and must not be used to size a frame.
Sizing from it would make an RGB unit reject every frame: `strips × leds × 3` is
neither a whole number of wire pixels nor the length the controller sent.

The geometry is not the only bound. The device's **payload envelope** is a
separate and usually smaller one: a device reads into a fixed buffer and refuses
any header whose `Size` exceeds it. That refusal consumes the header without its
body, so it desynchronises the stream and drops the session
([`message-layer.md`](message-layer.md) §1.2) rather than
dropping one frame; a sender that exceeds it gets a reconnect loop, not a lost
frame. The envelope is advertised on the wire, in `DEVICE_INFO`'s `envelope`
field, so a controller need not know it out of band or carry it as a per-model
constant, and a controller that assumes a geometry the device did not advertise
is the failure this field exists to prevent. The device's own slack beyond the
envelope is not a sender's to spend; deriving the limit is the controller's job
(`spec/application.md` Section 6.2).

### `NTP_SERVER`

The message is optional in both directions and carries an address, not a time.
Its layout, address types and vectors are in `spec/application.md` Section 4.2
and Appendix A.2. A device that knows the kind never answers it, so that a device
with no time-server support at all behaves the same as one that has it; an
older device, which cannot know the kind is response-free, answers
`ERR_UNKNOWN_KIND` (R1), which is why a controller sends `NTP_SERVER` only to a
device that advertises `pts`.

## Frame timing

Several devices that together form one display must show one image. Nothing in
the protocol carries a clock; every device and every controller keeps its own
with NTP, and each `PIXEL_FRAME` says when it may be shown: `not_before` and
`not_after`, both in its header. A device that implements these rules advertises
the `pts` capability. The rules are in `spec/application.md` Sections 6.3–6.6;
this section keeps their reasons.

**Showing a frame takes time.** An LED strip refresh takes most of a frame
period and cannot be interrupted; the specification therefore defines what
presenting a frame means while one is in progress.

**Why a late frame is discarded.** An LED refresh that takes most of a frame
period leaves a few milliseconds of slack per frame. A frame shown late pushes
back every frame behind it, and they catch up a little at a time. Discarding it
costs that panel one repeated image and leaves the next frame on time. The
output is left as it is rather than blanked: a dark panel is far more visible
than a repeated image, and blanking is itself a refresh that would delay the
next frame. (The timestamps travel inside the encrypted, compressed payload, so
the frame is decrypted and decompressed before the check; what a discard saves
is the pixel processing and the refresh.)

**Why the window is the sender's.** How late is too late depends on the frame
rate, which the sender knows and the device does not. The sender sets
`not_after = not_before + window`. A sender that wants no discarding sends
`not_after = 0`.

**Why a panel must not freeze.** With a wrong clock, or a lead shorter than the
link's delay, every frame is past its `not_after` and discarding alone would
leave the panel on one image for ever. After three discards in a row the device
presents such frames on arrival until one arrives in time.

**How failures degrade.** A restarted device whose clock is not yet set, a time
server that is unreachable, a wrong clock, a lead shorter than the link's
delay: each ends with that device presenting on arrival. A lead set too long
ends in "shown when the next frame arrives". Nothing latches and nothing has to
be recovered: a transient cause clears by itself, a standing one lasts until it
is fixed.

That device is then out of step with its neighbours, and this is the cost: a
panel presenting on arrival runs about one lead — a whole frame, at the
recommended lead — ahead of panels that hold, for as long as it lasts. A device
that stays unsynced is a fault to fix; the sender cannot see it. A wall with a
device that cannot keep time is driven with both timestamps zero.

**Why the sender repeats its last frame.** A device that discarded the last
frame of a stream would otherwise stay one image behind its neighbours until the
stream resumes, so a sender that stops sends that frame once more with both
timestamps zero.

**Why the clock is polled often.** At 20 ppm a clock drifts 1.2 ms a minute, so
a receiver polls its time server at least once a minute. On a network with
variable delay the offset is better taken from the exchange with the smallest
round-trip delay among the most recent ones, with a site-local server polled
every few seconds. NTP is not authenticated, so the clock is used for
presentation only and never feeds a security decision.

**Why `NTP_SERVER` names an address.** A controller that can resolve a name
sends the address instead, because a device may have no resolver, or none that
knows the name; a name should map to exactly one address.

### The numbers

| parameter | value | rationale |
|---|---|---|
| held frames | **1** | no new buffer on a small device |
| discards before the fallback | **3** | a stall delivers a few late frames at once and should not trip it; a wrong clock trips it within a tenth of a second |
| hold limit (receiver) | `not_before` at most **1 s** after arrival | a frame is never stuck behind a wrong clock |
| maximum lead (sender) | **1 s** | the same bound, seen from the sender |
| recommended lead | **one frame period** | the most a receiver holding one frame can use |
| recommended window | **10 ms** at 30 fps | late enough to forgive jitter, early enough that the next frame is not delayed |
| clock considered synced | NTP sync within **5 minutes** | about 6 ms of drift at 20 ppm; an outage shorter than that goes unnoticed |
| accuracy | **≤ 2 ms** recommended | small against the frame period |

The `pts` capability is tested by the presence of its name, not by an empty
value, because a capability may gain a value later (`spec/application.md`
Section 6.5).

## Response kinds (device → client)

The response kinds are in `spec/application.md` Section 10.2; the layouts of
`ACK`, `STATUS` and `DEVICE_INFO` are in Sections 5.1–5.3 and their vectors in
Appendix A.

### ACK

A detail longer than the limit is clamped, not refused: `detail_len` carries the
clamped length, and the diagnostic is truncated rather than the response lost.

### STATUS

`target_fps` is the **configured** frame rate set by `SET_FPS`, read live from
the device rather than from boot-time configuration, and `brightness` is
likewise the live value set by `SET_BRIGHTNESS`, not the boot-time default.
Neither is in the discovery record, which is written once at boot and never
updated. The payload is a single fixed layout: a shorter payload is malformed,
not an older peer, and there is no tier to fall back to. A later revision may add
a tier above it under R6.

### DEVICE_INFO

The device's authenticated self-description is the protocol's only self-describing
payload: a sequence of `[u8 namelen][name][u8 vallen][value]` pairs, both being
plain text. There is no count prefix; a receiver reads pairs until the payload
ends. Unlike every other response, `DEVICE_INFO`'s rules — not its byte offsets —
are the specification, because names and values are both text and the wire
carries no fixed layout to pin. A capability is a field with an empty value, so
there is no separate `caps` list inside `DEVICE_INFO` to keep consistent with
anything.

The reasons behind the ranges (`spec/application.md` Sections 5.3.1–5.3.2).
The ranges are stated explicitly because a receiver must reject outside them,
and two receivers cannot each invent their own:

- **`envelope`** has a lower bound of 80: the `Size` of a message padded to the
  smallest size class (64 bytes plus the message layer's 16-byte AEAD tag). The
  first command of a session is padded and is sent before the controller has
  read `envelope`, so a device that could not take 80 would lose every session
  at its first message. The bound was once 45 — one more than `PIXEL_FRAME`'s
  28-byte header plus the tag — which guaranteed a non-zero frame limit and
  nothing else. The upper bound is the message layer's own ceiling
  (`MaxPayloadSize`, message layer §7); nothing on this wire can exceed it.
- **`strips`** and **`leds`** start at 1: neither a device with no strips nor a
  strip with no LEDs is representable hardware.
- **`bpp`** is an enum, not an open decimal range, governed by R5: a value the
  specification does not define is a protocol error, never a value to guess at or
  round. Adding a third pixel format is a specification change, the same as any
  other enum.
- **The product is bounded too.** `strips × leds × bpp` can reach roughly
  1.7×10¹⁰ at the field maxima, which overflows a 32-bit integer. The
  specification requires a receiver to reject a geometry whose capacity exceeds
  16777216 bytes, and to compute that product and `strips × leds × 4` in a type
  that cannot overflow (Section 5.3.2) — the same ceiling as `envelope`'s, since a capacity larger than the largest
  possible envelope can never be the binding term in the frame limit.

Geometry is carried as strips × leds × bpp, not a single byte count, because it
serves different consumers (frame limits, and the shape of the output), so it is
a triple.

A private (`x-`) field carrying binary data encodes it as hex or base64 text
inside the value — the same trade TXT records, HTTP headers and JSON make, and
the reason there is no separate type byte.

Reasons for the rules of Section 5.3.3:

- **Unknown names are skipped.** An unknown name is the extension mechanism, so a
  receiver skips `vallen` bytes and goes on to the next pair.
- **A name's type is fixed; its length is not.** `bpp` is a decimal forever. To
  change what a name *means* or how it is read, mint a different name — never
  redefine one, because a reader that predates the change cannot tell. One
  exception is the growth path: a field may go from empty to valued (a
  capability gaining a parameter), because every reader that predates it tested
  only for presence, and presence is unchanged. The reverse — valued to empty, or
  one value type to another — is not permitted.
- **Order is not significant, and a repeated name takes its last value.** A
  receiver reads pairs in sequence to the end of the payload and does not index
  by position. Last value wins because that is how the discovery record's own
  parser treats a repeated key, so the two carriers agree on duplicates as well
  as on grammar.
- **Bounded.** A client buffers the whole payload before parsing it. Field
  lengths are capped at 255 by the one-byte length prefixes, but the field
  *count* is not, so the specification bounds both the payload and the count.

The vectors in Appendix A.5 contain only the known, fixed-order fields. Field
order is not significant on the wire; the fixed order is the encoder being
deterministic. A vendor (`x-`) field is deliberately excluded from the shared
vectors, because its position after the known fields is an encoder choice rather
than something every implementation needs to agree on byte for byte; it is
exercised instead by a decode-only test that proves a vendor field reaches the
caller intact.

`DEVICE_INFO` is authoritative for capabilities; the discovery record's `caps`
entry (R7) is a pre-connect selection hint only.

## Query framing

For a query (`GET_*`) the device sends the typed response first, then the ACK,
and the client correlates by `orig_message_num`, not by message order
(`spec/application.md` Sections 3.3–3.4). An ACK for some other command is
skipped, not an error: it answers an earlier command whose reply was never read,
or a response-free kind sent to a device too old to know it is one (R1).

The first command of a session rides the promoting datagram: the transport needs
a first message to complete admission, and `GET_DEVICE_INFO` is the natural one,
since a controller must read it before sending a frame anyway.

## Forward compatibility

This layer has no version field and no capability handshake. It does not need
one: every rule below defines what a receiver does with something it does not
understand, so a sender may add to the protocol without knowing what the peer
supports. Both incumbents work this way — Art-Net requires nodes to ignore
unrecognised opcodes, and ANSI E1.31 §6.2.4.1, §6.5 and §6.7.2 each state per
field what a receiver that lacks the feature must do.

The rules apply to both directions, because both ends are receivers. An
implementation that enforces them on one side only is worse than one that
enforces neither: extended messages would be accepted in testing and rejected on
the peer. The rules are in `spec/application.md` Sections 7.1–7.8.

### R1 — Unknown command kinds

An `ERR_UNKNOWN_KIND` means the peer is older, not broken. Probing with an
unrecognised kind is only usable for commands that are harmless when they *do*
land.

Not every ShieldNet receiver implements this command layer. A peer may use the
transport directly and never dispatch on `MessageType`; such a receiver answers
nothing, to any command. A probe therefore has **three** outcomes, not two:

- **OK** — the kind is recognised and was accepted.
- **`ERR_UNKNOWN_KIND`** — the kind is not recognised; the peer is older.
- **A read timeout, after one command timeout** — the peer answered nothing. It
  is indistinguishable from a dead or unreachable device, and a timeout is not
  support.

R1 is consequently not a general capability mechanism. For anything a controller
must know before acting, the authoritative source is R7's `DEVICE_INFO`, read
over the authenticated session.

### R3 — Trailing payload bytes

Three limits, each of them necessary:

- **Longer only.** A payload *shorter* than the known layout remains an error.
  Accepting short payloads would turn a truncation bug into a silently
  half-applied command.
- **Not inside a repeated element.** Appending to a payload's *tail* is safe;
  appending to an *entry* of a repeated array is not, because it changes the
  stride and silently misaligns every later entry for an older receiver. A new
  per-element field is sent as a second array after the first.
- **Not where a length is declared.** `PIXEL_FRAME` carries `pixel_byte_length`,
  which must still match the remaining payload exactly — that check validates
  geometry, not framing. Length-declared payloads validate exactly; only
  fixed-layout payloads extend by appending.

`NTP_SERVER`'s address carries a length, `len`, but it is **counted, not
length-declared**: `len` bounds an array whose element size is fixed, so a
receiver requires *at least* the bytes those elements occupy and ignores anything
after them. The distinction is which side the field constrains — a count says how
much to read, a declared length says how much there is.

### R4 — Reserved fields

Zero on send and ignored on receive makes each existing `rsv` a claimable
extension slot later.

### R5 — Unknown enum values

An unrecognised ACK status is **not** success: only `0` is `OK`. New error codes
are therefore free to add; new *success* codes are not, so success stays unary.
`NTP_SERVER` is response-free, so an `addr_type` a device does not know is
ignored, not answered.

Two shapes this rule exists to forbid, both of which read as harmless:

- **A two-valued enum decoded as a boolean.** `SET_MODE` carries a mode byte,
  and `mode != 0` looks equivalent to `mode == 1`. It is not: it silently
  accepts every value a future revision might define, answers `OK`, and enters
  PIXEL. That single line makes `mode` permanently unextensible, because no
  controller can ever tell a device that understands a new mode from one that
  does not.
- **A `default:` branch that returns a known value.** A `String()` or display
  helper that falls back to the zero-valued name turns an unrecognised value
  into a plausible wrong one at the point a human reads it. Render it as
  unknown, carrying the raw value.

*Where this is enforced:* on the device, wherever the command is decoded. On the
client, in the codec that decodes the payload; a layer that only frames
messages cannot enforce it.

### R7 — Capability advertisement

R1–R6 cover features whose absence is survivable: a receiver that ignores a new
optional field still behaves correctly, just without the enhancement. They do not
cover features whose absence changes what a **controller** must do — where
silently degrading would leave the controller believing something is true that is
not.

For those, the device advertises support in **two** places: the discovery
record's `caps` list, available before a session exists so a controller can
select a device to dial, and `DEVICE_INFO`'s empty-valued fields, fetched over an
authenticated session and authoritative. The discovery list is a **selection
hint only**: discovery is not authenticated — the PSK handshake authenticates the
*session*, not the advertisement — so a spoofed record could otherwise talk a
controller into believing a capability, or a payload limit, that is not real.

**The disagreement rule is one line: `DEVICE_INFO` always wins.** The discovery
list may legitimately be a strict subset of `DEVICE_INFO`'s capabilities — a
single mDNS TXT string is capped at 255 bytes, so a long `caps=` overflows long
before the record as a whole does, and a device with many capabilities can still
advertise enough to be selectable while `DEVICE_INFO` carries the whole truth.

A private capability uses the `x-` name prefix; there is no registry and nothing
to coordinate. The specification recommends that the part after `x-` begin with
its author's name, as in `x-acme-servo` (Section 7.8), so two authors are
unlikely to collide.

The distinction — advertise vs. degrade silently — is the design judgement this
rule exists to make explicit, not a formality: advertise when a controller must
change its behaviour, degrade silently otherwise. A capability flag that every
controller must check is a tax; a silent degradation that hides a correctness
difference is a bug.

### Discovery record

The discovery record is specified in `spec/application.md` Section 8; the
specification still reserves `_sled_x1._udp`. Everything in it is unauthenticated
and is a hint for choosing what to dial (R7).

### What this does not cover

The layers beneath this one — the ShieldNet message layer
([`message-layer.md`](message-layer.md)) and the transport
([`transport.md`](transport.md)) — version independently of
this one, and the transport carries its own version byte with no compatibility
story. These rules govern the application layer only.

## Conformance

The vectors in `spec/application.md` Appendix A are authoritative, not any test
file. Every byte-exact vector this layer depends on is published inline, in the
section for the payload it pins, as raw hex plus the exact inputs that produce
it, so it can be pasted directly into a test in any language. A conformance test
asserts these published vectors; it does not originate them. A vector that
disagrees between the specification and an implementation's test means the
implementation is wrong. `DEVICE_INFO`'s vector covers only the known,
fixed-order fields; field order is not significant on the wire, so vendor (`x-`)
fields are exercised by a separate decode test.
