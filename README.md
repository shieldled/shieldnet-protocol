# ShieldNet protocol documentation

The single home for the ShieldNet protocol: the specification, its test vectors,
and the reasoning and measurements behind it.

## Why a new protocol?

The established lighting-over-IP protocols carry DMX universes over UDP. They
were designed for a closed show network run by people who trust each other, and
on such a network they work well. On any other network they leave three gaps:

- **Anyone on the network can drive the lights.** Packets are not
  authenticated, and the sender's address is easy to forge, so any host that can
  reach a fixture can take it over, replay a recorded show or blank it.
  Their contents travel in the clear.
- **Delivery is best effort.** A lost packet is gone, and nothing tells the
  sender. A command that must arrive, a configuration change for example, has
  no way to confirm that it did.
- **The data model is a 512-channel universe.** A pixel display is cut into
  universes and reassembled on the device. Several devices showing one image
  need an extra synchronisation scheme on top, and a device can say little
  about what it is or what it can do.

ShieldNet is built for the network those protocols assume away: shared, untrusted,
and reachable by people who should not be controlling the device.

- **Only key holders get in.** A client proves knowledge of a pre-shared key
  before the device does anything expensive. Each device holds a key derived for
  it alone, so extracting one device's key opens that device and no other.
- **Every datagram is encrypted and authenticated**, with a sequence number that
  never repeats, so recorded traffic cannot be replayed.
- **The device is hard to knock over.** It keeps no state for a peer that has not
  proved itself, answers a forged source address with fewer bytes than it
  received, and stays silent towards anything it refuses. A recorded handshake
  never displaces a live session.
- **Delivery is reliable and ordered.** Every command except pixel frames and
  the time-server setting is acknowledged, and a refused command says why.
- **Frames are whole and timed.** A pixel frame is one message, compressed where
  that helps, rather than a set of universes. Each frame carries the window in
  which it may be shown, so devices that keep their clocks with NTP present the
  same image together, and a device whose clock is wrong falls back to showing
  frames on arrival instead of freezing.
- **The device describes itself**: its geometry, its limits and its
  capabilities, over the authenticated session. It is found by DNS-SD over
  multicast DNS.
- **Both sides can be extended without breaking the other.** Forward-compatibility
  rules (`spec/application.md` Section 7) fix how an older peer treats a newer
  one.
- **It fits a small embedded controller**, with a fixed memory budget and a
  bounded cost for every input it can receive.

It gives up things those protocols have. A session is unicast between one
controller and one device, so there is no multicast fan-out, and a device has a
single session at a time. Devices must be provisioned with a key before use.

### Use cases

- LED installations on networks the operator does not control: retail, venues,
  hospitality, building facades, public spaces.
- Displays made of several devices that must show one image in step: video walls,
  pixel ceilings, large signs.
- Permanent installations that must keep running unattended and survive hostile
  traffic on the network.
- Embedded devices that drive something other than LEDs: pixel output is an
  optional capability, and the command, status and self-description framework
  stands without it.

## The specification

Three documents, one per layer, in [`spec/`](spec/). **These are the normative
text and the authoritative source for any implementation.** Read them bottom-up;
each cites the one below rather than restating it.

| document | layer | scope |
| --- | --- | --- |
| [`spec/transport.md`](spec/transport.md) — *ShieldNet Transport Protocol* | **transport** | provisioning and the key schedule; the UDP admission exchange (INIT/RETRY/FINISH/ADMIT); the authenticated envelope around every KCP datagram; session lifecycle on the device |
| [`spec/message-layer.md`](spec/message-layer.md) — *ShieldNet Message Layer* | **message layer** | the length-prefixed, AEAD-sealed messages inside a session: header, nonce, message counter, compression and padding, how a receiver treats a message it cannot accept |
| [`spec/application.md`](spec/application.md) — *ShieldLED Device Protocol* | **application** | the ShieldLED command/response protocol. **Core**: pixel frames and their timing (optional, `pixel` capability), output control, status and device description, extensibility rules, discovery. **Program extension**: reserved values only (section 9); the extension is BlackShield's and specified separately |

Each opens with a plain-language walkthrough of how its layer works, explains the
reason beside any rule whose purpose is not obvious, and ends with its
conformance requirements, security considerations and references, followed by
appendices with its test vectors and a worked example taken apart byte by byte.

### Rendered copies

`make` renders the three documents to standalone HTML and PDF in `dist/`
(`make html` needs Python 3 with `markdown-it-py`; `make pdf` also needs Chrome
or Chromium). Set `REV` to the release tag when cutting a release, so the footer
and the links back to this repository name it: `make REV=v1.0.0`.
`make vectors` runs both generators and compares their output with the checked-in
JSON; `make clean` removes `dist/`.

## Design notes

The reasoning behind the specification: what each rule is for, what was
considered and rejected, and the threat model. **Informative.** Where they and
the specification differ, the specification governs.

| document | what it holds |
| --- | --- |
| [`design/transport.md`](design/transport.md) | transport design: every mechanism with the attack it stops, the device's concurrency design (§10), resource budget (§11), per-input cost (§12) |
| [`design/threat-model.md`](design/threat-model.md) | §14 of the transport design, split out: the threat matrix, what is closed, what is merely bounded, the residuals |
| [`design/message-layer.md`](design/message-layer.md) | message-layer design |
| [`design/application.md`](design/application.md) | ShieldLED Device Protocol design: the rationale for frame timing and for the forward-compatibility rules R1–R7 |

## Test vectors

Byte-exact, generated independently of any implementation, and the source of
truth for every implementation. An implementation's tests assert them. Each
specification also carries its vectors in its Appendix A.

| file | pins |
| --- | --- |
| [`vectors/shieldnet-v1-vectors.json`](vectors/shieldnet-v1-vectors.json) | `spec/transport.md` Appendix A: key schedule, the four admission messages, wire rejection cases, source classification, envelope, replay script, sequence reconstruction. Generator: [`vectors/gen_vectors.py`](vectors/gen_vectors.py) |
| [`vectors/shieldnet-msglayer-vectors.json`](vectors/shieldnet-msglayer-vectors.json) | `spec/message-layer.md` Appendix A: plain, padded and compressed frames. Generator: [`vectors/gen_msglayer_vectors.py`](vectors/gen_msglayer_vectors.py) |
| Appendix A of [`spec/application.md`](spec/application.md) | every ShieldLED Device Protocol payload vector, inline |

Both generators need Python 3 and the `cryptography` package, and reproduce their
JSON byte for byte.

## Which specification owns a rule

Each rule is stated **once**. If you find one stated twice, that is a defect,
independent of whether the two statements currently agree.

- Wire layouts, the key schedule, admission, the envelope, replay over
  `seq_full`, the send-path bound (`SEND_QUEUE_MAX`, 12.5) and the receive-window buffering
  rule (§13 item 5) —
  [`spec/transport.md`](spec/transport.md).
- KCP stream mode, the message header and its AAD, the `MessageNum` rule, header
  validation, pre-read bounds, and the compression and padding rules and
  categories (§6) — [`spec/message-layer.md`](spec/message-layer.md).
- Command kinds and each kind's compression and padding category (§3.5),
  payload layouts, ACK codes, payload vectors, forward compatibility, the
  discovery record — [`spec/application.md`](spec/application.md).

## Protocol version

This protocol is **version 1** and its wire version octet is `0x01`. It is the
only version that has been assigned; there is no negotiation and no compatibility
mode (`spec/transport.md` §15).

## License

Copyright (c) 2025-2026 BlackShield LDA. Licensed under the Apache License,
Version 2.0. See [`LICENSE`](LICENSE).
