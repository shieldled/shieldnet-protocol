# ShieldNet Transport Protocol

| | |
| --- | --- |
| Document | Specification of the ShieldNet transport: provisioning, the key schedule, admission and the authenticated envelope around every datagram |
| Protocol version | 1 |
| Status | Published |
| Copyright | © 2025-2026 BlackShield LDA. Apache License 2.0 |

## Abstract

ShieldNet is a pre-shared-key protocol for controlling a device over UDP on a
local network. This document specifies its transport: a four-message admission
exchange that authenticates a client and agrees session keys without letting an
unauthenticated peer create state on the device, and an authenticated envelope
around every KCP datagram of the session that follows. The messages carried
inside the session are specified in [SN-MSG].

## Status of this document

This is the authoritative specification of the ShieldNet transport, version 1.
An implementation conforms to the protocol by meeting the requirements of
section 16. Where this document and any implementation disagree, this document
governs.

The design rationale, the threat model and the resource analysis behind these
rules are in the design notes: [DESIGN]
([`../design/transport.md`](../design/transport.md)) and [THREAT]
([`../design/threat-model.md`](../design/threat-model.md)). They are
informative. Nothing in them adds to or relaxes a requirement stated here.

---

## 1. Introduction

### 1.1 Scope

This document specifies:

- the provisioning inputs and the key schedule;
- the admission exchange — INIT, RETRY, FINISH, ADMIT — and the procedures both
  parties follow;
- the envelope that authenticates every datagram of an admitted session, and its
  replay protection;
- the lifecycle of a session on the device.

It does not specify the messages exchanged inside a session ([SN-MSG]), nor any
application protocol above them.

### 1.2 Layering

```
application protocol        (for example [SLED])
ShieldNet message layer     [SN-MSG]        sealed, length-prefixed messages
KCP                         section 13       reliable ordered byte stream
ShieldNet envelope          section 11       per-datagram AEAD and replay window
ShieldNet admission         sections 8-10    INIT / RETRY / FINISH / ADMIT
UDP
```

Admission and the session share one UDP socket and one port on each side.

> **Note** — Section 12 is not a layer of its own: it is the session lifecycle
> on the device.

### 1.3 Roles

A **device** is the controlled party. It listens on a UDP port and holds at most
one admitted session at a time.

A **client** is the controlling party. It initiates admission and, once admitted,
owns the device's single session until another admission replaces it.

Every party that holds the pre-shared key is authorised to be a client. The
protocol does not distinguish one client from another.

### 1.4 How a session works

Read this section first. It describes one session from beginning to end in plain
terms; everything after it makes one of these steps precise.

**The setting.** A device is a small embedded controller driving something
physical. It sits on a local network where anyone can send it packets and forge
the sender's address. It has little memory and a slow processor. It must let an
authorised client in quickly, it must not be knocked over or locked up by anyone
else, and it cannot afford to remember anything about a peer that has not yet
proved itself. Every mechanism below follows from those constraints.

**The shared secret.** All authority comes from one 32-octet key, the PSK, held
by the clients. A device does not keep the PSK. It holds `k_dev`, a key derived
from the PSK and the device's own identifier, which a client re-derives whenever
it wants to talk to that device (section 3). Opening up one device therefore
yields a key that works for that device and no other.

**Step 1 — INIT: "I want to talk to device X."** The client sends a 256-octet
INIT carrying a random nonce and the identifier of the device it wants, with a
MAC showing that it knows the key (though it can be replayed). The device checks
the MAC — and then deliberately remembers nothing.

**Step 2 — RETRY: "show me you are really at that address."** Instead of keeping
state, the device answers with a *cookie*: a MAC, under a secret only the device
knows, over the address the INIT came from and the client's nonce. Only a sender
that actually receives packets at that address can return it, so a forged source
address gets nowhere unless the forger can also watch the traffic sent there.
RETRY also carries a counter, `admission_epoch`, that the client must echo, and
the address the device saw, so that the client can tell if its INIT was replayed
from somewhere else. RETRY is much smaller than INIT — 84 octets against 256 —
so a device never sends the victim of a forged address more octets than the
attacker spent.

**Step 3 — FINISH: "here is your cookie, and my half of a key exchange."** The
client echoes the cookie and the counter, adds a freshly generated X25519 public
key, and authenticates all of it with a second MAC. The device makes its inexpensive
tests first: is the cookie right for the address this came from? Is the counter
the current one? Is the MAC valid? Only then does it do the expensive part —
generate its own key pair and compute the shared secret. Without the key, the
most anyone can do is replay a FINISH they recorded, and the counter lets that
work once.

**Step 4 — ADMIT: "here is my half."** The device derives four session keys from
the shared secret, the long-term key and a transcript of everything exchanged.
It stores them in a small *pending record* — the first state it has created —
advances `admission_epoch` so that this FINISH can never be accepted again, and
replies with its public key and two authenticators. The client checks the cheap
authenticator first, then completes the key exchange and checks the second,
which only a device that really performed the exchange could have produced.

**Step 5 — the first datagram.** Both sides now hold the same keys, but the
device has *not* switched over: whatever session was running before is still
running. The client sends its first datagram of the new session, encrypted under
the new keys. When it arrives, decrypts and proves to be the start of the
client's stream, the device *promotes* the pending record: the new session
becomes *the* session and the old one is discarded. A handshake alone — which an
attacker might have recorded and replayed — never displaces a live session. Only
proof of possession of the new keys does.

**After that.** Every datagram in both directions is wrapped in an *envelope*:
encrypted and authenticated under a per-direction key, with a sequence number
that never repeats (section 11). Inside the envelope is KCP, which turns
datagrams into a reliable byte stream (section 13), and inside that stream are
the messages of [SN-MSG]. A session has no idle timeout and no keep-alive: a
client with nothing in progress may stay silent indefinitely and keeps its
device until another client is admitted in its place.

**What the device will not do.** It never answers a packet it rejects, never
resends a handshake message on its own, and never tells anyone why something
failed (section 9.4). To an outsider, a device that is refusing them looks
exactly like a device that is switched off. Implementers pay for that silence:
when admission fails, nothing on the wire says why. Section 4.3 and Appendix B
say where to look.

```
client                                         device
  INIT    (client_nonce, device_id,       ->   verify init_mac; create no state
           init_mac)
                                          <-   RETRY  (epoch_tag, cookie,
                                                       admission_epoch, device_id,
                                                       observed_source, retry_mac)
  FINISH  (client_nonce, epoch_tag,       ->   verify cookie and client_tag;
           cookie, admission_epoch,            X25519; install a pending record
           e_c, client_tag)
                                          <-   ADMIT  (admission_epoch, e_s,
                                                       admit_pre, admit_tag)
  envelope( KCP PUSH sn=0 )               ->   create the session; replace the
                                               previous one
```

### 1.5 How to read this document

- **To understand the protocol**, read section 1.4, then sections 9 and 10 (what
  each side does), then 11 and 12 (what happens once a session exists). Appendix
  C walks through one complete admission with real octets.
- **To implement it**, work through sections 3 to 13 in order. Each opens by
  saying what it is for, then states the rules. Section 16 lists what a client
  and a device must each implement, and Appendix A gives the test vectors that
  tell you when you have it right.
- **Rules and reasons.** A sentence is a requirement where it uses one of the
  capitalised key words of section 2.1, wherever in a section it appears. A
  block beginning **Why** or **Note** explains a rule; it is there so that the
  rule is not "simplified" away, and it adds no requirement of its own.
- **Security.** Section 17 says what the protocol protects, what it does not, and
  which rules everything depends on.

---

## 2. Conventions and terminology

### 2.1 Requirements language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in [RFC2119] and
[RFC8174] when, and only when, they appear in capitals.

Text in a block beginning **Why** or **Note** is explanation, not requirement.
So are every picture (a diagram drawn with lines, boxes or arrows), section 1.4,
and every appendix headed "(informative)". The layouts (tables and `||`
expressions), the formulas and the definitions are normative even where they use
no key word. Where one of them and a requirement appear to differ, the
requirement governs.

### 2.2 Notation

- `a || b` is the concatenation of octet strings.
- `x[n]` in a layout is a field of `n` octets. Offsets are zero-based from the
  first octet of the UDP payload.
- Multi-octet integers defined by this document are **big-endian**, on the wire
  and wherever they are an input to a cryptographic function. This does not
  extend into the KCP datagram, whose header is little-endian (section 13).
- `L("label")` is `uint8(length) || label`, the label in US-ASCII with no
  terminator.
- `HMAC(k, m)` is HMAC-SHA-256 [RFC2104], [RFC6234]. `HMAC/128(k, m)` is its
  leading 16 octets.
- `HKDF-Extract` and `HKDF-Expand` are as in [RFC5869] with SHA-256. A salt
  written `""` is 32 zero octets.
- `X25519` is as in [RFC7748].
- The envelope AEAD is ChaCha20-Poly1305 as in [RFC8439], with a 12-octet nonce
  and a 16-octet tag.

### 2.3 Terms

- **Tuple**: the source address and source port of a datagram, in the canonical
  form of section 7.1.
- **Admission attempt**: one run of the client procedure from INIT to either an
  established session or failure.
- **Pending record**: the state a device holds for an accepted FINISH until the
  session's first datagram arrives or the record expires.
- **Primary**: the device's one admitted session.
- **Promotion**: the step at which a pending record becomes the primary.
- **Control datagram**: an INIT, RETRY, FINISH or ADMIT.
- **Envelope datagram**: any other datagram on the socket.

> **Note** — terms used later. `admission_epoch` is the counter drawn at start-up
> (section 3.4); each value admits at most one FINISH (section 9.2 steps 4 and 7).
> The *canonical source* is the 18-octet encoding of an address and port (section
> 7.1), and `observed_source` is the address the device saw, in that encoding. In
> section 11.3 the tuple (defined above) is the peer's: on a device the client's
> address and port, on a client the device's. `hwm` is the high-water mark of a replay window, the highest
> sequence number accepted so far (section 11.4).

> **Note** — KCP in brief. Section 13 gives the rules; this is enough to read the
> rest of this document. A KCP *segment* is a 24-octet header and data. `conv`
> names the conversation. `cmd` says what the segment is: PUSH (data), ACK, or a
> window probe or its reply (WASK and WINS). `sn` numbers PUSH segments from 0, and
> `una` acknowledges every `sn` below it. *Stream mode* delivers one byte stream
> with no boundary between writes ([SN-MSG] section 3.1 explains why it is
> required). *No-delay mode* lowers KCP's minimum retransmission timeout and
> softens its back-off; Appendix B includes it in a set of values known to work,
> and section 13 item 4 leaves tuning local. Offsets in KCP layouts count from the
> start of the segment, not from the UDP payload as in section 2.2.

---

## 3. Provisioning and long-lived keys

Before any packet is exchanged, each side needs its long-term keys. This section
says what is installed where, and derives the two static keys that authenticate
the handshake messages.

### 3.1 Inputs

- **PSK**: exactly 32 octets of uniformly random secret, generated for this
  protocol and used for nothing else. One PSK defines a **domain**.
- **`device_id`**: 8 octets, unique within a domain.

### 3.2 Device key

```
prk_psk = HKDF-Extract(salt = "", ikm = PSK)
k_dev   = HKDF-Expand(prk_psk, L("shieldled/v1/device") || device_id, 32)
```

> **Note** — the `shieldled/v1/…` labels here and in section 6 are fixed wire
> values of this version, not placeholders; so is `MAGIC` (section 4.1).

A device holds `device_id` and `k_dev`. A client holds the PSK and derives
`k_dev` for the device it addresses.

**A device MUST NOT store the PSK**: not in persistent storage, and not in
memory except during the provisioning step described below. There are two ways
to provision a device:

1. **With `k_dev`.** Whatever provisions the device computes `k_dev` from the PSK
   and the device's `device_id` and installs that. The PSK never reaches the
   device. Automated provisioning SHOULD work this way.
2. **With the PSK, once.** A device MAY accept the PSK over a provisioning
   channel — an operator entering it at the device's own configuration
   interface, for example — solely in order to derive `k_dev`. It MUST derive
   and store `k_dev` at once and then erase every copy of the PSK it received,
   before it handles anything else. If it cannot complete the derivation, it
   MUST erase the PSK all the same and remain unprovisioned. It MUST NOT store,
   display, log or transmit the PSK.

Either way, what the device keeps is `k_dev` and nothing from which the PSK
could be recovered.

> **Why.** A device holds a key that is valid for itself only. Extracting it
> does not yield any other device's key, nor the ability to act as a client
> toward another device. The second way keeps that property for a device at
> rest and gives up a little at the moment of provisioning: the PSK passes
> through the device and through whatever carries it there (section 17.3).

### 3.3 Static keys

```
prk_static = HKDF-Extract(salt = "", ikm = k_dev)
k_req      = HKDF-Expand(prk_static, L("shieldled/v1/req"),  32)   client -> device
k_resp     = HKDF-Expand(prk_static, L("shieldled/v1/resp"), 32)   device -> client
```

### 3.4 Device secrets drawn at start-up

At each start a device MUST draw, from the random source of section 3.5:

- `cookie_secret`: 32 octets;
- `admission_epoch`: a 64-bit unsigned integer, non-zero, with its eight most
  significant bits clear.

Both MUST be held in volatile memory only. They MUST NOT be persisted, and MUST NOT
be derived from the PSK or `k_dev`.

> **Why.** Non-zero: an INIT relabelled as a FINISH would read `admission_epoch`
> from INIT's zero padding, so a non-zero value never matches it. This is a
> backstop, since step 3 of section 9.2 already discards such a datagram (Appendix
> A). The eight clear bits: because it is drawn below 2^56, and step 7 of section
> 9.2 fails closed rather than wrapping, on average 2^55 admissions remain. Drawn
> at start-up rather than derived from the PSK: so that no FINISH captured before a
> restart matches.

### 3.5 Randomness

Every random value in this protocol — the device's start-up secrets and
ephemeral keys, the client's `client_nonce` and ephemeral keys — MUST come from a
cryptographically secure random source. A device MUST NOT serve admission, and a
client MUST NOT begin an attempt, until that source is fully available.

### 3.6 Replacing the PSK

There is one PSK per domain and no means of rotating it in the protocol.
Replacing it requires re-provisioning every device. That is also the only
revocation mechanism: removing one client's authorisation means replacing the PSK
for the domain.

---

## 4. Constants

Every number the protocol depends on, in one place. Section 4.1 lists the values
that are part of the protocol and may not be changed; section 4.2 those an
installation chooses; section 4.3 two timing conditions that must hold between
them. An installation that breaks one of those conditions never admits anyone and
never says why, so section 4.3 is worth reading even if every default is kept.

### 4.1 Protocol constants

These are fixed by this version. An implementation MUST use these values.

| Name | Value |
| --- | --- |
| `MAGIC` | the 8 octets `53 4c 44 31 5a 30 30 31` (`"SLD1Z001"`) |
| `VERSION` | `0x01` |
| `TYPE_INIT` | `0x01` |
| `TYPE_RETRY` | `0x02` |
| `TYPE_FINISH` | `0x05` |
| `TYPE_ADMIT` | `0x06` |
| `HEADER_LEN` | 10 |
| `REQUEST_LEN` | 256 (INIT and FINISH) |
| `RETRY_LEN` | 84 |
| `ADMIT_LEN` | 82 |
| `ENVELOPE_LEN` | 20 |
| `KCP_OVERHEAD` | 24 |
| `REPLAY_WINDOW` | 256 |
| `COOKIE_EPOCH_MS` | 4 000 |
| `INIT_RETRY_MS` | 1 000 |
| `INIT_TRANSMISSIONS` | 3 |
| `FINISH_RETRY_MS` | 500 |
| `PUSH_ACK_TIMEOUT_MS` | 2 000 |
| `SESSION_DEAD_MS` | 10 000 |
| retry jitter | ±20 %, uniform |

Type values `0x03` and `0x04` are reserved.

> **Note** — `MAGIC` is the fixed value in the table, not a placeholder; the
> `shieldled/v1/…` labels of sections 3 and 6 are fixed in the same way.

### 4.2 Deployment constants

These are chosen per deployment. The defaults interoperate with each other.
`PENDING_SLOTS` is the number of admissions that may be in progress at once; a
deployment that raises `PENDING_TTL_MS` SHOULD raise `PENDING_SLOTS` too, since
a record then occupies its slot for longer.

| Name | Default | Constraint |
| --- | --- | --- |
| `WIRE_MTU` | 1400 | greater than `KCP_OVERHEAD + ENVELOPE_LEN`; the same value on both parties; small enough that a datagram is never fragmented on the path |
| `PENDING_SLOTS` | 2 | at least 1 |
| `PENDING_TTL_MS` | 5 000 | section 4.3 |
| `FINISH_PHASE_MS` | 1 500 | less than `COOKIE_EPOCH_MS`; section 4.3 |
| `SEND_QUEUE_MAX` | 32 KiB | section 12.5 |

### 4.3 Timing budgets

Two inequalities MUST hold for every client and device a deployment pairs. An
implementation MUST state the processing times needed to check them, and a
deployment MUST check them for its slowest pair.

**The pending-record budget.** A pending record lives `PENDING_TTL_MS` from the
instant the device installs it (section 9.3). Everything between that instant and
the arrival of the promoting datagram must fit:

```
round-trip time
  + the client's processing of ADMIT   (one X25519, the key derivation)
  + transmission of the first datagram                     <  PENDING_TTL_MS
```

Where it does not hold, raise `PENDING_TTL_MS`.

**The FINISH-phase budget.** The client abandons the attempt `FINISH_PHASE_MS`
after it first sends FINISH (section 10.3), and the device does not send ADMIT
until it has processed FINISH (section 9.2):

```
round-trip time
  + the device's processing of FINISH  (three HMACs, two X25519,
                                        the key derivation)   <  FINISH_PHASE_MS
```

Where it does not hold, raise `FINISH_PHASE_MS` on the clients, keeping it below
`COOKIE_EPOCH_MS`.

> **Why `FINISH_PHASE_MS` is less than `COOKIE_EPOCH_MS`.** A cookie stays valid
> for at least one full `COOKIE_EPOCH_MS` after it is issued (the current and the
> previous epoch are both accepted, section 9.1.1), so a FINISH resent until the
> end of its phase, after earlier copies were lost, still carries a valid
> cookie.

> **Note (informative).** Neither party can signal that a budget was missed. A
> pair that violates one fails every admission silently.

---

## 5. Wire formats

The exact octets of each datagram. There are four handshake messages, each of a
fixed length, and one format for everything sent once a session exists.

> **Why fixed lengths.** The two requests are padded to exactly 256 octets and
> the two responses are 84 and 82. A request is therefore always about three
> times the size of the response it can elicit, so replaying a request at a
> device with a forged source address sends the victim *fewer octets* than the
> attacker spent. (On a shared radio channel the cost in air time is nearer
> equal; section 17.4.) Fixed lengths also mean a receiver never has to trust a length
> field before it has authenticated anything.

### 5.1 Control header

Every control datagram begins:

| Offset | Field | Length |
| ---: | --- | ---: |
| 0 | `MAGIC` | 8 |
| 8 | `type` | 1 |
| 9 | `version` | 1 |

### 5.2 INIT — type `0x01`, 256 octets

| Offset | Field | Length |
| ---: | --- | ---: |
| 0 | control header | 10 |
| 10 | `client_nonce` | 24 |
| 34 | `device_id` | 8 |
| 42 | `init_mac` | 16 |
| 58 | zero padding | 198 |

`device_id` is that of the device the client is addressing.

### 5.3 RETRY — type `0x02`, 84 octets

| Offset | Field | Length |
| ---: | --- | ---: |
| 0 | control header | 10 |
| 10 | `epoch_tag` | 8 |
| 18 | `cookie` | 16 |
| 34 | `admission_epoch` | 8 |
| 42 | `device_id` | 8 |
| 50 | `observed_source` | 18 |
| 68 | `retry_mac` | 16 |

`epoch_tag` and `cookie` are opaque to the client, which echoes them in FINISH.
`observed_source` is the canonical source (section 7.1) of the INIT being
answered. `device_id` is the device's own.

### 5.4 FINISH — type `0x05`, 256 octets

| Offset | Field | Length |
| ---: | --- | ---: |
| 0 | control header | 10 |
| 10 | `client_nonce` | 24 |
| 34 | `epoch_tag` | 8 |
| 42 | `cookie` | 16 |
| 58 | `admission_epoch` | 8 |
| 66 | `e_c` | 32 |
| 98 | `client_tag` | 16 |
| 114 | zero padding | 142 |

`e_c` is the client's ephemeral X25519 public key.

### 5.5 ADMIT — type `0x06`, 82 octets

| Offset | Field | Length |
| ---: | --- | ---: |
| 0 | control header | 10 |
| 10 | `admission_epoch` | 8 |
| 18 | `e_s` | 32 |
| 50 | `admit_pre` | 16 |
| 66 | `admit_tag` | 16 |

`admission_epoch` is the value the client presented in FINISH. `e_s` is the
device's ephemeral X25519 public key.

### 5.6 Length and padding

Every control datagram has exactly the length given above. A receiver MUST verify
the length of a control datagram before it reads any field beyond the control
header, and MUST discard a datagram of any other length. A receiver MUST discard
an INIT or FINISH whose padding is not all zero.

A receiver MUST verify all ten octets of the control header and MUST discard a
control datagram whose `version` is not `0x01`.

> **Why zero padding.** No MAC covers the padding. Requiring it to be zero also
> makes a relabelled FINISH fail INIT's padding check (Appendix A).

### 5.7 Envelope datagram

```
ciphertext[n] || seq_wire[4] || tag[16]
```

`ciphertext` is the encryption of one KCP datagram (section 13), `n` its length.
Section 11 specifies how it is sealed and opened. An envelope datagram of `N`
octets MUST satisfy

```
KCP_OVERHEAD + ENVELOPE_LEN  <=  N  <=  WIRE_MTU
```

and a receiver MUST discard any other. A device SHOULD disable IP reassembly on
the path to this socket: the length limit above is applied after reassembly, so
it cannot recover what a fragmented datagram has already consumed.

---

## 6. Cryptographic computations

This section defines every MAC and every key. The picture first:

```
PSK ─┬─ HKDF with device_id ──► k_dev ──► k_req    authenticates INIT and FINISH
     │                                └─► k_resp   authenticates RETRY and ADMIT
     │
     └─ never stored on a device

cookie_secret  (device only, new at every start)
     ├──► epoch_tag                   names the cookie epoch (section 9.1.1)
     └──► cookie                      ties the exchange to the client's address

k_dev  +  dh (6.3)  +  transcript of the exchange
     └──► master ─┬─► k_kcp_c2s, k_kcp_s2c   envelope keys            (section 11)
                  ├─► k_c2s, k_s2c           message-layer keys       [SN-MSG]
                  └─► admit_tag              proves the device did the exchange
```

Six values authenticate the handshake, and each proves something different:

| Value | In | What it proves |
| --- | --- | --- |
| `init_mac` | INIT | The sender knows the key. It can be replayed, so it is **not** authentication: its job is to make the port silent to anyone who has never seen a client |
| `cookie` | RETRY, FINISH | The sender saw the RETRY that was sent to the address it claims |
| `retry_mac` | RETRY | This RETRY came from the addressed device, in answer to this client's nonce |
| `client_tag` | FINISH | The client knows the key and is offering this `e_c` in this exchange. This is the client's authentication |
| `admit_pre` | ADMIT | This ADMIT came from the device. It needs no key exchange to check, so it is tested before any expensive work |
| `admit_tag` | ADMIT | The device completed the key exchange |

Every label is length-prefixed, and the `type` and `version` octets of a message
are inputs to the MAC computed over it (`init_mac`, `retry_mac`, `client_tag`,
`admit_pre`), so none of those can be presented as another.

### 6.1 Handshake authenticators

```
init_mac  = HMAC/128(k_req,  L("shieldled/v1/init")  || type || version ||
                             client_nonce || device_id)

epoch_tag = the leading 8 octets of
            HMAC(cookie_secret, L("shieldled/v1/epoch") || cookie_epoch)

cookie    = HMAC/128(cookie_secret, L("shieldled/v1/cookie") || epoch_tag ||
                             canonical_source || client_nonce)

retry_mac = HMAC/128(k_resp, L("shieldled/v1/retry") || type || version ||
                             client_nonce || epoch_tag || cookie ||
                             admission_epoch || device_id || observed_source)
```

`type` and `version` are the octets of the message the authenticator belongs to.
`cookie_epoch` is a 32-bit unsigned integer (section 9.1.1).

> **Note** — worked example, `epoch_tag`. With `cookie_secret` the octet `88`
> repeated 32 times and `cookie_epoch` 7 (`00000007`), `epoch_tag` is
> `683e35eaec11879a` (`inputs.cookie_secret`, `inputs.cookie_epoch_be` and
> `schedule.epoch_tag_out` in the vector file).

> **Note** — worked example, `cookie`. This is a separate computation, not a
> continuation of the one above. With the same `cookie_secret`, the nominal
> `epoch_tag` `3333333333333333` (a nominal input of the vector file, not the
> `epoch_tag` just computed), `canonical_source` the octet `99` repeated 18 times
> and `client_nonce` the octet `22` repeated 24 times, `cookie` is
> `1b5f3e768ca7259c2bab1a958f2ecd4f` (`schedule.cookie_out`).

### 6.2 Transcript

```
context  = version || client_nonce || epoch_tag || cookie ||
           admission_epoch || device_id                         (65 octets)
context2 = context || e_c || e_s                               (129 octets)
```

`device_id` in `context` is the addressed device's. The device MUST use its own
`device_id` here and never a value taken from a received datagram.

### 6.3 Session keys and ADMIT authenticators

```
client_tag = HMAC/128(k_req, L("shieldled/v1/finish") || type || version ||
                             context || e_c)

dh         = X25519(own ephemeral private key, peer ephemeral public key)

master     = HKDF-Extract(salt = L("shieldled/v1/master") || context2,
                          ikm  = k_dev || dh)

k_c2s      = HKDF-Expand(master, L("shieldled/v1/c2s"),     32)
k_s2c      = HKDF-Expand(master, L("shieldled/v1/s2c"),     32)
k_kcp_c2s  = HKDF-Expand(master, L("shieldled/v1/kcp-c2s"), 32)
k_kcp_s2c  = HKDF-Expand(master, L("shieldled/v1/kcp-s2c"), 32)

admit_pre  = HMAC/128(k_resp, L("shieldled/v1/admit-pre") || type || version ||
                              context2)
admit_tag  = HKDF-Expand(master, L("shieldled/v1/admit"), 16)
```

`k_kcp_c2s` and `k_kcp_s2c` key the envelope (section 11). `k_c2s` and `k_s2c`
are handed to the message layer [SN-MSG].

> **Note (informative).** The salt of `master` is 149 octets, longer than the
> SHA-256 block, so HMAC hashes it first as [RFC2104] requires. An HKDF
> implementation that mishandles a long salt produces different keys.

### 6.4 Requirements

1. **X25519 output check.** An implementation MUST compute X25519 as in [RFC7748]
   and MUST reject the exchange if and only if the 32-octet output is all zero.
   It MUST NOT substitute a different test, such as a list of small-order points.
2. **Constant time.** Every comparison of a MAC, tag or cookie MUST be
   constant-time.
3. **Ephemeral keys.** Each party draws a fresh X25519 key pair per admission.
   The device MUST erase its ephemeral private key as soon as `dh` is computed.
   The client MUST keep its ephemeral private key until it leaves `AWAIT_ADMIT`
   (section 10) and erase it then.
4. **`master` and `dh`.** Both parties MUST erase `master` as soon as its five
   outputs are derived, whether or not the exchange then succeeds. The device
   MUST erase `dh` at the same point; the client erases it when it leaves
   `AWAIT_ADMIT` (section 10.5).
5. **Keys on failure.** Any session key derived for an exchange that does not
   complete MUST be erased.
6. **Prohibited.** Poly1305 tags MUST NOT be truncated. Session keys MUST NOT be
   used as MAC keys. An AEAD tag computed under a fixed nonce MUST NOT be used as
   a handshake authenticator. The envelope cipher is ChaCha20-Poly1305 and
   nothing else. An implementation MUST use a ChaCha20 implementation that is
   constant-time on the target.
7. **Logging.** An implementation MUST NOT log the PSK, any derived key, a
   cookie, a tag, a nonce, an ephemeral private key or a complete datagram.

> **Why the all-zero test (item 1).** Clamping makes every small-order input
> produce the all-zero output, so this one test catches them all, while lists of
> small-order points differ between libraries. With this test every implementation
> rejects exactly the same inputs.

---

## 7. Source addresses

Addresses matter twice. The cookie ties an exchange to the client's address, so
both sides must agree on how an address is written down (section 7.1). And a
device answers INIT, so it must never be tricked into answering *to* an address
that reaches many hosts (section 7.2).

### 7.1 Canonical source

```
canonical_source = ipv6_address[16] || port[2]
```

An IPv4 source is represented as an IPv4-mapped IPv6 address ([RFC4291] section
2.5.5.2): ten zero octets, `ff ff`, then the four address octets.

> **Note** — worked example. The IPv4 peer 192.168.4.2, port 5000, is
> `00000000000000000000ffffc0a804021388`: ten zero octets, `ffff`, the address
> `c0a80402` and the port `1388` (`canonical_source.v4` in the vector file).

### 7.2 Sources that are refused

A receiver MUST discard a datagram whose source address, tested in its own
address family **before** canonicalisation, is any of the following. It MUST
accept every other source at this step.

| Family | Refused |
| --- | --- |
| IPv4 | `224.0.0.0/4`; `255.255.255.255` and the broadcast address of any local subnet; `0.0.0.0/8`; `127.0.0.0/8`; any address assigned to the receiving interface |
| IPv6 | `ff00::/8`; `::`; `::1`; `::ffff:0:0/96`; `::/96`; any address assigned to the receiving interface |

Private, link-local, shared and unique-local ranges (`10/8`, `172.16/12`,
`192.168/16`, `169.254/16`, `100.64/10`, `fe80::/10`, `fc00::/7`) are accepted.

The family is that of the peer. An IPv4 peer that a dual-stack socket presents
as an IPv4-mapped address is an IPv4 source and is tested against the IPv4 row;
the `::ffff:0:0/96` entry refuses a datagram that arrived over IPv6 bearing such
an address. An implementation that cannot tell the two apart treats a mapped
address as IPv4.

This test is the first step of demultiplexing (section 8) and applies to control
and envelope datagrams alike.

> **Why a list of refused sources and not a list of accepted ones.** A RETRY
> sent to a multicast or broadcast address is transmitted to every host on the
> link, at the lowest rate — one replayed INIT becoming many times its own air
> time. Refusing those sources is all the rule needs to do. Defining instead
> which addresses are "valid unicast" invites two implementations to disagree
> about private, link-local and IPv4-mapped addresses, and the one that is too
> strict rejects every client without a word.

### 7.3 Interface binding

A device's socket MUST be bound to a single interface. `canonical_source` carries no
zone identifier, so link-local peers on two interfaces would otherwise be
indistinguishable.

### 7.4 Address translation

This version assumes there is no address translation between client and device.
The client's check of `observed_source` (section 10.4) fails across a translator.

---

## 8. Demultiplexing

Handshake messages and session traffic arrive on the same socket. The first
eight octets tell them apart: handshake messages begin with `MAGIC`, and
encrypted session traffic begins with ciphertext, which matches `MAGIC` only by
a 1-in-2^64 accident (such a datagram is simply lost, and KCP sends it again).

A receiver processes every datagram in this order:

1. Apply section 7.2. Discard a refused source.
2. If the datagram is at least `HEADER_LEN` octets and its first 8 octets equal
   `MAGIC`, it is a control datagram.
3. Otherwise it is an envelope datagram (section 11).

For a control datagram:

- A device MUST discard `RETRY` and `ADMIT`. A client MUST discard `INIT` and
  `FINISH`.
- A receiver MUST discard a datagram whose `type` is `0x03`, `0x04`, or any value
  other than the four defined types.
- A control datagram is never processed as an envelope datagram.

Every discard in this document is **silent**: no response, no change of state
(section 9.4).

---

## 9. Device admission procedure

This section is the device's half of the handshake, and the order of its steps
*is* the security property: inexpensive tests come before expensive ones,
nothing is remembered until the client has authenticated, and the key exchange
is last.

```
                    valid FINISH                 first datagram
                  (device sends ADMIT)         (KCP PUSH, sn = 0)
   ┌────────────┐                ┌────────────┐                ┌────────────┐
   │  no state  │ ─────────────► │  pending   │ ─────────────► │  primary   │
   │            │                │  record    │                │ (session)  │
   └────────────┘                └────────────┘                └────────────┘
     ▲        │                        │                  the previous primary,
     └────────┘                        ▼                  if any, is replaced
   INIT: answered             expires after               only at this point
   with RETRY, and            PENDING_TTL_MS, or is
   nothing is kept            replaced or evicted
```

### 9.1 INIT

INIT costs the device one comparison and a few MACs, and leaves no trace.
That is what lets it answer anyone who knows the key without being exhausted by
anyone who does not.

On an INIT the device MUST, in order:

1. Discard it unless its length and padding are as in section 5.
2. Discard it unless `device_id` equals the device's own. A device MUST NOT
   perform any cryptographic operation before this test.
3. Verify `init_mac`. Discard on failure, without computing a cookie.
4. Send a RETRY to the datagram's source, containing: the `epoch_tag` of the
   current cookie epoch; `cookie` computed over that `epoch_tag`, the datagram's
   `canonical_source` and its `client_nonce`; the device's current
   `admission_epoch`; the device's `device_id`; `observed_source` set to the
   datagram's `canonical_source`; and `retry_mac`.

The device MUST NOT create or change any state in handling an INIT.

#### 9.1.1 Cookie epochs

A cookie should be good for long enough to complete a handshake and no longer.
The device therefore changes the value that cookies are derived from every few
seconds, and accepts cookies from the current period and the one before.

```
cookie_epoch = floor(milliseconds since start / COOKIE_EPOCH_MS)
```

as a 32-bit unsigned integer. The clock MUST be monotonic and MUST NOT wrap
during the device's uptime; a 32-bit millisecond counter does not qualify.

Which epoch is current is determined by the clock at the time each datagram is
handled. An implementation MAY cache `epoch_tag` values, but a stale cache MUST
NOT extend the life of a cookie.

A FINISH is acceptable under the current epoch and the one before it. Before the
first epoch has completed there is no previous epoch, and only the current one is
acceptable.

> **Note** — `epoch_tag`. It tells the device which of its two epochs a cookie was
> computed over, by comparison with its two current tags (cached or computed), without trial
> verification and without putting the uptime-derived epoch counter on the
> wire.

### 9.2 FINISH

FINISH is where the device commits. It applies a series of inexpensive tests,
and only a datagram that passes all of them reaches the key exchange. (A FINISH
that an attacker recorded can pass them, once; section 17.4.)

On a FINISH the device MUST perform these steps in exactly this order:

1. Discard it unless its length and padding are as in section 5.
2. **Retransmission.** If an unexpired pending record exists for the datagram's
   tuple and the entire 256-octet datagram equals the FINISH stored in that
   record, send the stored ADMIT again, unchanged, and stop. This MUST NOT change
   the record's expiry or any other state.
3. **Cookie.** Discard unless the presented `epoch_tag` is the device's tag for
   the current or the previous cookie epoch (section 9.1.1), and the presented
   `cookie` equals the cookie computed over that `epoch_tag`, this datagram's
   `canonical_source` and its `client_nonce`.
4. **Admission counter.** Discard unless the presented `admission_epoch` equals
   the device's current `admission_epoch`.
5. **Authentication.** Verify `client_tag`. Discard on failure.
6. **Key agreement.** Draw an ephemeral key pair, compute `dh`, discard if the
   output is all zero (section 6.4), and compute the values of section 6.3 using
   the presented `admission_epoch`. Build the ADMIT.
7. **Commit**, as one atomic operation: if `admission_epoch` no longer equals the
   value verified in step 4, or incrementing it would set any of its eight most
   significant bits, erase the keys derived in step 6 and stop without
   responding. Otherwise increment `admission_epoch` and install a pending record
   for this tuple (section 9.3). Then, outside that operation, send the ADMIT.

A FINISH that fails any of steps 1 to 5 MUST NOT change any state.

> **Why this order.** Step 2 is the only path on which an unauthenticated
> datagram elicits a response from a device that holds state for it. Comparing
> the whole datagram, not a field of it, is what prevents a forged FINISH from
> reaching it. Step 3 ties a FINISH to the tuple its cookie was issued for, and
> step 4 makes every `admission_epoch` value usable once, so a captured FINISH
> that the device has never accepted can be replayed at most once, and only from
> the tuple it was captured from.

> **Note** — loss during admission, drawn as a picture. A lost ADMIT is answered
> from the stored copy (step 2); a lost first datagram is sent again by KCP under a
> new `seq_full` (section 11.2 item 2).
>
> ```
> client                                         device
>   FINISH                                  ->   valid: pending record, ADMIT sent
>                                           <-   ADMIT   (lost on the way)
>   FINISH again, byte-identical            ->   step 2: an unexpired record holds
>   (FINISH_RETRY_MS later)                      this exact FINISH; the stored ADMIT
>                                                is sent again, state unchanged
>                                           <-   ADMIT   (the same octets)
>   envelope( KCP PUSH sn=0, seq_full 1 )   ->   (lost on the way)
>   envelope( KCP PUSH sn=0, seq_full 2 )   ->   KCP sent sn = 0 again; it opens
>                                                under the record: promotion
> ```

### 9.3 Pending records

A pending record is the device's memory of an admission that has been
authenticated but not yet used: the keys are agreed, and the client's first
datagram has not arrived. There is a small fixed number of them, each lives a
few seconds, and none of them touches the session that is currently running.

A device holds `PENDING_SLOTS` pending records. A record contains: the tuple; the
FINISH datagram that created it; the ADMIT sent in response; the four session
keys; an empty client-to-device replay window (section 11.4); and its expiry. It
MUST NOT contain an ephemeral private key.

1. **Keying.** Records are keyed by tuple. A valid FINISH replaces the record of
   its own tuple and affects no other.
2. **Lifetime.** A record expires `PENDING_TTL_MS` after it is installed. A
   replacing FINISH installs a new record with a new expiry. Nothing else extends
   an expiry.
3. **Eviction.** If a valid FINISH arrives from a tuple that holds no record and
   every slot is occupied, the device MUST evict the record that was installed
   earliest and install the new one. A slot holding an expired record is free.
4. **Expiry.** An expired record MUST NOT be used. A device MUST evaluate expiry
   whenever it looks a record up, and MUST also discard expired records
   periodically, so that the keys of an abandoned admission do not persist.
5. **Erasure.** Whenever a record is replaced, evicted, expired or consumed by
   promotion, its four keys MUST be erased.
6. **Staleness.** A datagram or operation that began against one record MUST NOT
   take effect on a different record later installed in the same slot.

A device MUST NOT change the primary in response to a FINISH.

### 9.4 Silence and timers

A device that answers a bad packet tells the sender something — that it exists,
that a key is wrong, that a slot is full — and gives it a way to make the device
transmit. So the device says nothing, ever, to anything it does not accept, and
all retrying is left to the client.

1. A device MUST NOT respond in any way to a datagram that it discards.
2. A device MUST NOT send a control datagram except as the direct result of
   receiving one. It MUST NOT retransmit RETRY or ADMIT on a timer.
3. The interface carrying the socket MUST NOT emit ICMP echo replies or ICMP
   port- or host-unreachable messages.
4. A party MUST NOT change state, timers or path MTU in response to an ICMP
   message received on this socket.
5. A limit on the *number* of unauthenticated datagrams evaluated MUST NOT be
   applied in a way that lets discarded datagrams prevent a valid one from being
   evaluated.
6. A device MUST NOT give the established session's output priority over
   admission responses. A failing session transmits continuously and would
   otherwise prevent its own replacement.

---

## 10. Client procedure

The client drives the handshake. It is a state machine of five states, and at
every moment at most one kind of message is welcome; everything else is dropped.

```
        take         valid         valid          first PUSH
       control       RETRY         ADMIT         acknowledged
 IDLE ────────► AWAIT_ ────────► AWAIT_ ────────► AWAIT_ ────────► ESTABLISHED
   ▲            RETRY            ADMIT           PUSH_ACK              │
   │              │                │                │                  │
   │         resend INIT     resend FINISH      wait up to         session ends:
   │         ~1 s apart,     ~0.5 s apart,      2 s                the application
   │         3 in all        until 1.5 s                           ends it, or 10 s
   │              │                │                │              of silence with
   └──────────────┴────────────────┴────────────────┴───────────── data outstanding
            a timeout returns to IDLE; a datagram that fails a
            check is dropped and changes nothing
```

### 10.1 States

For every state and every kind of datagram, exactly one thing happens:

| Received | IDLE | AWAIT_RETRY | AWAIT_ADMIT | AWAIT_PUSH_ACK | ESTABLISHED |
| --- | --- | --- | --- | --- | --- |
| RETRY | discard | 10.4 | discard | discard | discard |
| ADMIT | discard | discard | 10.5 | discard | discard |
| INIT, FINISH | discard | discard | discard | discard | discard |
| envelope | discard | discard | discard | section 11 | section 11 |

A client MUST discard an ADMIT in `AWAIT_PUSH_ACK` and in `ESTABLISHED`.

> **Note (informative).** Acting on a second ADMIT would restart the client's
> outbound sequence at 1 under an unchanged key, which is nonce reuse.

### 10.2 Taking control

Admission starts only when the application asks for it. On that request the
client runs exactly one attempt. It MUST NOT start another on its own: there is
no automatic retry and no back-off. The outcome is reported to the application.

> **Why no automatic retry.** A device has one session. If two clients each
> re-admitted themselves whenever they lost it, each would displace the other
> for ever. Damping that with a back-off would hand an attacker a cheap weapon:
> suppress one packet per attempt and the client backs itself off into silence.
> Making "take control" a deliberate act removes the loop instead of slowing it.
> Retransmissions *within* an attempt still absorb ordinary packet loss.

The request carries the **first message** of the session, which begins in the
first KCP PUSH (section 10.5). (Its form: section 12.2.) A
first message is REQUIRED, because the device promotes on nothing else.

On the transition from `IDLE` to `AWAIT_RETRY` the client MUST draw a fresh
`client_nonce` and a fresh ephemeral key pair, and MUST hold both unchanged for
the whole attempt.

The client MUST use one UDP socket and one source port for the attempt and the
session that follows. It MUST know its own address and port as the device sees
them; a socket bound to a wildcard address does not provide this until it is
connected to the device.

### 10.3 Transitions

| From | Event | To |
| --- | --- | --- |
| IDLE | application takes control | AWAIT_RETRY; send INIT |
| AWAIT_RETRY | valid RETRY (10.4) | AWAIT_ADMIT; send FINISH |
| AWAIT_RETRY | `INIT_RETRY_MS` elapsed, fewer than `INIT_TRANSMISSIONS` sent | AWAIT_RETRY; send the same INIT again |
| AWAIT_RETRY | `INIT_RETRY_MS` elapsed after the `INIT_TRANSMISSIONS`-th transmission | IDLE; attempt failed |
| AWAIT_ADMIT | valid ADMIT (10.5) | AWAIT_PUSH_ACK |
| AWAIT_ADMIT | `FINISH_RETRY_MS` elapsed, phase not over | AWAIT_ADMIT; send the identical FINISH again |
| AWAIT_ADMIT | `FINISH_PHASE_MS` elapsed since the first FINISH | IDLE; attempt failed |
| AWAIT_PUSH_ACK | the first PUSH is acknowledged | ESTABLISHED |
| AWAIT_PUSH_ACK | `PUSH_ACK_TIMEOUT_MS` elapsed since ADMIT was accepted | IDLE; attempt failed |
| ESTABLISHED | no authenticated datagram for `SESSION_DEAD_MS` while the client has unacknowledged data outstanding | IDLE; session ended |
| ESTABLISHED | application ends the session | IDLE; session ended |

The device sends nothing on a session before it has promoted it, so a client MAY
take the first authenticated envelope datagram it receives as the acknowledgement
of its first PUSH.

Rules:

1. A datagram that fails any check of 10.4 or 10.5 is discarded and the state is
   unchanged. A check MUST NOT cancel or alter a timer.
2. Retransmitted INITs MUST be identical. Retransmitted FINISHes MUST be
   byte-identical.
3. Each `INIT_RETRY_MS` and `FINISH_RETRY_MS` interval is varied by the retry
   jitter. `FINISH_PHASE_MS` is not, and jitter MUST NOT carry a retransmission
   past it.
4. When a timer expires, the client MUST process datagrams already received
   before acting on the expiry.
5. The client MUST NOT end a session that has nothing outstanding because it is
   silent; only the application ends such a session (below). There is no
   keep-alive.
6. On every transition to IDLE the client MUST discard the values retained from
   RETRY and erase every secret of the attempt or session: the ephemeral private
   key, any cached `dh`, the session keys, and the KCP state.
7. To obtain fresh keys a client ends its session and takes control again. There
   is no rekeying within a session.

The application MAY end a session and take control again before sending, when
nothing authenticated has arrived for longer than a threshold of its choosing.
This generates no traffic while idle. The client never starts a new admission on
its own (section 10.2).

### 10.4 RETRY

The client is about to send its key-exchange share on the strength of this
message, so it makes sure the RETRY is for *its* INIT, from *the* device, and
describes *its own* address. The free check comes first.

In `AWAIT_RETRY`, on a RETRY the client MUST, in order:

1. Discard it unless its length is `RETRY_LEN`.
2. Discard it unless `observed_source` equals the client's own canonical source.
3. Verify `retry_mac`, computed with the client's own `client_nonce`. Discard on
   failure.
4. Discard it unless `device_id` equals the value sent in INIT.
5. Retain `epoch_tag`, `cookie` and `admission_epoch` together, build and send
   FINISH, and enter `AWAIT_ADMIT`.

> **Why the `observed_source` check.** Without it an attacker could replay the
> client's INIT from its own address and inject the genuine RETRY; the cookie would
> be bound to the attacker's address and the client's FINISH would fail silently.

> **Note** — in step 3 the `device_id` that enters `retry_mac` is the one carried
> in the RETRY. Step 4 requires it to equal the one sent in INIT, so a client that
> uses its own copy reaches the same outcome.

### 10.5 ADMIT

ADMIT is where the client spends its expensive computation and switches to the
new keys. The checks are ordered so that a forged ADMIT is thrown away for the
price of one MAC, and so that a damaged one cannot spoil the attempt.

In `AWAIT_ADMIT`, on an ADMIT the client MUST, in order:

1. Discard it unless its length is `ADMIT_LEN`.
2. Discard it unless `admission_epoch` equals the value sent in FINISH.
3. Verify `admit_pre`. Discard on failure. This MUST precede the X25519
   computation.
4. Compute `dh`, discard if the output is all zero, derive the values of section
   6.3 and verify `admit_tag`. On failure erase `master` and the keys derived
   from it and discard the datagram; keep the ephemeral private key and the
   cached `dh` for this `e_s`, so that a later, genuine ADMIT can still be
   processed.

   The client MUST compute `dh` at most once per distinct `e_s` in an attempt,
   reusing the result for further ADMITs carrying the same `e_s`.
5. **Commit**, exactly once per attempt: erase the ephemeral private key and any
   cached `dh`; set the outbound sequence to 1 (section 11.2 item 1) and the inbound
   replay window to empty (section 11); bind the session keys; send the first
   message, which begins in the first KCP PUSH (`sn = 0`); enter
   `AWAIT_PUSH_ACK`.

The test of the state and the commit MUST be atomic with respect to each other.
A client that handles datagrams, timers and application requests on one thread
satisfies this.

> **Why `dh` once per `e_s`.** `admit_pre` does not cover `admit_tag`, so without
> caching each bit-flipped replay of the genuine ADMIT would cost an X25519.

### 10.6 Silence

A client MUST NOT send anything in response to a datagram it discards.

---

## 11. Envelope

Once a client is admitted, every datagram in both directions is sealed in an
envelope: encrypted, authenticated, and numbered so that a recorded datagram
cannot be played back.

```
 UDP payload
 ┌──────────────────────────────────────────────┬──────────────┬─────────────┐
 │ ciphertext of one KCP datagram  (n octets)   │ seq_wire (4) │  tag (16)   │
 └──────────────────────────────────────────────┴──────────────┴─────────────┘
                                                  low 32 bits of
                                                  the 64-bit seq_full
```

The sender numbers its datagrams 1, 2, 3, … with a 64-bit counter and puts only
the low 32 bits on the wire. The receiver knows roughly where the counter is, so
it can rebuild the full value (section 11.5); a wrong guess simply fails to
decrypt, because the full value is part of the nonce.

### 11.1 Sealing

Each direction has its own key and its own 64-bit sequence, `seq_full`.

```
key        = k_kcp_c2s (client to device) or k_kcp_s2c (device to client)
direction  = "C2S" || 0x00  or  "S2C" || 0x00                  (4 octets)
nonce      = direction || seq_full                              (12 octets)
seq_wire   = the low 32 bits of seq_full                        (4 octets)

(ciphertext, tag) = ChaCha20-Poly1305(key, nonce, aad = seq_wire,
                                      plaintext = KCP datagram)

datagram   = ciphertext || seq_wire || tag
```

### 11.2 Sending

One rule matters above all others here: a sequence number is used once. Two
datagrams sealed under the same key and number expose the contents of both and
let an eavesdropper forge datagrams under that number.

1. `seq_full` MUST start at 1 for each direction of a newly admitted session.
2. A sender MUST use a new `seq_full`, one greater than the last, for every
   datagram it sends, including retransmissions of KCP segments and datagrams
   carrying only acknowledgements.
3. `seq_full` MUST NOT restart or repeat for the life of the session, including
   across a quiesce and resume (section 12.4).
4. A sender that has used `2^64 - 1` MUST NOT send again on that session.
5. Where more than one execution context can send, allocation of `seq_full` MUST
   be atomic: two datagrams MUST NOT ever be sealed under one value.
6. KCP MUST be configured with an MTU of `WIRE_MTU - ENVELOPE_LEN`, so that no
   envelope datagram exceeds `WIRE_MTU`.

### 11.3 Receiving

A device may hold two sets of keys for one address at the same moment: the
running session's, and those of an admission that is waiting for its first
datagram. An arriving datagram is tried against each in turn, and nothing about
its contents is believed until one of them opens it.

A receiver MUST process an envelope datagram as follows.

1. Discard it unless its length satisfies section 5.7.
2. Select the sessions whose tuple equals the datagram's. On a client this is its
   own session. On a device it is the primary, if its tuple matches, and then the
   unexpired pending record for that tuple, if any — in that order. If there is
   none, discard.
3. For each candidate in turn: reconstruct `seq_full` (section 11.5) and, if it
   is in range, open the AEAD under that candidate's key. If reconstruction is
   out of range or the AEAD fails, try the next candidate. If no candidate opens
   the datagram, discard it.
4. If the candidate is a pending record, continue at section 12.2, which applies
   the replay test together with its own condition.
5. Otherwise apply the replay test of section 11.4 to the reconstructed
   `seq_full` against the session's **current** window, and mark it. The test and
   the mark MUST be one atomic operation. Discard a datagram that fails, and
   deliver the plaintext of one that passes as in section 12.3.

An implementation MUST NOT read any field of the KCP datagram, and MUST NOT
change any session state, before the AEAD has opened.

> **Why the primary is tried first.** Established traffic pays one AEAD open, and
> a stale pending record is inert.

> **Note** — the two sets of keys on one tuple, and the order they are tried,
> drawn as a picture.
>
> ```
>  datagram from one tuple
>         │
>         ▼
>  primary: the running session, if its tuple matches              tried first
>         │ opens? ── yes ──► replay test and mark; deliver, or discard if it fails (step 5)
>         │ no, or there is no primary
>         ▼
>  pending record: unexpired, for this tuple                       tried second
>         │ opens? ── yes ──► promotion condition (section 12.2)
>         │ no, or there is none
>         ▼
>  discard, silently
> ```

### 11.4 Replay window

Datagrams can arrive out of order, so the receiver cannot simply demand that
each number be higher than the last. It keeps its high-water mark, `hwm`, at the
highest number seen and remembers which of the 256 numbers up to it have already
been accepted:

```
     refused: too old       │◄──── window: 256 numbers ────►│   accepted, and the
 ───────────────────────────┤ hwm-255  …  hwm-1       hwm   ├── window moves up ──►
                              each accepted at most once
```

Each receiving direction keeps a 64-bit high-water mark, `hwm`, and a window of
`REPLAY_WINDOW` sequence numbers: `hwm` and the 255 below it.

A sequence number is accepted if it is above `hwm`, or if it is within the
window and has not been accepted before. Accepting a number above `hwm` moves
`hwm` to it. A number below the window is refused.

A receiver MUST apply this rule to the `seq_full` of every datagram of an
established session (section 11.3 step 5). A receiver MUST NOT record a number
as accepted before the AEAD has opened.

> **Note** — worked example, from `replay_script` in the vector file. A window
> starts empty, and these numbers arrive in this order (the offset of a number is
> `hwm` minus the number):
>
> ```
> presented  result  why
> 1          accept  first
> 1          reject  duplicate
> 2          accept  next
> 1000       accept  forward jump: hwm becomes 1000
> 999        accept  in-window backfill
> 999        reject  duplicate backfill
> 745        accept  offset 255, the last value in the window
> 744        reject  offset 256, one past the window
> 1          reject  far below the window
> 1001       accept  forward again: hwm becomes 1001
> ```
>
> The number 744, with `hwm` 1000, is still inside the reconstruction range of
> section 11.5 (`reconstruct_range` in the vector file) but outside the 256-wide
> window.

### 11.5 Sequence reconstruction

Only 32 bits of the sequence travel with each datagram. The receiver assumes the
datagram is near the highest number it has seen — within about 2^31
either side — and picks the full value closest to that. At 500 datagrams a
second the 32 bits wrap after 99 days, and sessions can last longer than that,
which is why the counter is 64 bits and why this step exists.

A receiver MUST reconstruct `seq_full` by the computation below (section 11.3
step 3).

With `hwm` the receiver's high-water mark (0 for an empty window):

```
d32       = (seq_wire - (hwm mod 2^32)) mod 2^32
delta     = d32               if d32 <  2^31
            d32 - 2^32        otherwise
candidate = hwm + delta                        (a signed 64-bit computation)
```

`candidate` is out of range if it is less than 1 or more than `REPLAY_WINDOW`
below `hwm`. Otherwise it is the `seq_full` used for the nonce and the replay
test.

> **Note (informative).** The comparison is written so that `d32 = 2^31` maps to
> a negative delta. A `candidate` exactly `REPLAY_WINDOW` below `hwm` is in range
> here and is then refused by the window of section 11.4.

> **Note** — worked example, crossing 2^32 (`reconstruct` in the vector file).
> With `seq_wire` 2 and `hwm` 4294967295: `d32` = (2 − 4294967295) mod 2^32 = 3,
> which is below 2^31, so `delta` is 3 and `candidate` is 4294967298.

---

## 12. Sessions on the device

A device has one session. This section says how a pending record becomes that
session, what happens to the one it replaces, and how a session behaves when its
client goes quiet — which, by design, is nothing at all.

### 12.1 State

A device has at most one primary, which is **live** or **quiesced**, and up to
`PENDING_SLOTS` pending records.

A session is **retired** when no datagram is processed against it and none is
sent on it; it is **released** when its memory is freed; its keys are erased
before release.

### 12.2 Promotion

Promotion is the moment the new session replaces the old, and it is where a
small mistake has large consequences: promote twice and a sequence restarts
under a key that has already used it. The rules below make promotion happen
exactly once, on exactly one kind of datagram.

> **Why only a PUSH with `sn = 0`.** That is the first segment of the client's
> stream. Accepting anything else would let a client park out-of-order data on
> the device before the stream had begun, and would let a reordered later
> datagram use up the one promotion.

A datagram that opens under an unexpired pending record (section 11.3) is a
candidate for promotion.

1. **Condition.** The datagram's `seq_full` MUST pass the replay test of section
   11.4 against the record's window, and the first KCP segment in the datagram
   MUST be a PUSH with `sn = 0` (section 13). A datagram that fails either is
   discarded **without** being recorded in the replay window.
2. **Exactly once.** Promotion consumes the pending record. Testing the
   condition, recording the sequence number and claiming the record MUST be one
   atomic operation, so that a duplicate of the promoting datagram cannot promote
   a second time. The record MUST still be unexpired at that moment.
3. **What the new primary inherits.** The record's four keys, its tuple, and its
   client-to-device replay window **including the promoting datagram's sequence
   number**. The window MUST NOT be reset. These MUST be the values held at the
   moment of the claim, even if the record is replaced or expires while the
   promotion completes.
4. **Outbound sequence.** The device's `seq_full` for the new primary starts at
   1 (section 11.2 item 1), and MUST be set before any datagram is sealed under
   the new `k_kcp_s2c`.
5. **`conv`.** The KCP conversation identifier of the promoting datagram is bound
   to the primary. A later datagram carrying a different `conv` MUST be
   discarded.
6. **The previous primary.** The device MUST retire the old session (section
   12.1) from the moment of the claim, before allocating the new one, and MUST
   release it only after it is retired. Its keys MUST be erased before its memory is released.
7. **The record** is cleared and its keys erased — unless it has meanwhile been
   replaced by a different admission (section 9.3 item 6), in which case that
   admission is left untouched.
8. **Failure.** If the device cannot allocate the new session after the claim,
   the result is no primary at all: the previous primary has been retired and is
   released, and the claimed record is discarded. The device MUST erase every
   copy of the keys involved.

The promoting datagram is then delivered to KCP as the first datagram of the
session. A malformed segment later in that datagram does not undo the promotion.

The first message on the KCP stream MUST be a sealed message of [SN-MSG]. There
is no further handshake inside the session.

### 12.3 Established session

An accepted datagram is delivered to KCP only if the primary it was accepted
against is still the primary and its `conv` is the bound one.

### 12.4 Quiesce and resume

If the client stops acknowledging, the device eventually gives up retransmitting
to it. It does not end the session for that: it stops talking and waits. When
the client speaks again, the session carries on from where it was.

When KCP declares the link dead — a segment has been retransmitted the configured
number of times without acknowledgement — the device MUST stop sending on the
session and stop retransmitting, and MUST retain the session, its keys and its
tuple. The primary is then quiesced.

A quiesced primary becomes live again when a datagram is accepted for it and KCP
accepts that datagram as well-formed for the bound `conv`.

On resume the device MUST preserve the KCP sequence state, `conv`, both
directions' `seq_full` and the replay window. It MUST NOT recreate the KCP state,
and it MUST clear whatever caused the link to be declared dead — retransmission
counts and timeouts — and re-base KCP's stored timestamps to the current time, so
that the session does not immediately quiesce again.

> **Note (informative).** KCP compares 32-bit millisecond timestamps as signed
> differences, which invert after about 24.8 days. A session may be quiesced for
> longer than that.

### 12.5 No idle timeout; bounded send path

A client may be silent for as long as it likes and still own its device. The
device therefore cannot use "the client seems to be gone" as a reason to free
memory, and must bound what it queues for the client by other means.

1. A device MUST NOT end a session for inactivity, except that [SN-MSG]
   ("Outcomes of a read", item 2) ends one whose peer falls silent while a
   message is partly read. A primary is replaced only by
   a promotion, and released otherwise only by a promotion that fails (section
   12.2 item 8) or when the message layer ends the session ([SN-MSG], "Outcomes
   of a read"). After a release the device has no
   primary and continues to serve admission.
2. There is no keep-alive in either direction, and an implementation MUST NOT
   depend on one.
3. The data a device has queued or sent and not yet had acknowledged MUST be
   bounded by `SEND_QUEUE_MAX`, independently of whether the peer is responding.
   `SEND_QUEUE_MAX` counts octets of application data written to KCP and not yet
   acknowledged, queued or in flight, excluding KCP and envelope headers. An
   implementation MAY account in whole KCP segments at their full payload size,
   which only refuses earlier. At the bound the device MUST refuse further writes
   from its application with an error, and MUST accept them again once the total,
   by the implementation's measure, falls below it.

---

## 13. KCP

KCP is a small, widely used protocol that provides reliable, ordered delivery
over datagrams: it numbers segments, acknowledges them and retransmits what is
lost. ShieldNet uses its wire format unchanged. The envelope wraps each KCP
datagram, so KCP never sees anything that has not been authenticated.

The plaintext of an envelope datagram is one KCP datagram: one or more KCP
segments, each beginning with the 24-octet header

```
conv[4] || cmd[1] || frg[1] || wnd[2] || ts[4] || sn[4] || una[4] || len[4]
```

in **little-endian** byte order, as defined by the KCP reference implementation
[KCP]. `IKCP_CMD_PUSH` is 81.

1. `conv` is chosen by the client and is not negotiated.
2. KCP operates in stream mode on both parties ([SN-MSG] section 3.1).
3. The KCP MTU is `WIRE_MTU - ENVELOPE_LEN` (section 11.2).
4. An implementation MUST be wire-compatible with [KCP]. Its tuning — interval,
   fast-resend threshold, congestion control, window sizes, the dead-link
   threshold — is local. Appendix B gives a set of values known to work.
5. A party MUST be able to buffer the whole receive window it advertises. One
   that refuses segments inside its advertised window is seen by its peer as
   loss, and the peer retransmits until it declares the link dead.

> **Note** — the KCP segment header drawn as a picture. It agrees field for field
> with the layout above: offsets count from the start of the segment, not from the
> UDP payload, and every field is little-endian.
>
> ```
> offset  0      4      5      6      8      12     16     20     24
>         ┌──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬────────┐
>         │ conv │ cmd  │ frg  │ wnd  │  ts  │  sn  │ una  │ len  │  data  │
>         │ (4)  │ (1)  │ (1)  │ (2)  │ (4)  │ (4)  │ (4)  │ (4)  │ (len)  │
>         └──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┴────────┘
> ```

---

## 14. The message layer

The session keys `k_c2s` and `k_s2c` are used only by [SN-MSG], which specifies
the messages on the KCP stream, including the rules for compression and padding.

---

## 15. Versioning

Version 1 is the only version. There is no negotiation and no fallback: a
datagram carrying `MAGIC` and any other `version` is discarded (section 5.6).

A future version MUST use a different `MAGIC` or a different port. It MUST NOT
share this version's `MAGIC` and distinguish itself by the version octet alone.

> **Why.** A datagram with this `MAGIC` and another version octet is silently
> discarded (section 5.6); coexistence could rest only on negotiation, which cannot
> be made safe. Not implementing a second version is what closes downgrade, and a
> separate `MAGIC` or port keeps a future version from sharing this one's
> socket.

---

## 16. Conformance

An implementation conforms as a **client**, as a **device**, or as both.

### 16.1 All implementations

- the key derivations of sections 3 and 6, and the requirements of section 6.4;
- randomness as in section 3.5 and the constants of section 4.1;
- the formats and length rules of section 5;
- source handling as in section 7 and demultiplexing as in section 8;
- the envelope as in section 11;
- KCP as in section 13;
- versioning as in section 15;
- the byte-exact test vectors of Appendix A.

### 16.2 Client

- the procedure of section 10, including the state table, the explicit
  take-control rule, the check order of 10.4 and 10.5, and the atomic commit;
- silence (10.6) and the ICMP rule (9.4 item 4);
- the timing budgets of section 4.3, stated for the implementation.

### 16.3 Device

- provisioning as in section 3.2, and start-up secrets as in section 3.4;
- the procedures of section 9, in the order given;
- pending records as in section 9.3;
- silence, timers and ICMP as in section 9.4;
- session handling as in section 12;
- the timing budgets of section 4.3, stated for the implementation.

---

## 17. Security considerations

### 17.1 Assumptions

- **The PSK is authorisation.** Any holder of the PSK is a legitimate client. The
  protocol provides no per-client identity and no finer revocation than replacing
  the PSK (section 3.6).
- **Randomness.** Every guarantee below assumes section 3.5. A device or client
  with a predictable random source has no security.
- **Local network.** A *local* attacker sends datagrams from any spoofed source,
  observes all traffic on the link and forges ICMP. An *on-path* attacker can
  also drop, delay and reorder datagrams. Neither holds the PSK or a `k_dev`.

### 17.2 What the protocol provides

Against both:

- no session can be established, taken over or injected into;
- no state is created on the device, and no Diffie-Hellman computation is
  performed, except for a FINISH authenticated under the key — which an attacker
  can present only by replaying a captured one, once (section 17.4);
- a live session cannot be displaced except by a completed admission;
- keys are fresh per session, and bound to the device, the client's address, the
  cookie epoch and both ephemeral keys; a completed session's traffic cannot be
  decrypted from `k_dev` alone once both ephemeral private keys are erased;
- no key or nonce can be made to repeat.

### 17.3 What it does not provide

- **Availability against an on-path attacker.** An attacker who can drop
  datagrams can prevent admission.
- **Confidentiality of the session's existence and shape.** `MAGIC`, `device_id`
  and the four fixed lengths identify the protocol and the device. `seq_wire` is
  a cleartext packet counter. Datagram sizes and timing are visible.
- **Admission counting.** `admission_epoch` is cleartext in RETRY and advances by
  one per accepted FINISH. Anyone who has captured one INIT can replay it to read
  it.
- **Rekeying.** A session's keys last as long as the session, which may be
  indefinite.
- **Protection of keys at rest**, and of a client, which holds the PSK itself.
- **Protection of the PSK during provisioning.** A device provisioned by being
  given the PSK (section 3.2, the second way) sees it once. A device that is
  already compromised at that moment, or anyone able to read the channel that
  carries the PSK to it, learns the PSK and with it every device's key. That
  channel is outside this protocol and needs its own protection. Provisioning
  with `k_dev` avoids the exposure altogether.

### 17.4 Costs an attacker can impose

- **Reflection.** A captured INIT can be replayed from any spoofed source
  indefinitely; each replay elicits an 84-octet RETRY. The response is smaller
  than the request by design, but on a shared radio medium the cost in air time
  is close to that of the request.
- **Computation.** A datagram at a known tuple costs the receiver one AEAD
  operation over up to `WIRE_MTU` octets, or two while that tuple holds both the
  primary and a pending record. A forged control datagram costs up to four
  HMACs (two when `epoch_tag` values are cached) and one 256-octet comparison
  before it is discarded.
- **A replayed FINISH.** An on-path attacker who suppresses a FINISH can replay
  it once within the life of its cookie (at most `2 × COOKIE_EPOCH_MS`), causing
  one key agreement and occupying the pending record of the tuple it was
  captured from. It cannot obtain a session. Replayed from its own tuple while
  its record lives, it re-sends the stored 82-octet ADMIT (section 9.2 step 2)
  and changes nothing.

### 17.5 Rules that carry the security

Each of the following is stated normatively above. They are collected here
because relaxing any one of them yields session establishment, nonce reuse or a
permanent denial without the key.

| Rule | Section |
| --- | --- |
| `client_tag` is verified before any Diffie-Hellman computation | 9.2 |
| The steps of FINISH processing are performed in order | 9.2 |
| The retransmission test compares the whole FINISH datagram | 9.2 |
| `k_dev` is an input to `master`; both ephemeral keys are bound by the tags | 6.3 |
| Length is verified before any field beyond the control header is read | 5.6 |
| No KCP field is read before the AEAD opens | 11.3 |
| The replay test and its mark are atomic | 11.3 |
| Promotion happens exactly once per pending record | 12.2 |
| The promoted session inherits the already-marked replay window | 12.2 |
| A second ADMIT is discarded after commit | 10.1 |
| The client keeps its ephemeral key until it leaves `AWAIT_ADMIT` | 6.4, 10.5 |
| No ADMIT check alters a timer | 10.3 |
| A FINISH never changes the primary | 9.3 |
| `device_id` is tested before any cryptographic operation | 9.1 |
| Promotion happens only on a PUSH with `sn = 0` | 12.2 |
| `observed_source` must equal the client's own address | 10.4 |
| `seq_full` never repeats and never restarts | 11.2 |
| ICMP is ignored; the device emits no ICMP responses | 9.4 |

---

## 18. References

### 18.1 Normative

- **[RFC2104]** Krawczyk, H., Bellare, M., Canetti, R., "HMAC: Keyed-Hashing for
  Message Authentication", RFC 2104.
- **[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119.
- **[RFC4291]** Hinden, R., Deering, S., "IP Version 6 Addressing Architecture",
  RFC 4291.
- **[RFC5869]** Krawczyk, H., Eronen, P., "HMAC-based Extract-and-Expand Key
  Derivation Function (HKDF)", RFC 5869.
- **[RFC6234]** Eastlake, D., Hansen, T., "US Secure Hash Algorithms (SHA and
  SHA-based HMAC and HKDF)", RFC 6234.
- **[RFC7748]** Langley, A., Hamburg, M., Turner, S., "Elliptic Curves for
  Security", RFC 7748.
- **[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key
  Words", BCP 14, RFC 8174.
- **[RFC8439]** Nir, Y., Langley, A., "ChaCha20 and Poly1305 for IETF Protocols",
  RFC 8439.
- **[KCP]** skywind3000, "KCP — A Fast and Reliable ARQ Protocol", reference
  implementation `ikcp.c`, <https://github.com/skywind3000/kcp>.
- **[SN-MSG]** "ShieldNet Message Layer", [`message-layer.md`](message-layer.md).

### 18.2 Informative

- **[SLED]** "ShieldLED Device Protocol", [`application.md`](application.md).
- **[DESIGN]** "ShieldNet v1 — Admission and Transport Envelope" (design notes),
  [`../design/transport.md`](../design/transport.md).
- **[THREAT]** "ShieldNet v1 — threat model and residuals",
  [`../design/threat-model.md`](../design/threat-model.md).

---

## Appendix A. Test vectors

The vectors are published with this specification in
[`../vectors/shieldnet-v1-vectors.json`](../vectors/shieldnet-v1-vectors.json),
produced by [`../vectors/gen_vectors.py`](../vectors/gen_vectors.py) from an
implementation independent of any ShieldNet implementation. A conforming
implementation MUST reproduce every value in the file.

| Section of the file | Pins |
| --- | --- |
| `inputs` | the nominal values the others are computed from. These are **independent inputs, not a chain**: `epoch_tag`, `cookie`, `canonical_source` and `observed_source` are fixed nominal values, and `context`, every authenticator and every message use *them* |
| `schedule` | the values listed under this table |
| `messages` | the complete INIT, RETRY, FINISH and ADMIT built from the nominal inputs |
| `wire_cases` | datagrams to classify. `role` is the receiver (0 device, 1 client); `cls` the expected classification (0 discard, 1 envelope, 2 INIT, 3 RETRY, 4 FINISH, 5 ADMIT); `decodes` whether the datagram then passes section 5.6. Covers the four valid messages, a 10-octet datagram of each type, every type one octet short and one long, non-zero padding, a wrong version, the reserved types, each type in the wrong direction, and two datagrams without `MAGIC` |
| `canonical_source` | section 7.1 for an IPv4 and an IPv6 peer |
| `source_local`, `source_cases` | section 7.2. Addresses are in 16-octet canonical form with `is_v4` giving the family; `source_local` lists the receiver's own addresses with their prefix lengths |
| `replay_script` | numbers presented in order to one window, with the expected result of each, covering both edges of the window |
| `reconstruct` | the `candidate` of section 11.5 for a `seq_wire` and an `hwm`: `d32 = 2^31`, `d32 = 2^31 - 1`, values just above and below `hwm`, a forward and a backward crossing of 2^32, a result of exactly 0, and results below the window |
| `reconstruct_range` | whether that `candidate` is in range (section 11.5): the first datagram of a session, a negative result, 0, exactly `REPLAY_WINDOW` below `hwm` (in range) and one further (not) |
| `envelope_size` | the length bounds of section 5.7 at `WIRE_MTU` 1400: 43 and 1401 discarded, 44 and 1400 accepted |

The `schedule` section pins:

- `prk_psk`, `k_dev`, `prk_static`, `k_req`, `k_resp`; the public keys `e_c`,
  `e_s`; `init_mac`, `retry_mac`, `client_tag`, `admit_pre`; `context`,
  `context2`; `dh`, `master`, the four session keys, `admit_tag`.
- `epoch_tag_out` is the tag derived from `cookie_secret` and `cookie_epoch_be`;
- `cookie_out` is the cookie derived from `cookie_secret`, the nominal
  `epoch_tag`, `canonical_source` and `client_nonce`.
- `envelope` and `envelope_s2c` seal the 9-octet `kcp_msg` at `seq_full` in each
  direction; they pin the sealing of section 11.1 only and are shorter than the
  minimum of section 5.7.
- `envelope_push` is a datagram a device accepts: `kcp_push` — one KCP PUSH
  segment, `sn = 0`, `conv` = `kcp_conv`, carrying `kcp_msg` — sealed
  client-to-device at `seq_full` 1, as the promoting datagram of a session is.
- `k_dev_psk2` and `k_dev_dev2` are `k_dev` under a second PSK and a second
  `device_id`.
- `dh_low_order` is the all-zero output for `low_order_point`

Behaviour that depends on a running peer cannot be expressed as byte vectors. An
implementation's own tests MUST cover at least:

- an INIT bearing another `device_id` (discarded before any MAC);
- a FINISH whose cookie is from the previous epoch (accepted) and from the one
  before (discarded);
- an INIT and a FINISH with each other's `type` octet (discarded: a relabelled FINISH fails
  the INIT padding check; a relabelled INIT fails the `epoch_tag` and cookie
  test);
- two admissions across a device restart (different cookie, `context`, `master`);
- a FINISH replayed from a different tuple (discarded at the cookie);
- a byte-identical FINISH (stored ADMIT sent again, expiry unchanged);
- two FINISHes racing on one `admission_epoch` (exactly one ADMIT);
- eviction of the earliest record when every slot is held;
- promotion by a datagram carrying `sn = 0` and `sn = 1` together; a datagram
  with `sn = 1` alone (discarded, not recorded);
- a duplicate of the promoting datagram (no second promotion); a second datagram
  after promotion (delivered to the primary);
- a pending record expiring, and one being replaced, while its promotion is in
  progress;
- a datagram accepted for a primary that is retired before it is delivered;
- replay of a captured datagram after promotion (refused);
- an ADMIT with a valid `admit_tag` and a corrupted `admit_pre` (discarded
  before any X25519);
- an ADMIT with a valid `admit_pre` and a corrupted `admit_tag`, followed by the
  genuine ADMIT (accepted);
- an ADMIT arriving in `AWAIT_PUSH_ACK` (discarded);
- a RETRY with a mismatched `observed_source`, and one with a bad `retry_mac`;
- quiesce and resume, preserving `seq_full`, the replay window and `conv`;
- the send bound: writes refused at `SEND_QUEUE_MAX` and accepted after it
  drains.

---

## Appendix B. Implementation notes (informative)

**Concurrency.** Several requirements are stated as atomicity (sections 9.2 step
7, 11.2 item 5, 11.3 step 5, 12.2, 10.5). How an implementation achieves them is
its own affair. The design notes describe one arrangement — a short lock for
record state and a separate lock for the KCP object, with cryptographic work done
under neither — and the hazards it avoids ([DESIGN] section 10).

**No cryptography while excluding other work.** Verification of an
unauthenticated datagram should not be performed while holding a lock that the
session's own processing needs, or a flood of forgeries delays the session.

**Memory.** With the default constants a device needs about 1.1 kB for pending
records and about 200 octets of per-session metadata beyond KCP's own state.
KCP's buffers dominate and are bounded by its receive window and by
`SEND_QUEUE_MAX`; [DESIGN] section 11 gives the arithmetic. A device should size
for two sessions, since promotion creates the new one before releasing the old.

**KCP tuning.** A set of values known to work: no-delay mode on, interval
20 ms, fast resend after 2 duplicate acknowledgements, congestion control off,
send window 32, receive window 8, dead-link threshold 20. Upstream KCP's
`ikcp_wndsize` raises any receive window below 128 to 128; a device that uses 8
must remove that clamp.

**Diagnostics.** Because every failure is silent, an implementation is well
advised to keep local counters of discards by cause. Counters are not secrets and
are not restricted by section 6.4 item 7.

---

## Appendix C. A worked admission (informative)

One complete admission, with the octets of every message. All values are from
the test-vector file of Appendix A, so an implementation can be checked against
each step. The inputs are chosen to be recognisable, not realistic: the nonce is
all `22`, the device identifier all `11`, and so on.

Some things differ from a live exchange, because the vector file fixes inputs so
that each computation can be tested on its own:

- `epoch_tag`, `cookie` and `observed_source` are nominal values (`33…`, `44…`,
  `aa…`), not values computed from a device's secret and the client's address
  as section 6.1 requires. A real client would reject this RETRY, whose
  `observed_source` is not its address.
- `admission_epoch` is `55…`, whose top eight bits are not all clear (`0x55` =
  `01010101`). A real device draws a value with those bits clear (section 3.4).
- The first message in C.6 is the nine octets `hello kcp`, standing in for a
  sealed message of [SN-MSG], which is at least 36 octets.

### C.1 Keys held before anything is sent

```
PSK        = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
device_id  = 1111111111111111

k_dev      = 9d2dc9b4d9b47262d4a4084266816d2aec487c1696630a361301a89d8fb4ed93      (section 3.2)
k_req      = 3cb0fa8aebaa8060d9e9bccc6583d47f814088b07a78373da15976562c07ec71      (section 3.3)
k_resp     = a45382686e51e308e94f246866befb0f4fd5c6b5177f37e7e8b58703e5860478
```

Two intermediate values lie between the PSK and these keys: `prk_psk`, from
which `k_dev` is expanded, and `prk_static`, from which `k_req` and `k_resp` are.

```
prk_psk    = 46bd320605c5a6b6163ab70bc6345b92a5f908e79fe58979c23ebb47d1a5e307
prk_static = daf1b4d25ba007863f566504280fa357ff7ef450de61025c2b0becf5199326e3
```

The client holds the PSK and derives the other three. The device was given
`device_id` and `k_dev`, and derived `k_req` and `k_resp` when it started.

### C.2 INIT, client to device

The client picks a nonce and names the device. `init_mac` is computed under
`k_req` over the label, type `01`, version `01`, the nonce and the identifier.

```
   0  MAGIC              534c44315a303031
   8  type               01
   9  version            01
  10  client_nonce       222222222222222222222222222222222222222222222222
  34  device_id          1111111111111111
  42  init_mac           23b5e62ac53384d94109f194374f4b90
  58  zero padding       00 … 00   (198 octets)
```

The device compares `device_id` with its own, verifies `init_mac`, and stores
nothing.

### C.3 RETRY, device to client

```
   0  MAGIC              534c44315a303031
   8  type               02
   9  version            01
  10  epoch_tag          3333333333333333
  18  cookie             44444444444444444444444444444444
  34  admission_epoch    5555555555555555
  42  device_id          1111111111111111
  50  observed_source    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  68  retry_mac          fa31e37eb0f610906dab2d18fda94036
```

The client checks that `observed_source` is its own address, verifies
`retry_mac` under `k_resp`, and checks `device_id`. It keeps `epoch_tag`,
`cookie` and `admission_epoch` to send back.

### C.4 FINISH, client to device

The client generates an X25519 key pair; `e_c` is the public half. `client_tag`
is computed under `k_req` over the label, type `05`, version `01`, the 65-octet
`context` and `e_c`.

```
   0  MAGIC              534c44315a303031
   8  type               05
   9  version            01
  10  client_nonce       222222222222222222222222222222222222222222222222
  34  epoch_tag          3333333333333333
  42  cookie             44444444444444444444444444444444
  58  admission_epoch    5555555555555555
  66  e_c                219e4d800da968d2a5fcb009c784f4746c7138edb9ee4844
                         b739e830b05cf424
  98  client_tag         49093e048cee846eff3138e5829a9971
 114  zero padding       00 … 00   (142 octets)
```

The device checks the cookie against the address this arrived from, checks that
`admission_epoch` is still current, and verifies `client_tag`. Only now does it
generate its own key pair and compute the shared secret:

```
dh         = f51374f53d26b1f83b4bccfc30b5c609abcaafbd97c3014794c7b45c42a1f059
master     = a6dd39d8509e3fc1de19d84428d24b4370bdde9fbfca48e259b8511ff3a70ea4
k_kcp_c2s  = 011d9b055e5fef5b60cf9844044f756dce326cf789ab70b256c2bf034ae09d82
```

(and `k_kcp_s2c`, `k_c2s`, `k_s2c` likewise). It installs a pending record
holding the four keys and advances `admission_epoch`.

### C.5 ADMIT, device to client

```
   0  MAGIC              534c44315a303031
   8  type               06
   9  version            01
  10  admission_epoch    5555555555555555
  18  e_s                1cf579aba45a10ba1d1ef06d91fca2aa9ed0a11505156531
                         55405d0b18cb9a67
  50  admit_pre          a2f94176780fc5af05f6645f3eb7f90f
  66  admit_tag          ee82a6988c67e4ce6e92fdae3fb9d86e
```

`admission_epoch` is the value the client sent, not the device's new one. The
client verifies `admit_pre` under `k_resp`, then computes the same `dh` and
`master` from its own private key and `e_s`, and checks that `admit_tag` is what
it derives. Both sides now hold the same four session keys.

### C.6 The first datagram, client to device

The client's first message goes into KCP, which emits one PUSH segment with
`sn = 0`. KCP's header is little-endian:

```
   0  conv               44332211
   4  cmd                51
   5  frg                00
   6  wnd                2000
   8  ts                 00000000
  12  sn                 00000000
  16  una                00000000
  20  len                09000000
  24  data               68656c6c6f206b6370
```

That is `conv` 0x11223344, `cmd` 81 (PUSH), a `wnd` of 32, a nominal value fixed
by the vector file and not a recommendation (Appendix B), `sn` 0, and nine
octets of data. The client seals it under `k_kcp_c2s` with `seq_full` = 1 —
nonce `43 32 53 00` followed by eight octets holding 1 — and appends the low 32
bits of the sequence and the tag:

```
   0  ciphertext         9302eeefc942b487667cad36c5756ceed47439394fafcbac
                         9a602432d755303370
  33  seq_wire           00000001
  37  tag                2fb179d6f1bd34648ea2e00cf312e215
```

The device finds the pending record for this address, rebuilds `seq_full` = 1
from `seq_wire`, opens the datagram under the record's `k_kcp_c2s`, sees a PUSH
with `sn = 0`, and promotes the record. The session exists, and whatever session
the device had before is gone.
