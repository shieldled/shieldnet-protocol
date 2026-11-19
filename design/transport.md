# ShieldNet v1 — Admission and Transport Envelope

> **Design notes — informative.** The specification is
> [`spec/transport.md`](../spec/transport.md) (ShieldNet Transport Protocol).
> This document is the reasoning behind it: what each rule is for, and what was
> considered and rejected. Where the two differ, the specification governs.
> Where these notes say a rule is required, the specification is what requires
> it.

**Status:** design notes for version 1 (§4.7).
**Scope:** the UDP admission exchange and the authenticated envelope around
every KCP datagram. **Out of scope:** the post-admission ShieldNet message
layer, referenced not restated (§13) and discussed in
[`message-layer.md`](message-layer.md).
**Goals, in priority order:** (1) no unauthenticated peer can allocate state,
displace a session, or affect KCP; (2) fixed, small, measurable device cost, so
an ESP32-class microcontroller keeps headroom for the application; (3)
simplicity — every mechanism must name the attack it stops.
**Rationale lives beside this document:** §14 — the threat model, the residuals
and the reasoning — is [`threat-model.md`](threat-model.md), kept separate so
these notes can be read without it; §14.0 indexes it. It is the same numbered
section, and every `§14.x` citation below resolves there.

Where these notes use "must" in lower case they are describing what a design
needs; what an implementation is required to do is in `spec/transport.md`.

---

## 0. Conventions and references

**Encoding.** `||` is octet concatenation. Multi-byte integers are big-endian
**on the wire and wherever they are an input to a cryptographic function** —
including `seq_full` inside the AEAD nonce and `cookie_epoch` inside
`epoch_tag`'s input, neither of which is a wire field. This does **not** extend
into the KCP payload (§8.7).

**Labels.** Every domain label is encoded `uint8(len) || label`, written
`L("...")`, US-ASCII, no terminator. The invariant that matters is **per key**:
no two labels used under one key may be ambiguous. Length prefixing enforces it
mechanically. The keys carrying more than one label are `prk_static` (`req`,
`resp`), `k_req` (`init`, `finish`), `k_resp` (`retry`, `admit-pre`),
`cookie_secret` (`cookie`, `epoch`) and `master` (`c2s`, `s2c`, `kcp-c2s`,
`kcp-s2c`, `admit`). The PSK's own PRK, `prk_psk`, carries one (`device`).
Labels are listed rather than counted so the check can be made by reading; any
new label under any of these keys re-opens it.

**`HMAC/128(k, m)`** is the leading 128 bits of HMAC-SHA-256(k, m).

**HKDF** is RFC 5869, Extract and Expand named separately. `salt=""` means 32
zero octets. Note that §4.5's `master` salt exceeds SHA-256's 64-octet block, so
RFC 2104 pre-hashes it — correct and intended, but it is the >64-octet path and
every implementation must take it.

**PSK** is exactly 32 octets of uniformly random secret. It is held by
**controllers only**. **`device_id`** is 8 octets, unique within a PSK domain.

A device **never stores** the PSK. It holds its own

~~~
prk_psk = HKDF-Extract(salt="", ikm=PSK)
k_dev   = HKDF-Expand(prk_psk, L("shieldled/v1/device") || device_id, 32)
~~~

and its `device_id`. (The specification, `spec/transport.md` 3.2, also lets a
device be *given* the PSK once, at a provisioning interface, solely to derive
`k_dev` and erase the PSK at once; a provisioning portal on the device works
that way. Automated provisioning installs `k_dev` directly.) **One PSK is live
at a time** (§4.7). A controller holds the PSK and derives `k_dev` for whichever
device it is addressing. Everywhere below that says "the PSK" as a key-schedule
input means **`k_dev`** — the two sides compute the same value by different
routes.

Were every device given the PSK, extracting the key from one device would yield
full active capability against every device *and every controller* in the domain
— and §14.6 notes the key sits unencrypted in flash. With per-device derivation,
opening one device yields that device only: `k_dev` is one-way from the PSK, so
it does not let the attacker derive any sibling's key, impersonate a controller
to a sibling, or read any other device's traffic. It costs one Extract and one
Expand at provisioning time and nothing at runtime.

### 0.1 Where these notes discuss each rule

Each rule is discussed **once**. Where another section needs it, it cites rather
than restates. This table says which section discusses what; changing a rule
means changing the specification, and these notes follow.

| Subject | Where these notes discuss it | Sections that cite it |
| --- | --- | --- |
| Wire layouts, offsets, message lengths, padding | **§3** | §6, §7, §12, §15 |
| Constants and timer values | **§2** | §4, §6, §7, §9, §11, §12 |
| Key schedule, every MAC and its coverage | **§4** | §6, §7, §11, §12, §15 |
| Device key and provisioning | **§0** | §4.1, §4.7 |
| PSK replacement and the fresh-PSK requirement | **§4.7** | §14 |
| Which lock guards which operation, and acquisition order | **§10** | §6, §8, §9 |
| Device control-path procedure | **§6** | §9, §12 |
| Client state machine and procedures | **§7** | §14, §15 |
| Envelope receive/send procedure | **§8** | §7, §11, §12 |
| Per-input CPU and response cost | **§12** | §2, §11, §14 |
| Memory footprint | **§11** | §9, §14 |
| Threat model, residuals, out-of-scope | **§14** ([separate file](threat-model.md)) | §11, §12 |
| Demultiplexing, and where source rejection runs | **§5** | §6, §8 |
| The source-rejection list itself | **§4.3** | §5, §14 |
| Device state and lifecycle | **§9** | §6, §7, §8, §14 |
| Message layer carve-outs (compression, padding); the rules are `spec/message-layer.md` 6 and `spec/application.md` 3.5 | **§13** | §2, §14 |
| Test vectors | **§15** | §4.5, §8.3, §14 |
| The message layer itself (framing, AEAD, `MessageNum`) | **[`message-layer.md`](message-layer.md)** | §13 |

The "Sections that cite it" column is indicative, not exhaustive — it names
where a rule is leaned on hardest, not every mention.

**If you find a rule discussed twice, that is a defect** — independent of
whether the two statements currently agree.

**References:** RFC 5869, 7748, 8439, 2104, 6234, 4291 §2.5.5.2, and KCP as
implemented by `ikcp.c` (§8.7).

---

## 1. Overview

A device holds at most one authenticated primary KCP session. Admission is a
client-driven raw-UDP exchange on the socket and source port that will
afterwards carry KCP — **two round trips**:

~~~
client                                        device
  INIT   (nonce, device_id,            ->  verify init_mac; NO state
          init_mac, pad)
                                       <-  RETRY (epoch_tag, cookie,
                                                  admission_epoch, device_id,
                                                  observed_source, retry_mac)
  FINISH (nonce, epoch_tag, cookie,    ->  verify cookie + client_tag; X25519;
          admission_epoch, e_c,            install a pending record for this tuple
          client_tag, pad)
                                       <-  ADMIT (admission_epoch, e_s,
                                                  admit_pre, admit_tag)
  envelope(KCP PUSH sn=0)              ->  create KCP; replace primary
~~~

The primary is replaced **only** at the last step — never by FINISH alone, never
by an unauthenticated datagram, never by a timeout.

---

## 2. Constants

| Name | Value |
| --- | --- |
| `MAGIC` | `"SLD1Z001"` (`53 4c 44 31 5a 30 30 31`) |
| `VERSION` | `0x01` |
| `TYPE_INIT` / `RETRY` / `FINISH` / `ADMIT` | `0x01` / `0x02` / `0x05` / `0x06` |
| `HEADER_LEN` | 10 (`MAGIC[8] \|\| type[1] \|\| version[1]`) |
| `REQUEST_LEN` | **exactly 256** |
| `COOKIE_EPOCH_MS` | **4 000** (current + previous accepted) |
| `PENDING_TTL_MS` | **5 000** |
| `PENDING_SLOTS` | deployment constant, **default 2** — concurrent in-flight admissions, tuple-keyed (§6.3). One per controller that §14.0a allows; raise only with §11's memory figure re-checked |
| `REPLAY_WINDOW` | 256 packets |
| `ENVELOPE_LEN` | 20 (`seq_wire[4] \|\| tag[16]`) |
| `KCP_OVERHEAD` | 24 (§8.7) |
| `WIRE_MTU` | deployment constant, default 1400 |
| `SEND_QUEUE_MAX` | deployment constant, default 32 KiB (§9.5); §11 recommends 6 KiB on an ESP32-class board |
| `MAX_MSG_PAYLOAD` | deployment constant, **per architecture**: the largest message-layer `Size` (sealed body plus tag, `spec/message-layer.md` 4.1) a **sender** emits. The whole message — `MAX_MSG_PAYLOAD` plus its 20-octet header — has to fit an empty send queue, which the specification requires (`spec/message-layer.md` 7.3). It is a send bound only; what a peer can *receive* is that peer's own bound (`spec/message-layer.md` 7.3) |
| `INIT_RETRY_MS` / transmissions | 1 000 / 3 |
| `FINISH_RETRY_MS` | 500 |
| `FINISH_PHASE_MS` | deployment constant, **default 1 500**, which the specification requires to be below `COOKIE_EPOCH_MS` — the whole FINISH phase, client-side (see the second budget below) |
| `PUSH_ACK_TIMEOUT_MS` | 2 000 |
| `SESSION_DEAD_MS` | 10 000 — client-side, see §7.2 |
| retry jitter | **±20 %**, uniform, on `INIT_RETRY_MS` and `FINISH_RETRY_MS`, so two controllers told to take control at once do not retransmit in lockstep. `FINISH_PHASE_MS` is a hard clamp that jitter must not exceed. There is **no attempt backoff** — see §7.2 |

`0x03` and `0x04` are **reserved, and the specification has a receiver reject
them**.

Requests are a **fixed** 256 octets, not a range. That removes a length field
from every MAC, makes the stored-FINISH comparison of §6.2 step 2 a fixed-size
`memcmp`, and leaves nothing about a request's size for an implementation to get
wrong.

**The admission timing budget.** `PENDING_TTL_MS` runs from the instant the
device **installs** a pending record, and is **never extended for that record**.
Everything both peers do between that instant and the promoting PUSH must fit
inside it:

~~~
RTT
  + the client's admission work   (per-operation counts: §12)
  + PUSH transmit                                          <  PENDING_TTL_MS
~~~

The **client's** scalar multiplication is inside this budget; the **device's**
is not, because §6.2 does its DH at step 6 and installs the record at step 7 —
the clock starts after its own work is done. The client's X25519 on an
unaccelerated ESP32-class microcontroller is the dominant term (this document
states no cycle figure for it; §11 gives only code size and stack), which is why
`PENDING_TTL_MS` is 5 000. The device's work matters to §12's per-input cost,
not to this budget.

**A replacing FINISH installs a new record with a full TTL; a byte-identical
resend extends nothing.** The distinction is the whole of it. A resend (§6.2
step 2) is a bare replay — anyone who captured the datagram can send it — so
letting it refresh the clock would allow an indefinite hold. A *replace* is a
different, freshly authenticated FINISH: it costs its sender a valid
`client_tag` at the current `admission_epoch`, which for an attacker means a
fresh capture and a fresh suppression per refresh (§14.4). Charging a legitimate
controller's retry the remainder of its own suppressed attempt's clock would be
the perverse reading — it would let an attacker shorten a legitimate retry's
window for free, by starting the clock early with a replay.

For eviction (§6.3), a record's age is measured from the same instant: its most
recent install, not the first time its tuple was ever occupied.

Nor would a refresh help a client that is merely *slow*: it stops retransmitting
the moment ADMIT lands, so no refresh would ever fire for it.

`PUSH_ACK_TIMEOUT_MS` (2 000) is a *post-admission* timer and is not inside the
TTL; a client whose PUSH is unanswered for that long returns to IDLE (§7.2), and
any new attempt is an application decision.

The specification requires an implementation to state the processing times
needed to check this inequality, and a deployment to check it for its slowest
pair (`spec/transport.md` 4.3); these notes recommend measuring the client's
X25519 for that. Where it does not hold, raise `PENDING_TTL_MS` — do not shorten
the FINISH phase, which would break the retransmission guarantee.

**The FINISH phase has its own budget, and the device's work is inside this
one.** The client leaves `AWAIT_ADMIT` for IDLE when `FINISH_PHASE_MS` expires
(§7.2), and the ADMIT it is waiting for is not sent until the device has
finished §6.2 step 6:

~~~
RTT
  + the device's FINISH work   (3 HMAC + 2 X25519 + 6 HKDF: §12)   <  FINISH_PHASE_MS
~~~

The specification requires a deployment to check this inequality as well, for
its slowest pair; these notes recommend measuring the device's FINISH processing
on its slowest supported device. Where it does not hold, raise `FINISH_PHASE_MS`
on the controllers — it is a client-side constant and changes nothing on the
wire — keeping it below `COOKIE_EPOCH_MS`, the minimum lifetime of the cookie
the phase depends on (§7.3). Without this check a device whose two scalar
multiplications outlast the phase can never admit anyone, and §9.3 forbids it
from saying so.

**`PENDING_TTL_MS` and `PENDING_SLOTS` must be sized together.** The TTL is how
long a record occupies a slot, so raising it to accommodate slow X25519
proportionally raises how long an attacker's captured FINISH holds one, and how
long the slot table stays full. An implementation that raises the TTL should
raise `PENDING_SLOTS` with it, and re-check §11's memory figure for pending
records; never shorten the FINISH phase to make room. The default of 2 is one
slot per controller that §14.0a allows; it carries no spare, so a deployment
whose controllers admit simultaneously should raise it rather than rely on
eviction. Getting this wrong produces a client that can **never** be admitted
and, because §9.3 forbids every signal, cannot discover why.

**No count cap is placed on the evaluation of unauthenticated inbound
messages.** A budget of "evaluate at most K" is spent as fast by junk as by the
genuine message, so an attacker sends K forgeries and the real one is never
examined — converting a bounded CPU drain into an unbounded denial. All
client-side verification is bounded by the **phase timer** — but only in the
phases that have one. `AWAIT_PUSH_ACK` and `ESTABLISHED` do not, so a spoofed
envelope at an established client's tuple (§7.5) is bounded by nothing here. The
residual drain is in §14.

`COOKIE_EPOCH_MS` is 4 000. The cookie's job is return-routability over the ~1.5
s between RETRY and FINISH, so any epoch length beyond that is pure attack
surface: a **suppressed** FINISH — one the device never accepted, so
`admission_epoch` never advanced — stays acceptable for the whole
current-plus-previous window, which at 4 000 is 8 s. A short epoch does not
close the replay (see §14.4); it makes the capture perishable.

`cookie_epoch` is `floor(monotonic_ms_since_boot / COOKIE_EPOCH_MS)` as
`uint32`. At boot it is 0, so "the previous epoch" is undefined for the first
`COOKIE_EPOCH_MS`; the specification has a device accept only the current epoch
until the first epoch has completed, rather than computing `current - 1` and
wrapping to `0xFFFFFFFF`. The specification requires `monotonic_ms_since_boot`
to be monotonic and never to wrap during uptime (`spec/transport.md` 9.1.1),
which in practice means a **64-bit** source (on a microcontroller, its 64-bit
hardware timer): a 32-bit millisecond tick wraps at 49.7 days, inside this
protocol's envelope (§9.5 forbids idle timeout, §8.3 reasons about ~99-day
sessions), and at that wrap epochs run backwards and are reused under an
unchanged `cookie_secret`. The obvious implementation choice is the wrong one
and no test vector catches it.

---

## 3. Wire format

Every control datagram begins `MAGIC[8] || type[1] || version[1]`. The
specification has a receiver verify all ten octets and reject any other
`version`. Offsets are zero-based from the start of the UDP payload.

### 3.1 INIT — `0x01`, N = 256

| Offset | Field | Len |
| ---: | --- | ---: |
| 0 | `MAGIC \|\| type \|\| version` | 10 |
| 10 | `client_nonce` | 24 |
| 34 | `device_id` (the device the client is addressing) | 8 |
| 42 | `init_mac` | 16 |
| 58 | zero padding | 198 |

`device_id` names the intended device, and the specification has a device
silently drop an INIT carrying any other value.

It is kept for two reasons. It lets a device reject a misdirected INIT with
**zero cryptography** — the cheapest rejection in the protocol (§6.1 step 2) —
and it binds the intended device into `context` (§4.5), a backstop behind
per-device `k_dev`: a FINISH relayed to a sibling already fails at the sibling's
cookie check (§6.2 step 3), and its `client_tag` is under another device's
`k_req`.

A cross-device RETRY relay is not one of them: replay a client's INIT at a
sibling device, capture the sibling's genuine RETRY, inject it at the client
with the source rewritten, and the client would send its FINISH carrying the
wrong device's cookie. That attack **does not apply**: `k_resp` derives from
`k_dev` (§0), so a sibling's `retry_mac` cannot verify at a client that derived
`k_dev` for the device it addressed. Do not remove `device_id` on the strength
of that — the zero-cryptography rejection stands on its own.

### 3.2 RETRY — `0x02`, N = 84

| Offset | Field | Len |
| ---: | --- | ---: |
| 0 | `MAGIC \|\| type \|\| version` | 10 |
| 10 | `epoch_tag` | 8 |
| 18 | `cookie` | 16 |
| 34 | `admission_epoch` | 8 |
| 42 | `device_id` | 8 |
| 50 | `observed_source` (§4.3) | 18 |
| 68 | `retry_mac` | 16 |

`epoch_tag` is an **opaque 8-octet value** the client echoes in FINISH without
interpreting. Eight, not four: it is an input to `cookie` and to `context`, so a
recurrence makes a suppressed FINISH acceptable again — at four octets that is
about `N²/2³³` over `N` epochs, which at one epoch per 4 s is not negligible
over a device's life. Eight octets pushes recurrence past any deployment
lifetime and makes §14.4's bound on a suppressed capture true rather than
approximately true. It stands in for `cookie_epoch` everywhere that feeds a
derivation (§4.4), and the raw epoch never appears on the wire — `cookie_epoch`
is `floor(uptime / COOKIE_EPOCH_MS)`, so sending it raw would disclose uptime in
a single sample. What the opaque tag buys is narrow. It does not stop an
observer who polls **from boot onward**, who still counts boundaries and
recovers uptime at `COOKIE_EPOCH_MS` resolution (§14.4). What it denies is the
*late-arriving* observer, who cannot recover uptime accrued before it started
watching.

`observed_source` is the `canonical_source` the cookie was minted for. The
client compares it against its own socket address (§7.3 step 2). It closes this:
an attacker replays the client's INIT from its **own** address, receives a
genuine RETRY whose cookie is bound to that address, and injects it; the
client's FINISH is then dropped for tuple mismatch with no diagnosis. The check
works because the deployment is a local link with no address translation. **If
translation ever comes into scope this check must be relaxed and that attack
returns.**

`device_id` lets the client detect that it is talking to a different device than
it addressed — see §14 for what that does and does not cover.

### 3.3 FINISH — `0x05`, N = 256

| Offset | Field | Len |
| ---: | --- | ---: |
| 0 | `MAGIC \|\| type \|\| version` | 10 |
| 10 | `client_nonce` | 24 |
| 34 | `epoch_tag` | 8 |
| 42 | `cookie` | 16 |
| 58 | `admission_epoch` | 8 |
| 66 | `e_c` (X25519 public) | 32 |
| 98 | `client_tag` | 16 |
| 114 | zero padding | 142 |

### 3.4 ADMIT — `0x06`, N = 82

| Offset | Field | Len |
| ---: | --- | ---: |
| 0 | `MAGIC \|\| type \|\| version` | 10 |
| 10 | `admission_epoch` | 8 |
| 18 | `e_s` (X25519 public) | 32 |
| 50 | `admit_pre` | 16 |
| 66 | `admit_tag` | 16 |

`admission_epoch` is the value the client **presented in FINISH**, not the
device's post-increment value — the only value the client can reproduce.

`admit_pre` comes from the static key schedule, not from `master`, so it is
checkable **before** the client's X25519. Without it, ADMIT's only cheap filter
is the cleartext epoch, and an attacker spoofing the device could force a scalar
multiplication plus six HKDF operations per packet on a client that may itself
be a microcontroller.

### 3.5 Padding

**Every message has a fixed length, and the specification has a receiver verify
it before reading any field beyond the 10-octet header:** INIT and FINISH
exactly `REQUEST_LEN` (256, zero-padded), RETRY exactly 84, ADMIT exactly 82.
`context` is 65 octets and `master`'s salt 149; `init_mac`'s input is 52 and
`client_tag`'s 119. Assert those in a test rather than assuming them — a
transposition of two fixed-width fields is otherwise self-consistent. A receiver
rejects any other length, and rejects non-zero padding in a request, as the
specification requires.

This is a memory-safety rule, not a policy one. Were the length requirement
stated only for requests, a 10-octet `MAGIC || 0x02 || 0x01` would pass the
demux and the header check and reach a client's RETRY handler, which reads
`observed_source` at offset 50 and `retry_mac` at 68 — an out-of-bounds read of
~70 octets, from any spoofed source, **before any cryptographic check**, since
§7.3 step 2 compares `observed_source` first. Length validation precedes every
field access.

### 3.6 Transport envelope

~~~
ciphertext[n] || seq_wire[4] || tag[16]

direction_label   = "C2S\x00" (client→device) or "S2C\x00"
nonce[12]         = direction_label || seq_full[8]        (big-endian)
(ciphertext, tag) = ChaCha20-Poly1305-IETF-detached(
                        key = k_kcp_<dir>, nonce = nonce,
                        ad  = seq_wire, msg = kcp_datagram)
~~~

**Size bounds.** The specification requires an envelope datagram to satisfy
`KCP_OVERHEAD + ENVELOPE_LEN ≤ N ≤ WIRE_MTU`. The upper bound is mandatory:
without it a spoofed tuple plus a fragmented 64 KB datagram buys an AEAD open
over ~47× the bytes of a full-`WIRE_MTU` one, the only cost in §12 that would
otherwise scale with an attacker-chosen length.

`seq_full` is a direction-local `uint64` starting at 1 for a newly admitted
session and **never restarting for that session's life**, including across
quiesce/resume (§9.4). `seq_wire` is its low 32 bits. A sender emits a fresh
`seq_full` for every datagram including a KCP retransmission, and fails closed
rather than wrapping, both of which the specification requires: once it has used
`2^64 − 1` it refuses to send on that session — which `atomic_fetch_add` alone
cannot do (§10.1).

---

## 4. Key schedule

### 4.1 Long-lived, derived once at init

~~~
prk_static = HKDF-Extract(salt = "", ikm = k_dev)   /* §0: the device holds
                                                        k_dev; a controller
                                                        derives it from the PSK */
k_req      = HKDF-Expand(prk_static, L("shieldled/v1/req"),  32)   /* client→device */
k_resp     = HKDF-Expand(prk_static, L("shieldled/v1/resp"), 32)   /* device→client */
~~~

Both are boot constants, derived once at init. An implementation that derives
them per datagram doubles the cost of the floods §12 bounds.

### 4.2 Per-boot device secrets

From a CSPRNG at boot, RAM only, never persisted, never PSK-derived:

- `cookie_secret[32]`
- `admission_epoch` — random non-zero `uint64` with the top 8 bits cleared

Nothing is persisted. Cross-boot separation comes from `cookie_secret`: two
boots collide only if 32 octets of CSPRNG output repeat, and `cookie_secret` is
an input to `cookie`, which is an input to `context`. The freshly drawn
`admission_epoch` also means no FINISH captured before a restart carries the
current value.

Per-boot secrets make a captured admission useless after a restart, and
per-device `k_dev` (§0) makes it useless at another device in the same domain;
making cookies survive a reboot would open replay across restarts.

**CSPRNG requirement, applying to BOTH parties.** Every random value in this
document — the device's secrets above and its ephemeral keypair (§6.2 step 6),
and the client's `client_nonce` and ephemeral keypair (§7.2) — comes, as the
specification requires, from a cryptographically secure random source. What that
source *is* is a platform matter and deliberately not named here; what the
protocol requires of it is:

1. It is a CSPRNG, not a PRNG seeded from a predictable value.
2. **It is fully available before the first value is drawn.** The specification
   has a device not serve admission, and a client not attempt one, until it is.

**The rest of this document assumes both rules hold**, and reasons about no
scenario in which a drawn value repeats. That is a deliberate boundary: a
protocol cannot defend against its own randomness being predictable, and a
mechanism that tried — a persisted counter — would buy a birthday bound, a
reboot oracle and a flash-wear brick, for a threat the platform is responsible
for excluding. Where a rule below is justified by "this value is unique", the
justification is rule 1, not a second mechanism.

**Platform note.** On a microcontroller the source is its hardware RNG. On parts
with a radio the RF subsystem must be up first — which admission already
implies, since a device needs a bound address to serve on. On radio-less parts
no such precondition applies. Elsewhere the source may be a syscall
(`getrandom`), a library routine (`arc4random_buf`, `crypto/rand`), or a CPU
instruction (`RDSEED`, `RNDR`).

### 4.3 Canonical source

~~~
canonical_source = ipv6_address[16] || port_be[2]
~~~

IPv4 as IPv4-mapped IPv6 per RFC 4291 §2.5.5.2 — `00×10 || ff ff || a.b.c.d`,
not the IPv4-compatible form.

**A datagram whose source matches any entry below is dropped, as the
specification requires. Everything else is accepted.** The test is applied to
the received source address in its own family, *before* canonicalisation.

| Family | Reject |
| --- | --- |
| IPv4 | `224.0.0.0/4` (multicast) · `255.255.255.255` and the broadcast address of any local subnet · `0.0.0.0/8` · `127.0.0.0/8` (loopback) · any address assigned to the receiving interface |
| IPv6 | `ff00::/8` (multicast) · `::` (unspecified) · `::1` (loopback) · `::ffff:0:0/96` (a genuine v6 source in the mapped range — it would canonicalise as a v4 peer) · `::/96` (IPv4-compatible, deprecated) · any address assigned to the receiving interface |

This is deliberately a **rejection list, not an acceptance category.** An
acceptance category such as "a global or link-local unicast address" would be
IPv6 vocabulary applied to addresses that `canonical_source` has turned into
`::ffff:a.b.c.d`. Two correct implementations disagree on that: read negatively
(not multicast, loopback, unspecified or link-local — Go's `IsGlobalUnicast`)
nearly every IPv4 peer passes; read positively (the IANA global range
`2000::/3`) **every IPv4 peer is rejected**, because no mapped address is in
`2000::/3`. The second reading silently drops every controller, permanently,
with no signal (§9.3). "Link-local" splits the same way: `169.254.0.0/16` is
link-local in IPv4, but `::ffff:169.254.1.1` is not in `fe80::/10`, so a scope
macro applied to the canonical form gets it wrong.

**RFC1918, `169.254.0.0/16`, `100.64.0.0/10`, `fe80::/10` and `fc00::/7` are all
accepted.** They are what this deployment actually uses — SoftAP hands out
`192.168.4.x`, STA gets RFC1918, a failed DHCP autoconfigures `169.254.x.x` —
and none of them makes the device transmit to more than one peer, which is the
only property the rule needs.

The threat is narrow and the list matches it exactly: a replayed INIT carrying a
group-address source elicits a RETRY sent to that group, which 802.11 transmits
at the lowest basic rate, unacknowledged, to every station on the BSS — one
attacker packet becoming tens of times its airtime, received link-wide. That is
genuine amplification on the resource §12 says is the contended one, from a byte
ratio §12 calls harmless. Nothing about it requires classifying unicast
addresses.

**The specification requires the admission socket to be bound to a single
interface.** `canonical_source` carries no zone identifier, so on a device
running SoftAP and STA at once — ordinary for an ESP32-class board with a config
portal — `fe80::1%ap` and `fe80::1%sta` are different peers that canonicalise
identically. The cookie is the *only* tuple binding (§6.2 step 3), and a
collision there also makes one peer's pending record reachable by another.
Binding to one interface is cheaper than carrying a zone through every
derivation.

### 4.4 Request and response MACs

`type` and `version` are inputs to every MAC **over a wire message** below —
`init_mac`, `retry_mac`, `client_tag`, `admit_pre`. Binding them is what closes
cross-type reinterpretation directly, instead of resting it on padding content
and on `admission_epoch` happening to be non-zero.

They are **not** inputs to `cookie`. The reason is not that `cookie` is
device-internal — it is a wire field in both RETRY and FINISH. It is that
`cookie` is computed under `cookie_secret`, a key used for two labelled purposes
and never to MAC a wire message, so there is no second message type it could be
confused with (§0).

`admit_tag` (§4.5) is an HKDF output rather than a MAC: it binds `version`
through `context` and binds `type` **not at all**. That is safe only because
`admit_pre` covers `type` and is checked first (§7.4); it is not a property
`admit_tag` provides.

~~~
init_mac  = HMAC/128(k_req,  L("shieldled/v1/init") || type || version ||
                             client_nonce || device_id)

epoch_tag = HMAC-SHA-256(cookie_secret,
                         L("shieldled/v1/epoch") || cookie_epoch)[0:8]

cookie    = HMAC/128(cookie_secret,
                     L("shieldled/v1/cookie") || epoch_tag ||
                     canonical_source || client_nonce)

retry_mac = HMAC/128(k_resp, L("shieldled/v1/retry") || type || version ||
                     client_nonce || epoch_tag || cookie ||
                     admission_epoch || device_id || observed_source)
~~~

`epoch_tag` is **cached, not recomputed per datagram**: it changes once per
`COOKIE_EPOCH_MS`. **The §9.2 maintenance tick recomputes it on the boundary**,
not a receive path — the recompute is an HMAC, and §10.3 forbids cryptography
under either lock, so a lazy recompute under a reader's lock would break that
rule on the cheapest attacker-drivable path. The two cached tags are `rec_lock`
state (§10.1).

**Which epoch is current is decided by the handler's clock, not by the cache.**
INIT and FINISH each read `monotonic_ms_since_boot`: INIT issues the cookie
under the tag of the epoch that reading falls in, and FINISH accepts exactly
that epoch and the one before it (none before epoch 0). The cached tags serve
the common case. If the tick has stalled and a cached tag belongs to some other
epoch, the handler computes the tag it needs on demand, outside both locks
(§10.3); that costs one extra HMAC only while the tick is late. Without this
rule a stalled maintenance tick stretches a cookie's life without bound, because
acceptance would follow the cache rather than time.

`init_mac` is **not authentication**: `k_req` is long-lived and a captured INIT
stays replayable. It makes the port silent to a peer that has never observed a
client, and costs one HMAC to reject. The PSK proof is `client_tag`.

`retry_mac` proves that a holder of the addressed device's `k_dev` — that
device, or a PSK holder — minted this RETRY for this `client_nonce`, which is
what stops a blind attacker — RETRY does not echo enough for the client to
correlate otherwise. It does not by itself prove the cookie was minted for the
client's tuple; `observed_source` does that.

### 4.5 Transcript and session keys

~~~
context   = version || client_nonce || epoch_tag || cookie ||
            admission_epoch || device_id
context2  = context || e_c || e_s

client_tag = HMAC/128(k_req,  L("shieldled/v1/finish")    || type || version ||
                              context || e_c)

dh        = X25519(own_ephemeral_private, peer_ephemeral_public)
master    = HKDF-Extract(salt = L("shieldled/v1/master") || context2,
                         ikm  = k_dev || dh)      /* 32 || 32, unambiguous */
k_c2s     = HKDF-Expand(master, L("shieldled/v1/c2s"),     32)
k_s2c     = HKDF-Expand(master, L("shieldled/v1/s2c"),     32)
k_kcp_c2s = HKDF-Expand(master, L("shieldled/v1/kcp-c2s"), 32)
k_kcp_s2c = HKDF-Expand(master, L("shieldled/v1/kcp-s2c"), 32)

admit_pre = HMAC/128(k_resp,  L("shieldled/v1/admit-pre") || type || version ||
                              context2)
admit_tag = HKDF-Expand(master, L("shieldled/v1/admit"), 16)
~~~

The device uses **its own** `device_id` when building `context`, never a value
taken from a received datagram; FINISH does not carry it. This is a backstop: a
FINISH relayed to a sibling already fails at the sibling's cookie check (§6.2
step 3), and its `client_tag` is under another device's `k_req`. Were both
bypassed, the sibling would compute a different `context`, hence a different
`master`, and its ADMIT would fail the client's `admit_tag`.

`version` is in `context` so that the session keys themselves are
version-separated: without it, cross-version key separation would rest entirely
on §4.7's deployment rule with no cryptographic backstop. It costs one octet of
MAC input and nothing on the wire.

`admit_tag` is an Expand output rather than a MAC because `master` already
commits to `context2` through its salt; this removes a key and an HMAC without
weakening the binding. **Consequence for future edits:** it covers ADMIT only
through `context2`, so any field added to ADMIT that is not also added to
`context2` becomes silently unauthenticated — there is no MAC over the message
to catch the omission the way `retry_mac` would, and `admit_pre` too covers only
`context2`. It is DH-derived, so it is the client's proof the device completed
the agreement. `admit_pre` comes from the static key schedule, so it is
checkable first.

Required:
- The X25519 rejection rule is: compute per RFC 7748 and **reject if and only if
  the 32-octet output is all zero** — the check a general-purpose X25519
  library's scalar-multiplication call reports. The specification forbids
  substituting a small-order blacklist or a `u < p` test; they reject different
  sets and §15 requires every implementation to agree.
- The **device** wipes its ephemeral private key as soon as `dh` is computed; it
  never stores one (§6.3).
- **Both parties wipe `master` as soon as its five Expand outputs exist**, on
  success as on failure. Nothing reads it afterwards, and it re-derives all four
  session keys, so a retained copy is a fifth session key with no use. The
  device wipes `dh` at the same point; the client keeps `dh` only as §7.4 step
  4's cache, until it leaves `AWAIT_ADMIT`.
- The **client** retains its ephemeral private key until it leaves `AWAIT_ADMIT`
  (§7.2), and wipes it on that transition — **not** when `dh` is computed.
  Wiping earlier is exploitable: `context2` does not cover `admit_tag`, so
  ADMIT's last 16 octets are malleable past `admit_pre`. An attacker flips one
  bit there, the client computes `dh`, wipes, derives, and only then fails
  `admit_tag` — after which the genuine ADMIT the device resends can never be
  processed, because the private key matching the `e_c` inside the client's own
  `client_tag` is gone and §7.2 forbids re-drawing it mid-attempt. One stored
  template and one bit per attempt is a permanent, targeted denial of admission
  with no PSK and no ability to drop packets. `admit_pre` bounds how many DHs a
  forged ADMIT can force, so retaining the key costs nothing an attacker can
  drive.
- A fresh CSPRNG `client_nonce` and a fresh ephemeral keypair per **admission
  attempt**, held constant across every retransmission within it. §7.2 discusses
  that rule and why it holds.

### 4.6 Forbidden

- **A fixed-nonce AEAD tag is not used as a handshake authenticator.**
  XChaCha20-Poly1305 at a zero nonce collides with any message-layer nonce that
  is also all-zero under the same direction key, which reuses Poly1305's
  one-time `(r,s)` and permits forgery. This protocol derives every MAC from
  HMAC-SHA-256 (§4.4) and reserves `MessageNum = 0` (`spec/message-layer.md`
  5.1) so the collision cannot arise; both rules exist for this reason and
  neither may be relaxed alone.
- Poly1305 tags are not truncated below 16 octets.
- Session AEAD keys are not used as MAC keys.
- No table-driven or otherwise non-constant-time cipher may replace ChaCha20 on
  any target. ChaCha20 is ARX and constant-time by construction everywhere;
  software AES is table-driven and is why AES-CCM was rejected despite its
  8-octet tag.
- All MAC and tag comparisons are constant-time.
- No log may contain the PSK, a derived key, a cookie, a tag, a nonce, an
  ephemeral private key, or a full datagram.

### 4.7 Version

**One version exists.** `version` is `0x01`, and this protocol is the only one
ever assigned a version. There is no negotiation, no fallback and no
compatibility mode. A datagram whose magic is not `MAGIC` (§2) is not a control
message at all and takes the envelope path (§5); one carrying `MAGIC` and a
version octet other than `0x01` is refused by the §3 decoder, which validates
magic, version and type together before reading any field. Either way it is
dropped before any state is touched — but note the version is **not** a
demultiplexing input: §5 routes on source and magic, and discards on type and
direction.

This is worth stating rather than leaving implicit, because the alternative is
subtly unfixable. `version` is inside `context` (§4.5), so it is bound into the
session keys — but a peer speaking some other protocol never computes `context`
at all, and could therefore offer no cryptographic evidence about what was
available. Coexistence on one port cannot be made safe by negotiation. **Not
implementing a second version is what closes downgrade**, and any future version
should take its own port or its own magic rather than share this one.

One standing requirement, also stated in §14.0a:

> The specification requires (`spec/transport.md` 3.1) that a deployment
> provision a **fresh PSK** — one generated for this protocol and used for
> nothing else.

The reason is structural rather than cryptographic. This document's schedule
derives a per-device `k_dev` and, except under the second provisioning method of
`spec/transport.md` 3.2, never puts the domain PSK on a device (§0), which is
what bounds a device compromise to that device. A system that provisions the
same secret onto every device does not have that property, and sharing a PSK
across the boundary imports the weaker system's blast radius into this one,
whatever the two key schedules do separately. The full statement is in the
threat model, §14.0a.

**The PSK is installed out of band and does not rotate.** Changing it means
reprovisioning every device in the domain and restarting the stack, so at most
one PSK is live, there is no generation identifier on the wire, and replacing a
compromised PSK is a flag day by construction. That is also the only revocation
this document provides — a holder of the current PSK is authorised (§14.1), so
"revoking a controller" means replacing the PSK everywhere. §14.0a states this
as an assumption.

---

## 5. Demultiplexing

0. **Apply §4.3's source-rejection list — §4.3 owns the list, this step owns
   where it runs. A datagram whose source matches it is dropped here, before the
   magic test and before any other rule in this document.** This is §4.3's only
   enforcement point, and it is placed in the demux rather than in §6 or §8 so
   that it covers the control path, the envelope path and every reserved or
   misdirected type with one test.
1. `N ≥ HEADER_LEN` and first 8 octets equal `MAGIC` → control path (§6).
2. Otherwise → envelope path (§8).

A ciphertext collides with `MAGIC` with probability 2⁻⁶⁴; such a datagram is
lost and KCP retransmits under a fresh sequence, so no handling is required. The
magic is not shortened: the 8-octet value is fixed by the wire format.

**Direction.** A device rejects `RETRY` and `ADMIT`; a client rejects `INIT` and
`FINISH`, as the specification requires. These are well-known types in the wrong
direction — neither unknown nor malformed, so a rule that drops only "unknown or
malformed" misses them. Reserved types `0x03`/`0x04` and any type outside
`0x01`–`0x06` are dropped silently and never reinterpreted as an envelope.

---

## 6. Device control path

### 6.1 INIT → RETRY

1. Reject unless the length and padding match §3.1.
2. Drop silently unless `device_id` equals this device's own — no crypto, the
   cheapest rejection in the protocol, and what stops every device in a PSK
   domain answering every INIT (§3.1).
3. Verify `init_mac` under `k_req`, computed over the datagram's fields
   including its `device_id`. **On failure drop silently — do not compute the
   cookie.**
4. Compute `cookie` for the current epoch, set `observed_source` to this
   datagram's `canonical_source`, take `epoch_tag`, `device_id` and
   `admission_epoch` from this device's own state, compute `retry_mac` under
   `k_resp`, emit RETRY.

No state is created.

### 6.2 FINISH → ADMIT

Processed in **exactly this order**; the order is the security property that
keeps a scalar multiplication unreachable without the PSK, except for one replay
of a suppressed capture (§14.4).

1. Reject unless the length and padding match §3.3.
2. **Only if an unexpired pending record exists whose `source_tuple` matches**,
   `memcmp` the received datagram against the stored FINISH octets. On a match,
   **resend the stored ADMIT verbatim and return** — no DH, no epoch change,
   **and no change to the pending expiry** (§2). Locking per §10.3: the lookup,
   the comparison and the copy of the stored ADMIT are one guarded operation,
   because step 7 on another FINISH overwrites both buffers.

   This is the one unauthenticated path that both takes a lock **and transmits**
   (§8.1 step 2 takes the same lock but sends nothing). Its transmission is
   bounded by the pending record's fixed lifetime, so the bound is per record,
   not per attacker (§14.3).

   The comparison is over the **whole 256-octet datagram**, not a field of it.
   Comparing only `client_tag` would be forgeable: `client_tag` is cleartext at
   offset 98, so an attacker could copy 16 observed octets, vary everything
   else, and still take this path — and the ADMIT it elicits is *genuine*, so
   `admit_pre` cannot filter it at the client. A fixed-size `memcmp` costs less
   than the checks in steps 3–4 that a mismatch falls through to.
3. Accept only if the presented `epoch_tag` equals this device's tag for the
   current or the previous epoch as of this datagram's arrival (§4.4), and the
   presented `cookie` equals `cookie` recomputed over that `epoch_tag`, **this
   datagram's** `canonical_source` and its `client_nonce`. Both tags are
   **cached** (§4.4), so this step costs one HMAC (§12). The current-or-previous
   latitude belongs to the `epoch_tag` membership test alone; `admission_epoch`
   is strictly single-use and is checked at step 4. Reject on mismatch. **This
   is the tuple binding** — without it a suppressed-and-replayed FINISH from
   another address is admitted and binds the pending record to the wrong tuple.
4. Reject unless the presented `admission_epoch` equals the current one.
5. Verify `client_tag` under `k_req`. Reject on failure. **An invalid FINISH
   does not alter pending or primary state.**

   No `client_nonce` cache is required. One could never fire (step 4 demands the
   current epoch, step 7 increments on every acceptance, so a cached nonce is
   only ever compared against a later epoch); two admissions cannot derive the
   same `master` because `admission_epoch` is inside `context`, and across a
   reboot because `cookie_secret` is redrawn each boot (§4.2).

6. Generate the ephemeral pair, compute `dh` and **reject the FINISH if the
   X25519 output is all zero** (§4.5); otherwise derive the §4.5 values.
   **Outside both locks** (§10.3).
7. Guarded per §10.3, atomically: **re-check that `admission_epoch` still equals
   the value verified at step 4 and abort silently if not** — steps 5–6 run
   outside the lock, so two controllers can both pass step 4, and without this
   compare-and-swap both receive a valid ADMIT while only one pending record
   survives, stranding the loser in a believes-admitted state with no liveness
   signal to correct it.

   `context`/`context2`, the session keys and the ADMIT bytes are all built at
   step 6, using the presented `admission_epoch` — §3.4 requires ADMIT to carry
   the value the client presented, which is the only one it can reproduce, so
   the increment comes after. The guarded region also covers the outgoing
   record's key wipe (§6.3) and, when every slot is held, the oldest-slot scan
   and eviction (below) — both of which read or write `rec_lock` state and
   cannot sit outside it. In full: increment `admission_epoch` (failing closed
   if it would leave §4.2's top-8-bits-clear range); store this FINISH's 256
   octets; store the prebuilt ADMIT; increment `pending_generation`; install the
   pending record. Derivation and the ADMIT transmission are outside it — §10.1
   forbids cryptography and transmission there.

   **On abort, including the fail-closed increment, wipe every key derived at
   step 6** before returning. They are live session keys for a session that will
   never exist.

**Pending records are keyed by source tuple, and within one tuple the last
writer wins.** A valid FINISH replaces the record for *its own* tuple; the
outgoing record's four keys are wiped (§6.3) and `pending_generation` is
incremented, so a promoting datagram for the displaced record fails §8.5 (a)1
and is dropped. A FINISH never touches the primary, and never touches another
tuple's record.

There are `PENDING_SLOTS` records (§2). When every slot is held and a valid
FINISH arrives from a tuple that holds none, the **oldest** slot is evicted and
its keys wiped.

That eviction is the weak edge of this design and is the one path by which a
stranger's FINISH displaces someone. An attacker who already has suppression can
reach it only by waiting for the table to be otherwise full: `admission_epoch`
is single-use, so an attacker holds at most one installed slot at a time
whatever it captures (§14.4). The slot count therefore sizes *capacity* for
legitimate controllers, not an attacker's price. Evicting oldest-first is
deliberate: it spends the record closest to its own expiry, so a legitimate
client that has just been ADMITed and is computing its DH is the last to be
displaced, not the first.

**Keying by tuple is what stops a replayed FINISH being aimed at another
controller's slot.** A captured FINISH carries the cookie its original tuple was
issued (§4.4), and §6.2 step 3 recomputes that cookie over *this datagram's*
`canonical_source` — so a replay is only ever accepted from the tuple it was
captured from, and can only ever occupy that tuple's slot, though when every
slot is held installing it still evicts the oldest record, as above. An attacker
cannot aim a captured FINISH at a backup controller's slot, because it cannot
produce a FINISH that validates from the backup's tuple without the PSK. What
the replay can take is the original controller's own slot, and that does not
deny the controller: if it is still in `AWAIT_ADMIT` the replay completes its
admission, and otherwise its next valid FINISH takes the slot back (§14.4).

Making the slot first-come, first-served for `PENDING_TTL_MS`, to stop a
suppress-and-replay attacker evicting a backup controller's pending record
mid-failover, **would be a strict escalation of the attack it prevents.** Under
replace semantics the attacker evicts one attempt; under first-come it
*occupies* a slot for the full TTL, from one injected packet, and the controller
whose tuple it holds cannot take it back. (The threat model, §14.4, discusses
the converse — refusing a new FINISH when the table is full rather than
evicting.) It would also buy little — `COOKIE_EPOCH_MS` at 4 000 already limits
a suppressed FINISH to ≤8 s of usefulness, and tuple-keying (above) removes the
cross-controller eviction that would make a single slot's occupancy matter.

Replace semantics cost little because slots are tuple-keyed. A controller only
ever replaces **its own** tuple's record, so it cannot evict another
controller's in-flight admission at all; the one exception is oldest-slot
eviction when every slot is held, which §14.4 records with its price. A client
whose record is replaced is told so by its own attempt failing; §7.2 makes any
further attempt an explicit application decision, so contention cannot spin.

### 6.3 The pending record

`PENDING_SLOTS` records, each fixed-size, never heap-allocated, each with its
own `PENDING_TTL_MS` expiry and each keyed by `source_tuple`. Fields:

`source_tuple`, the stored **FINISH[256]**, the stored **ADMIT[82]**, `k_c2s`,
`k_s2c`, `k_kcp_c2s`, `k_kcp_s2c`, `pending_generation` (`uint32`,
**device-wide-monotonic: a record installed into a freed or evicted slot
continues the counter rather than restarting, so a generation copied from that
slot's previous occupant can never match**), `expiry`, and an **empty**
client→device replay window.

It does not contain an ephemeral private key. Storing the finished ADMIT is what
makes §6.2 step 2 implementable: rebuilding it would need the wiped private key,
and minting a fresh `e_s` produces a tag the client cannot verify.

Replacing a pending record wipes the outgoing record's four keys rather than
merely overwriting a pointer, and sets a **fresh** `expiry` — a replace is a new
record, not a continuation of the one it displaces (§2).

**Invariant: every operation that advances a slot's `pending_generation` wipes
that slot's outgoing four keys; these notes recommend doing it in the same
critical section.** Replace, oldest-slot eviction, expiry-discard and the §9.2
tick all do (above and §6.2 step 7); §8.5's promotion is the sole exception:
(a)4 advances the generation without wiping, and every exit of §8.5 then wipes
both copies — (c) wipes the record's keys under its generation guard and wipes
the promotion buffer once installed, and the allocation-failure branch wipes the
same two. This is what lets §8.5's allocation-failure branch leave a re-claimed
slot untouched: if a slot's generation has moved, its old keys are already gone,
so there is nothing to leak. A new generation-advancing path that omitted the
wipe would silently reopen that leak.

`expiry` is also what orders eviction: every record carries the same
`PENDING_TTL_MS`, so the smallest `expiry` is the oldest install and no separate
timestamp is needed. These notes recommend adding none — §11's 536 B counts
these fields exactly.

**Expiry is evaluated at lookup on the control and envelope paths, and also on
the §9.2 maintenance tick**, wiping the four keys.

The tick is what makes the bound real. Both lookups are tuple-keyed, so a record
whose client vanishes is never touched again and its four session keys sit in
RAM indefinitely; "until the next FINISH" describes a trigger that may never
fire, not a bound. The tick already exists for the established session (§9.2);
reusing it is not the admission timer §9.2 forbids. These notes recommend adding
no *dedicated* timer for it; `spec/transport.md` 9.3 item 4 requires expiry to
be evaluated at every lookup and expired records to be discarded periodically.

---

## 7. Client state machine

The client is specified as five states and one byte of state. Nothing here adds
a message, a round trip, or a byte on the wire; it exists so that "what happens
to message X in state Y" has an answer in every cell, which a numbered list of
per-message rules does not provide.

~~~
IDLE ──send INIT──► AWAIT_RETRY ──valid RETRY──► AWAIT_ADMIT ──valid ADMIT──►
AWAIT_PUSH_ACK ──PUSH acked──► ESTABLISHED
~~~

### 7.1 Message handling by state

| Received | IDLE | AWAIT_RETRY | AWAIT_ADMIT | AWAIT_PUSH_ACK | ESTABLISHED |
| --- | --- | --- | --- | --- | --- |
| RETRY | drop | §7.3 | drop | drop | drop |
| ADMIT | drop | drop | §7.4 | **drop** | **drop** |
| INIT / FINISH | drop (§5) | drop (§5) | drop (§5) | drop (§5) | drop (§5) |
| envelope | drop | drop | drop | §7.5 | §7.5 |

The two bold cells are the duplicate-ADMIT gate, and stating them as cells is
the point. A predicate — "if a live session exists on this socket" — is
undefined for a client and would leave `AWAIT_PUSH_ACK` open for up to
`PUSH_ACK_TIMEOUT_MS`. A duplicate ADMIT there would make the client re-run
§7.4's commit, restarting `seq_full` at 1 under an unchanged `k_kcp_c2s` and
re-initialising the s2c replay window: ChaCha20-Poly1305 nonce reuse, reachable
with no PSK, and reachable in normal operation whenever an ADMIT is merely slow.

### 7.2 Transitions

| From | Event | To |
| --- | --- | --- |
| IDLE | application invokes *take control* | AWAIT_RETRY (send INIT) |
| AWAIT_RETRY | valid RETRY (§7.3) | AWAIT_ADMIT (send FINISH) |
| AWAIT_RETRY | `INIT_RETRY_MS` fires, transmissions remain | AWAIT_RETRY (resend the **same** INIT) |
| AWAIT_RETRY | RETRY fails any §7.3 check | AWAIT_RETRY (discard, keep waiting) |
| AWAIT_RETRY | `INIT_RETRY_MS` elapsed after the third and last transmission (§2) | IDLE (attempt failed) |
| AWAIT_ADMIT | valid ADMIT (§7.4) | AWAIT_PUSH_ACK (commit, send PUSH) |
| AWAIT_ADMIT | `FINISH_RETRY_MS` fires, phase budget remains | AWAIT_ADMIT (resend the **byte-identical** FINISH) |
| AWAIT_ADMIT | ADMIT fails any §7.4 check | AWAIT_ADMIT (discard, keep waiting) |
| AWAIT_ADMIT | `FINISH_PHASE_MS` exhausted **with no ADMIT accepted** | IDLE (attempt failed, ephemeral wiped) |
| AWAIT_PUSH_ACK | first PUSH acknowledged | ESTABLISHED |
| AWAIT_PUSH_ACK | KCP retransmits the PUSH | AWAIT_PUSH_ACK (fresh outer sequence, §3.6) |
| AWAIT_PUSH_ACK | `PUSH_ACK_TIMEOUT_MS` elapsed | IDLE (attempt failed) |
| ESTABLISHED | no authenticated datagram received for `SESSION_DEAD_MS` **while the client has unacknowledged data outstanding**, or the application abandons the session | IDLE (session ended) |

The last row matters for two reasons. It is the client-side recovery after a
**device reboot** — the device keeps no state a returning peer would recognise
and §9.3 forbids telling it anything, so the client's own detection is the only
exit. It is also what makes **deliberate re-admission** possible: a client that
wants a fresh session leaves ESTABLISHED first, which is why §7.1's ADMIT gate
can be a state: without an exit from ESTABLISHED, a state gate would wedge
re-admission forever.

There is deliberately **no seamless rekey**. A client that wants fresh keys
re-admits the ordinary way, accepting a gap. §14.4 records why there is no
rekey-without-teardown path from ESTABLISHED.

**Taking control is explicit.** The application invokes a one-shot *take
control* action; the client then runs exactly one admission attempt from IDLE,
and does **not** retry on its own, and reports the outcome to the application:
ESTABLISHED on success, back in IDLE on failure. Whether and when to try again
is the application's decision — a human or an operator policy, not a timer.
There is no standing condition, no automatic re-arm, and **no backoff** — a
client that is not told to take control sends nothing. Retransmissions *within*
an attempt (`INIT_RETRY_MS`, `FINISH_RETRY_MS`) are unaffected; they are not new
attempts, and they absorb ordinary packet loss, so a single dropped frame does
not surface as a failure.

**This is why there is no backoff.** Automatic retry under a standing
`session_wanted` condition would mean two controllers that both wanted the
device displace each other in a loop — A promotes, B's session dies, B re-admits
and displaces A, indefinitely, at 2×X25519 and a two-object heap peak per
iteration (§8.5). An exponential backoff to damp it would become the cheapest
attack in the document: one suppressed frame per attempt would ratchet a
controller to the backoff ceiling, outliving the attacker, unless something on
the recovery path reset it.

Explicit control removes the loop rather than damping it. Two controllers only
contend if a human or an application deliberately tells both to take control,
and neither retries on its own, so there is nothing to ratchet and nothing to
converge. The deployment this serves has at most two controllers and one active
at a time (§14.0a); automatic failover would solve a problem it does not have.

**Stale-session revalidation, and why it is not a keepalive.** `SESSION_DEAD_MS`
detects a dead session only once the client has data outstanding, so a
controller that has gone quiet learns nothing until it next sends — and then
waits the full 10 s before it may even begin recovering. The application's first
command after a quiet spell pays detection *plus* admission, which is the worst
latency in the protocol and falls on the most visible operation.

A client can shorten that by re-admitting **before** sending, when the time
since its last authenticated inbound datagram exceeds a local threshold. It
already keeps that timestamp — `SESSION_DEAD_MS` is defined against it — so this
needs no new state, no new message and no protocol support. It generates **no
traffic while idle**: the trigger is the application wanting to send, not a
timer. That is exactly what separates it from the keepalive §9.5 forbids, and
why it is stated here rather than being ruled out with one.

It is not free. Re-admission abandons the current session (every path to a new
attempt goes through IDLE, above), so a client that revalidates when the session
was in fact healthy has thrown away a working session and spent an admission —
2×X25519 on the device, §12. The threshold is therefore a local policy choice
and deliberately unspecified: low costs needless admissions, high leaves the 10
s detection in place. What the protocol guarantees is only that the information
the decision needs is already in the client's hands.

Nothing in the protocol enforces the one-attempt rule above, and nothing needs
to. An attempt requires a valid `client_tag`, so only a PSK holder can spend
one, and §14.1 assumes a holder of the current PSK is legitimate. Rate-limiting
an authorised party protects nothing — it may take the device whenever it likes.
The rule is here so a conforming controller is unambiguous, not as a defence.

**There is also no automatic failover.** If the active controller dies, the
standby does nothing until told. The device can therefore sit with no controller
indefinitely, and §9.5 forbids it from reclaiming the dead session on its own.
That is the accepted cost of removing the loop, and it is the right cost for a
deployment with two known controllers and a human or supervisor deciding which
is active.

A timer that fires in the same tick as a message arrives loses: drain the socket
and process what is there before declaring a timeout. Otherwise a valid RETRY
whose cookie is good for several more seconds, or an ACK for a PUSH the device
has already promoted, is discarded — and in the second case the device holds a
primary §9.5 forbids it from reclaiming.

Every transition to IDLE discards the retained
`(epoch_tag, cookie, admission_epoch)` set and wipes **every value derived for
the attempt**: the ephemeral private key, the cached `dh` (§7.4 step 4 requires
that cache), any `master` not yet wiped per §4.5, and — from `AWAIT_PUSH_ACK` or
`ESTABLISHED` — the four session keys and the client's KCP object. `master` is
named explicitly because all four session keys and `admit_tag` are re-derivable
from it, so wiping the four without it wipes nothing. The specification has a
client draw a fresh CSPRNG `client_nonce` and a fresh X25519 keypair on each
entry to AWAIT_RETRY, and hold both constant for that attempt; they are inputs
to `cookie` and `client_tag`, so re-drawing mid-attempt invalidates the client's
own cookie.

The specification requires the client to keep one socket and source port for an
attempt and for the session that follows, and to know its own address; these
notes recommend determining that address by `connect()`-ing to the device and
reading `getsockname()` (`spec/transport.md` 10.2). A wildcard-bound socket
reports `0.0.0.0`/`::` and cannot form `canonical_source` (§4.3), which §7.3
needs.

### 7.3 AWAIT_RETRY — handling RETRY

1. Reject unless the length matches §3.2, **before reading any field**.
2. Compare `observed_source` against the client's own socket address; discard a
   mismatch. This is free, so it runs before any MAC.
3. Verify `retry_mac`; discard on failure.
4. Discard unless `device_id` equals the value the client put in its INIT. With
   `device_id` bound into `init_mac` a foreign device will not answer at all, so
   this is defence in depth — but a client does not accept a RETRY from a device
   it did not address, as the specification requires (`spec/transport.md` 10.4
   step 4).
5. Retain `(epoch_tag, cookie, admission_epoch)` **as a set** — all three are
   inputs to `context`, and FINISH must echo all three (§3.3); `admission_epoch`
   is additionally what §7.4 step 2 compares ADMIT against, and pairing a cookie
   with a different epoch fails silently at a boundary. Move to AWAIT_ADMIT.
   Discard the set on any transition to IDLE.

No epoch high-water rule is needed. The threat one would address — a
longer-uptime sibling device poisoning the client's notion of the current epoch
— is closed at the source by `device_id` in INIT (§3.1), since a sibling never
answers, and the state machine leaves AWAIT_RETRY on the first valid RETRY, so a
high-water mark would be recorded and never compared. No age bound on the
retained set is needed: it cannot expire mid-attempt. It does not exist until
RETRY arrives, so it is held for the FINISH phase alone — `FINISH_PHASE_MS`,
which §2 requires to be below `COOKIE_EPOCH_MS` — against a **minimum** cookie
lifetime of one `COOKIE_EPOCH_MS`. A restart rule on cookie age could never
trigger anyway: `epoch_tag` is opaque (§3.2), so a stale cookie is
indistinguishable from any other silent failure. `cookie` also binds
`client_nonce`, which §7.2 makes fresh per attempt.

### 7.4 AWAIT_ADMIT — handling ADMIT

1. Reject unless the length matches §3.4, before reading any field. **No check
   below cancels or alters any timer** — cancelling the FINISH phase timer
   before the length check would let one 10-octet datagram from any spoofed
   source disarm the client's only exit from `AWAIT_ADMIT` and hang it
   permanently.
2. Reject unless `admission_epoch` equals the value presented in FINISH.
3. Verify `admit_pre` — **before** the X25519 (§3.4 gives the reason).
4. Compute `dh` — **reusing a cached result if this `e_s` was already seen in
   this attempt** — discard if it is all zero (§4.5), derive the §4.5 values,
   and verify `admit_tag`. **Do not wipe the ephemeral private key here**
   (§4.5): it is wiped on leaving `AWAIT_ADMIT` (§7.2). On any failure after
   derivation, wipe every derived key before returning, mirroring §6.2 step 7.

   Caching `dh` per `e_s` is required, not an optimisation. `admit_tag` is
   covered by nothing, so an attacker who captures the genuine ADMIT can flip
   one of its last 16 octets and replay at line rate: every copy carries a
   genuine `admit_pre` and so passes step 3, and without the cache each one
   costs a full X25519 plus six HKDF operations on a client that may itself be a
   microcontroller. §2 refuses count caps, so the cache is what bounds the
   scalar multiplications — one per distinct `e_s`, and an attacker cannot vary
   `e_s` without breaking `admit_pre`. The six HKDF operations are still paid
   per copy (§14.3).
5. Commit, exactly once per attempt: wipe the ephemeral private key and the
   cached `dh`, set c2s `seq_full` to 1, initialise an empty s2c replay window,
   hand the first KCP PUSH (`sn = 0`) to the envelope, and move to
   AWAIT_PUSH_ACK. **That PUSH needs a payload, so *take control* takes a first
   message as an argument**: KCP emits no PUSH for an empty write, and §8.5
   promotes on nothing else. It is an ordinary message-layer message (§8.5's
   last paragraph), `MessageNum` 1; a message with an empty payload is still 36
   octets on the stream and is enough. KCP may retransmit that PUSH afterwards,
   each retransmission taking a fresh outer sequence (§3.6); the
   *initialisation* happens once.

FINISH retransmissions while in AWAIT_ADMIT are byte-identical, because §6.2
step 2 compares the whole datagram.

### 7.5 Envelope, both directions

The client applies §8.1–§8.4 symmetrically: §3.6's size bounds in **both**
directions (`44 ≤ N ≤ WIRE_MTU` — an undersized datagram cannot hold a KCP
header and an envelope), the reconstruction rule of §8.3, marking its s2c replay
window only after the AEAD verifies, and §8.4's fresh-sequence rule on send.
**§10.1's rule that outbound `seq_full` allocation be atomic applies to the
client too** (`spec/transport.md` 11.2 item 5) — a client has the same two
producers, its KCP tick and its RX-path ACKs, over `k_kcp_c2s`.

A spoofed envelope datagram at the client's tuple costs it one AEAD open over up
to `WIRE_MTU`; see §14.

**These notes recommend that the client process socket input, timer expiry and
application requests on a single thread; the specification requires only that
the state byte and the commit be atomic.** §7's state byte is read-and-written
by all three, and §7.1's duplicate-ADMIT cells are a test-and-act on it: two
ADMITs racing on separate contexts could both observe `AWAIT_ADMIT` and both run
step 5, resetting c2s `seq_full` to 1 twice under one `k_kcp_c2s`. A
single-threaded loop also makes §7.2's drain-before-timeout rule meaningful. A
client that cannot be single-threaded guards the state byte and the commit with
one mutex, which gives the atomicity the specification requires.

### 7.6 Silence

On any verification failure the client emits nothing. It retries or restarts per
§7.2. It never sends an error datagram of any kind.

**The specification requires ICMP to be ignored on this socket, by both parties
(`spec/transport.md` 9.4 item 4).** The socket these notes recommend a client
`connect()` (§7.2) surfaces ICMP errors as asynchronous socket errors on both
POSIX and common embedded IP stacks, and the client must ignore them: otherwise
one spoofed port-unreachable per second would make admission permanently
impossible, and a spoofed fragmentation-needed would shrink path MTU below
`WIRE_MTU`. Neither party may alter state, timers, or path MTU in response to an
ICMP message. Path MTU is fixed at `WIRE_MTU`, with no PMTU discovery.

§9.3 carries the device's side of this: anything the IP stack answers on its own
is a response to a datagram, and therefore falls under the same rule.

---

## 8. Envelope path

### 8.1 Receive

1. Reject any datagram outside §3.6's size bounds. Note the check runs *after*
   IP reassembly, so it does not recover the reassembly buffers and timer the
   fragments consumed: **the specification recommends that a device disable IP
   reassembly on this socket's path**, which is the only place that cost can be
   refused.
2. Select candidates by exact source tuple, discarding an expired pending record
   as found. No match → drop. Guarded per §10.3, copy each candidate's direction
   key, replay high-water mark and generation. **Try the primary before the
   pending record.** A stale pending record is then inert, and established
   traffic costs one AEAD open rather than two; only the single promoting
   datagram pays the extra.
3. Split `tag` (last 16) and `seq_wire` (preceding 4), reconstruct `seq_full`
   (§8.3), open the AEAD **holding no lock**. On failure **try the next
   candidate** — a datagram from a client re-admitting on the tuple its old
   session still holds fails under the primary's keys and must still reach the
   pending record, or promotion becomes impossible. When no candidate opens it,
   drop silently: no `ikcp_input`, no ACK, no resume of a quiesced primary, no
   per-packet log. No KCP field may be read before an open succeeds — the header
   is ciphertext.
4. **Primary path**, guarded per §10.3: re-check the record still exists and its
   own `generation` is unchanged; perform the §8.2 accept-test against the
   record's **current** high-water mark — not the copy from step 2, which is
   only an input to reconstruction, since two duplicates evaluated against one
   stale copy would both pass; then mark. Test and mark are one atomic
   operation.
5. Dispatch: §8.6 for the primary, §8.5 for a pending record. §10.3 gives the
   locking for each, including which parts of §8.5 may allocate.

### 8.2 Replay window

Per direction: a `uint64` high-water mark and a `REPLAY_WINDOW`-bit map. A
sequence is accepted iff above the mark, or within the window below it and not
yet marked. Marked only after the AEAD verifies. A KCP retransmission is
deliverable because its sender wraps it in a fresh outer sequence.

### 8.3 Sequence reconstruction

Sessions do not time out (§9.5), so at ~500 pps `seq_wire` wraps 2³² in ~99
days.

~~~
d32       = (uint32_t)(seq_wire - (uint32_t)(hwm & 0xFFFFFFFF))
delta     = (d32 < 0x80000000) ? (int64_t)d32 : (int64_t)d32 - 0x100000000
candidate = (int64_t)hwm + delta            /* SIGNED */
~~~

`candidate` is signed 64-bit, as the specification requires (`spec/transport.md`
11.5), because in `uint64` a "negative" result wraps above `hwm` and the range
checks below become inoperative. The `d32` split is written out because
`(int32_t)` of a value above `INT32_MAX` is implementation-defined in C and
wraps in some other languages, and §15 requires every implementation to agree at
exactly that boundary.

Reject `candidate < 1` or more than `REPLAY_WINDOW` below `hwm` — **as a
rejection of this candidate, not of the datagram.** §8.1 step 3 tries the next
candidate on failure, and this check must fall through exactly as an AEAD
failure does: a client re-admitting on the tuple its old session still holds
sends `seq_wire = 1` against a primary whose `hwm` is in the thousands, which
fails here under the primary and must still reach the pending record, or
promotion on a reused tuple is impossible. The reconstructed 64-bit value, never
`seq_wire`, feeds the nonce, window and wrap check. **A misprediction fails
closed through the AEAD, not the window** — a wrong candidate gives a wrong
nonce — which is why §8.2 marks only after verification.

Note the deliberate one-value gap between this check and §8.2's window. "More
than `REPLAY_WINDOW` below" accepts a candidate exactly `REPLAY_WINDOW` below
`hwm`, which the 256-bit window then drops as too old — the two checks have
different jobs, and both reject the datagram. The cost is one AEAD open for that
one sequence value per window, which buys an attacker nothing: any junk datagram
at a known tuple already costs an open. The boundary is pinned from both sides
by the replay script in §15, so implementations cannot drift on which check does
the rejecting.

### 8.4 Send and MTU

Output appends a fresh sequence and tag to every datagram including ACK-only
ones, receives the session generation and a copied key, and re-checks the
generation before sending. The specification requires that none be sent on a
retired primary (`spec/transport.md` 12.1); the re-check is the method these
notes describe. Internal KCP MTU = `WIRE_MTU` − `ENVELOPE_LEN`; a `WIRE_MTU` at
or below `KCP_OVERHEAD + ENVELOPE_LEN` leaves KCP no payload and is rejected.
`WIRE_MTU` 1400 → 1380 internal.

### 8.5 Promotion

Promotion runs in three regions, in this order, under the locks §10.3 assigns.
**`kcp_lock` is held continuously across all three** — the per-region entries in
§10.3 describe what `rec_lock` does inside that hold, not a re-acquisition.
Releasing between regions lets a second promotion run its own (a) against an
already-retired primary, after which both (b) bodies free the same pointer.

**(a) Claim — metadata region.** Atomically:

1. Re-check the pending record still exists, is **unexpired**, and its
   `pending_generation` equals the value copied at §8.1 step 2. Abort if any of
   the three fails. The expiry re-check is required by §6.3's rule that expiry
   is evaluated at every lookup on the envelope path: §8.1 step 3 opens the AEAD
   holding no lock and then blocks on `kcp_lock`, which §10.2 says may be held
   for milliseconds, so a record unexpired at step 2 can be expired by the time
   (a) runs.
2. Perform the §8.2 accept-test against the pending record's **current** replay
   window.
3. Require a KCP PUSH with `sn == 0`, tested on the **first** segment — KCP
   packs segments, so a first message over one MSS carries `sn=0` and `sn=1`
   together. Anything else is dropped **without marking**, so a reordered `sn=1`
   cannot consume the promotion.
4. Mark the sequence, **increment `pending_generation`** to claim the promotion,
   and **copy out everything (c) will install**: the four keys, the tuple, the
   just-marked c2s replay window (high-water mark *and* bitmap), and the claimed
   `pending_generation`. **(c) reads none of these from the record.**

   The copy must happen here because `rec_lock` is released across (b), and four
   reapers take `rec_lock` alone: §6.2 step 2's discard-on-expiry at lookup,
   §6.2 step 7's same-tuple replace, its oldest-slot eviction, and §8.1 step 2's
   discard-on-expiry. (§9.2's sweep is **not** among them — §10.3 makes the tick
   take `rec_lock` inside `kcp_lock`, so promotion's continuous hold excludes it
   entirely.) A claim does not make a record un-reapable, and none of this needs
   an attacker: `PENDING_TTL_MS` is 5 000 and §2 requires only that the
   promoting PUSH arrive within that budget, so it may arrive near its end.

   **The window is the dangerous one.** A record wiped during (b) yields zeroed
   keys, which fail *closed* at the AEAD; a zeroed replay window fails **open**
   — high-water mark 0, empty bitmap — so every c2s sequence this admission ever
   used, the promoting datagram included, becomes acceptable again. (c) cannot
   detect it.

   The copy is 190 octets (4×32 keys + 18 tuple + 40 window + 4 generation) into
   **one static promotion buffer**, not the stack — §11's stack row has no
   headroom for it. A single static buffer is sound because `kcp_lock` is held
   continuously across (a)(b)(c), so two promotions from different tuples
   serialise completely on either core; that hold is what makes it legal, and it
   is the reason to state the storage class rather than leave it to the
   implementer.
5. **Retire the outgoing primary: increment the primary `generation` and detach
   the primary pointer**, so no later lookup can resolve it. Nothing is freed or
   wiped here — only invalidated.

   `generation` is a device-wide `uint32` incremented once per promotion; it is
   the counter §8.1 step 4, §8.4 and §8.6 compare. Any copy taken before this
   step holds the pre-increment value and therefore fails those checks. The
   post-increment value belongs to the primary installed in (c).

Steps 1–5 are one atomic operation and they are what makes promotion safe.
Without them two copies of one captured promoting datagram — which needs no PSK,
only duplication off the air — both pass §8.1 step 2, both open the AEAD (step 3
holds no lock), and both arrive here: the second creates a second KCP object,
frees the primary the first installed, and resets s2c `seq_full` to 1, giving
**nonce reuse on `k_kcp_s2c`** plus a use-after-free. The claim in step 4 is the
only thing that makes the second copy fail step 1.

**(b) Build — allocating region, no metadata lock held.** Set the device's
outbound s2c `seq_full` to 1 **before** feeding the datagram, not in (c). Stock
`ikcp_input` invokes no output callback, so nothing is emitted between the feed
and (c) — but that is a property of the KCP library (§8.7), not of this
document, and a fork that flushed on input would emit under the new `k_kcp_s2c`
at the *retired* primary's counter. Setting it first removes the dependency. The
plain store is safe because the only other writer is §8.4's callback, which runs
inside `ikcp_flush` under the `kcp_lock` this region already holds. Then create
the KCP object, feed it the datagram, then wipe the retired primary's four keys
and free its KCP object.

A non-zero return from that feed does **not** undo the promotion. (a)3 has
already established that the first segment is a PUSH with `sn == 0` from a peer
that holds the session keys, so the only way the feed fails is a malformed
*later* segment packed into the same datagram; the session is installed
regardless and that datagram is simply not delivered. Only an allocation failure
takes the branch below.

Step (a)5 is what makes this region safe, and it must come **before** anything
here. §8.4 and §8.6 both defend against a stale primary pointer by re-checking
the `generation` — but were the new generation assigned in (c), after (b) had
already wiped and freed, the old value would still be installed throughout (b),
so the check would pass and an RX thread that copied the pointer, keys and
generation at §8.1 step 2 would go on to open the AEAD under an **all-zero key**
and call `ikcp_input` on **freed memory**. The key-wipe rule below makes that
worse rather than better: without it the thread would read stale-but-valid keys
and merely fail an AEAD check. Invalidate first, destroy second.

**(c) Install — metadata region.** Bind `conv` from the decrypted header;
install the new primary **under the `generation` incremented in (a)5**, with the
pending keys, tuple and the **already-marked** c2s replay window as the
primary's, **every one of them taken from (a)4's copy and none of them re-read
from the record**. The window is not re-initialised (`spec/transport.md` 12.2
item 3), or the promoting datagram replays. The device has no s2c *receive*
window, which is the client's (§7.5), and its outbound s2c `seq_full` was set in
(b). Wipe the promotion buffer once installed.

Then **clear the pending record and wipe its four keys, in the same critical
section, only if its `pending_generation` still equals the value claimed at
(a)4** — the same comparison (a)1 performs. Without that check a record
*replaced* during (b) is a different, freshly admitted client's, holding its own
keys and its own valid ADMIT, and clearing it strands that client until
`PUSH_ACK_TIMEOUT_MS` with §9.3 forbidding any explanation. If the generation
moved, leave the slot alone: it belongs to someone else.

The wipe is (c)'s and no one else's. A cleared slot holds no record, so no
reaper visits it and a later install has no outgoing record to wipe; unwiped,
the record's copies would sit in the static pending array (§11) for as long as
the slot stays free, outliving the primary's own keys once a later displacement
wipes them (below). If the generation moved, the operation that moved it already
wiped those copies (§6.3).

If KCP allocation fails in (b), **wipe the promotion buffer (a)4 filled** — it
is the second live copy of the session keys and this is the one exit path that
reaches neither (c)'s wipe nor a reaper, so without this rule 190 octets of live
key material persist in a static buffer until the next *successful* promotion,
and by construction promotions are failing. Then **discard the claimed pending
record and wipe its four keys — but only if its `pending_generation` still
equals the value claimed at (a)4**, the same guard (c) applies. A replace or a
reaper during (b) may have installed a *different* freshly-admitted client in
that slot; wiping it by slot index would strand that client exactly as an
unguarded (c) would. If the generation moved, leave the slot alone. Then —
because (a)5 has already retired the outgoing primary — **wipe and free that
primary too, leaving the device with no session**. Neither the pending record
nor the primary can be restored: (a) consumed the record's replay sequence and
generation, and retired the primary's. The client recovers through
`PUSH_ACK_TIMEOUT_MS` (§7.2), and any other controller may admit.

Leaving the primary unchanged on allocation failure is not compatible with
retiring it before the allocation, and retiring it late produces the
use-after-free above. Losing the incumbent on a failed promotion is the price of
making the generation check mean something; it is also nearly moot, because a
device that cannot allocate a KCP object is already under the memory pressure
§9.5 describes. It is not stuck there — this branch frees the retired primary,
so the next promotion needs one object rather than two — but while the shortfall
lasts every promotion fails and §9.3 forbids the device saying so, which is why
§9.5's send-path bound is a hard requirement rather than advice.

**Releasing the previous primary is a lifetime operation, not just a pointer
swap**, and its keys are secret material: **wipe `k_c2s`, `k_s2c`, `k_kcp_c2s`
and `k_kcp_s2c` before the memory is freed.** That wipe is safe only because
(a)5 retired the primary first — no reader can still resolve it. The maintenance
tick of §9.2 may be inside that object's flush; §10.3 places the flush and the
free under the same lock, so they are mutually excluded by construction and no
deferred-free mechanism is needed.

The KCP stream then begins directly with the encrypted ShieldNet message format
under `k_c2s`/`k_s2c` — no second in-KCP handshake. A cleartext or
unauthenticated first payload is not valid and is rejected, as the specification
requires (`spec/transport.md` 12.2, last paragraph).

### 8.6 Established

The sequence was already marked at §8.1 step 4, atomically with the accept-test,
guarded per §10.3. **Do not mark again here** — doing so either double-marks or
moves the mark out of the atomic test, letting two copies of one captured
datagram both pass against one stale high-water mark.

On entering, **re-read the current primary and re-check its `generation` —
guarded per §10.3 — before touching the KCP object.** The pointer resolved at
§8.1 step 2 may have been freed by a promotion while this path waited for the
KCP lock (§10.3); `conv` alone does not detect that.

Then: only an accepted datagram may reach `ikcp_input`, and only a successful
`ikcp_input` may resume a quiesced primary (§9.4). A datagram whose decrypted
`conv` differs from the bound one is dropped, as the specification requires
(`spec/transport.md` 12.2 item 5 and 12.3).

**"Successful" means `ikcp_input` returned 0**: the datagram parsed as KCP for
the bound `conv`. It does not mean a segment was new — `ikcp_input` returns 0
for a duplicate or out-of-window segment it discards. That is the right test for
resume, which asks whether the peer is there, not whether it said anything new.

### 8.7 KCP dependency

The payload is a KCP datagram in upstream KCP's wire format (skywind3000
`ikcp.c`); conv-less forks and forks that change the segment header will not
interoperate. A fork that only changes behaviour inside one endpoint — error
handling, buffering limits, how small a receive window it honours — stays
interoperable.

A tuning that works, as a default and not a wire requirement: `nodelay` 1,
`interval` 20 ms, fast resend 2, congestion control off (`nc` 1), `snd_wnd` 32,
`rcv_wnd` 8, `dead_link` 20 (KCP's own default). Stream mode is the message
layer's requirement (message layer §1.1). **KCP's header is little-endian** and
§0's big-endian rule does not extend into it. The 24-octet header is
`conv[4] || cmd[1] || frg[1] || wnd[2] || ts[4] || sn[4] || una[4] || len[4]`,
so §8.5 and §8.6 read offsets 0, 4 and 12. `IKCP_CMD_PUSH` is 81 (`0x51`).
`conv` is client-chosen, not negotiated, bound at promotion.

Constants this document names but does not own: `IKCP_CMD_PUSH`, `rcv_wnd`,
`dead_link` and `IKCP_RTO_MAX` are all `ikcp.c`'s. They appear in §8.7, §9.4,
§9.5 and §11: `rcv_wnd` bounds device memory, and `dead_link` and `IKCP_RTO_MAX`
govern quiesce and resume (§9.4), so changing the KCP library changes those
figures and §9.4 and §11 must be re-checked.

---

## 9. Device state and lifecycle

### 9.1 States

State is (primary ∈ {none, live, quiesced}, pending ∈ a `PENDING_SLOTS`-entry
set of tuple-keyed records, each free or held — §6.3).

The device also mutates `admission_epoch` on every accepted FINISH (§6.2 step 7)
and sets the outbound s2c `seq_full` to 1 at promotion (§8.5 (b)). Neither is a
state transition here — they are counters within a state — but both are listed
so the table is not read as the complete set of mutations.

| From | Event | To |
| --- | --- | --- |
| a slot is free | valid FINISH | slot = held, ADMIT sent |
| slot held for tuple T | valid FINISH from T, not byte-identical | that slot replaced per §6.2 (**outgoing keys wiped**), `pending_generation`++ |
| all slots held | valid FINISH from a new tuple | oldest slot evicted (**keys wiped**), new record installed |
| this tuple's slot is held | byte-identical FINISH | unchanged (expiry **not** refreshed, §2); stored ADMIT resent |
| no slot matches this tuple | valid FINISH, epoch moved between steps 4 and 7 | unchanged; nothing sent |
| this tuple's slot is held | valid FINISH, epoch moved between steps 4 and 7 | unchanged; nothing sent (§6.2 step 7) |
| this tuple's slot is held | accepted envelope datagram that is not PUSH `sn=0` | unchanged; **window not marked** (§8.5) |
| this tuple's slot is held | promotion attempted, KCP allocation fails | **primary = none**: the promotion buffer wiped, the claimed record freed **only if its generation is unchanged** (§8.5), and the incumbent, already retired at §8.5 (a)5, wiped and freed; neither is recoverable; nothing sent |
| primary = live | accepted envelope datagram with a foreign `conv` | unchanged; dropped (§8.6) |
| slot held | expiry observed — at control lookup, envelope lookup, or the §9.2 tick (§6.3) | that slot freed, keys wiped |
| this tuple's slot is held | valid enveloped PUSH `sn=0` | primary = live (new generation), that slot freed if its generation is unchanged (§8.5 (c)), old primary released |
| primary = live | KCP dead-link | primary = quiesced |
| primary = quiesced | an accepted enveloped datagram that `ikcp_input` **also accepts** | primary = live |
| primary = live or quiesced | the message layer ends the session (a partial message: a header failing the pre-read bounds, or a message left partly read past the receiver's time bound; `spec/message-layer.md` 8) | primary = none, keys wiped; the device continues to serve admission |

Resume is keyed on a *successful* `ikcp_input` (§8.6 defines it), not merely an
accepted envelope: a datagram that opens but is not KCP for the bound `conv`
says nothing about the peer's KCP state and must not restart retransmission
toward it.

`primary = none` occurs before the first promotion since boot, after an
allocation failure in §8.5 (b) — the incumbent having been retired at (a)5 —
which leaves no primary and installs no successor, and after the message layer
ends the session (`spec/message-layer.md` 8 items 2 and 3; `spec/transport.md`
12.5 item 1).

### 9.2 No admission timers

The device does not retransmit RETRY or ADMIT, and does not emit a **control**
datagram except as the direct result of a received one, as the specification
requires (`spec/transport.md` 9.4 item 2). All admission retry is the client's.

This is scoped to admission and does **not** reach the established session.
KCP's ARQ is timer-driven — retransmissions, delayed ACKs and window probes come
from a periodic flush, and the dead-link counter on which §9.4 depends advances
only there — so a maintenance tick is required, not forbidden.

**The tick runs in every lifecycle state, including `primary = none`.** It
drives KCP for an established primary, and it evaluates pending-slot expiry
(§6.3) — which is the only scheduled evaluation point, since both lookups are
tuple-keyed and a vanished client is never looked up again. Scoped to an
established primary, it would leave a device holding pending slots before its
first promotion with nothing obliged to run, and §6.3's five-second key lifetime
unenforced. A device-wide tick is not the admission timer this section forbids:
it sends nothing and retransmits nothing.

### 9.3 Silence

The device does not respond to a rejected or unauthenticated datagram in any
way. A client distinguishes failure modes by its own timers, not by any device
signal.

**This extends to responses the IP stack generates on its own.** The interface
carrying the admission socket does not emit ICMP echo replies or ICMP
port/host-unreachable messages, which the specification requires. Those are
responses to a datagram as surely as a RETRY is, and each is a keyless liveness
oracle and a reflection primitive that — unlike the INIT reflector of §14.3 —
needs no captured datagram at all. §7.6 carries the matching rule for both
parties' handling of *inbound* ICMP.

Note the collateral: suppressing these interface-wide also disables ping and the
error signalling a SoftAP config portal on the same interface would otherwise
give. Where that is unacceptable, the portal belongs on a different interface —
not on an exception to this rule.

### 9.4 Quiescing

On KCP dead-link the device stops emitting output and stops retransmit work, but
retains the session, keys and tuple, as the specification requires
(`spec/transport.md` 12.4). An enveloped datagram that `ikcp_input` also accepts
resumes it.

**Resume does not recreate the KCP object** (`spec/transport.md` 12.4). `ikcp`
latches its dead-link state and never clears it, so the tempting implementation
is to recreate — but a fresh object has `snd_nxt = rcv_nxt = snd_una = 0` while
the peer is at some N, so every segment is discarded in both directions forever:
the envelope decrypts, `ikcp_input` returns 0 while discarding what it was
given, §9.1's `quiesced → live` transition fires, and the session is live in
name and delivers nothing. §9.5 forbids the device from destroying it and §7.2
gives no controller a reason to re-admit on its own, so the device stays held by
a dead session until someone deliberately takes control again. Clear the latched
state in place, and with it **everything that latched it**: reset each `snd_buf`
segment's `xmit` to 0, reset `rx_rto` and every segment's `rto` to their initial
values, reset `probe`/`probe_wait`, and re-base every stored timestamp —
`resendts`, `ts_probe`, the segment `ts` fields, and **`kcp->ts_flush`** — to
the current clock.

The segment fields are the ones that must not be missed. Clearing `state` alone
leaves those segments with `xmit ≥ dead_link`, so the first flush after resume
re-latches immediately and the session oscillates live→quiesced forever — the
same permanent occupation by another route. Leaving each segment's `rto` where
backoff drove it is nearly as bad: `ikcp_flush` grows a segment's `rto` on every
timeout and does not cap it, so the first loss after resume waits out that
inflated timeout, long enough to re-trigger dead-link and produce the
oscillation this rule exists to prevent. `rx_rto` itself moves only with
acknowledged round-trip samples (`ikcp_update_ack`), so resetting it is hygiene
rather than a cure. `ts_flush` is the mildest: `ikcp_update` and `ikcp_check`
replace a value 10 s or more from the clock on their own, so a stale one delays
a flush by at most that long rather than stopping it; it is re-based with the
rest because the specification requires every stored timestamp re-based
(`spec/transport.md` 12.4).

Re-basing is not optional housekeeping. `ikcp` compares timestamps with
`_itimediff`, a **signed 32-bit** difference on millisecond values, so every
timer comparison inverts once two stored values are more than ~24.8 days apart.
§8.3 sizes sessions at ~99 days and §9.5 forbids destroying an idle one, so a
quiesce past 24.8 days is in scope by construction. §2 pinned the device's own
clock to 64 bits; this is the same wrap living inside the KCP library, and only
a re-base on resume reaches it.

The object, its KCP sequence state, its `conv` and its `generation` all persist.

Resume also preserves `seq_full` and the replay windows, as the specification
requires (`spec/transport.md` 12.4 and 11.2 item 3). Restarting `seq_full` under
an unchanged key is direct nonce reuse.

### 9.5 No idle timeout, no keepalive

A session is not destroyed for inactivity, except that the message layer ends
one whose peer falls silent while a message is partly read (`spec/transport.md`
12.5 item 1). There is no keepalive, heartbeat or liveness probe, and no rule
may come to depend on one. A controller may be silent indefinitely and keep the
device. A completed admission followed by a valid first PUSH replaces a session;
otherwise a session is released only by a failed promotion or by the message
layer's end path.

**The send path is bounded independently of peer liveness.** `SEND_QUEUE_MAX`
(§2, default 32 KiB) caps the **total** of `snd_queue` *and* `snd_buf` — not
queued-but-unsent alone. Against a vanished peer `snd_buf` fills to the send
window and stays full, so a cap covering only `snd_queue` bounds the smaller
half. `rcv_buf`, `rcv_queue` and the ack list are bounded by `rcv_wnd`. A
receiver must be able to buffer the whole window it advertises
(`spec/transport.md` 13 item 5), so a buffer smaller than the advertised window
refuses segments a legitimate peer was granted, which the peer sees as loss and
retransmits until dead-link. Lowering `rcv_wnd` is the only lever on
receive-side memory. On reaching the cap the device refuses further application
writes — returning an error to the caller, never silently dropping — and resumes
accepting them once the total falls below the cap; the specification requires
both (`spec/transport.md` 12.5 item 3). Size it so that the **worst case** — two
sessions at their `rcv_wnd`/`SEND_QUEUE_MAX` ceilings — fits, since §8.5 creates
the new KCP object before releasing the old; §11 gives the arithmetic and
recommended values. Note this is a bound on what a *legitimate* peer can commit:
segments enter a queue only after the AEAD opens (§8.1) or the application
writes, so the ceilings are reached by real authenticated traffic, not by a
PSK-less flood. Boards should set `rcv_wnd` (§11); that is a recommendation of
these notes.

An allocation failure at promotion is **not** permanent: §8.5's
allocation-failure branch frees the retired primary, so each failed promotion
returns the largest holder of memory on the device (§11) and the next attempt
needs one object rather than two. What the cap buys is that the device does not
get there in the first place; §14.5 records what genuinely is irreversible.

---

## 10. Concurrency — the two locks

There are exactly two locks. Every rule below is stated against one of them by
name.

### 10.1 `rec_lock` — short critical section

A spinlock-class lock on a microcontroller; a plain mutex on POSIX. It protects
**record state**:

- the pending records in full (§6.3), including their expiry and
  `pending_generation`
- the primary's metadata: keys, tuple, `generation` (the device-wide promotion
  counter, §8.5 (a)5), and the **c2s** replay window — the only window the
  device holds, since it has no s2c *receive* window (§8.5 (c), §7.5, §11). One
  carve-out: §8.5 (b) wipes and frees a **retired** primary's copy under
  `kcp_lock` alone, which is safe precisely because (a)5 detached it first — no
  reader can resolve it, so there is nothing for `rec_lock` to serialise against
- the pointer identifying the current primary KCP object
- `admission_epoch` and the two cached `epoch_tag` values (§4.4)
- the quiesced/live flag. There is **no liveness timestamp**: dead-link is KCP's
  own retransmission count (§9.4), §9.5 forbids an idle timeout, and nothing on
  the device would read one

Every operation under it is bounded and none allocates, transmits or does
cryptography — but several are larger than O(1) and the list is worth stating in
full: §6.2 step 2's 256-octet `memcmp`, and its 128-octet key wipe when the
lookup finds the record expired (§6.3); §6.2 step 7's 338-octet store (FINISH +
ADMIT); §8.5 (a)4's 190-octet copy and (c)'s 190-octet install; the
O(`PENDING_SLOTS`) scans in §6.2 step 7's eviction, §9.2's expiry sweep (which
may wipe up to `PENDING_SLOTS`×128 octets of keys) and §8.1 step 2's tuple
lookup, that last on **every** envelope datagram. All are bounded by
`PENDING_SLOTS` and by fixed field sizes. **No cryptography, no allocation, no
transmission, nothing that can block, ever.** Held for microseconds.

**Outbound `seq_full` is NOT under either lock.** It is allocated by a lock-free
**compare-and-swap loop** (not `atomic_fetch_add` — see below), and the session
generation is passed to the output callback **by value**. §9.2 mandates a
maintenance tick and §8.4 has the RX path emit ACKs, so the counter has two
producers by design. On the device §10.3 happens to run both flushes under
`kcp_lock`, which already serialises them — but these notes recommend that nonce
uniqueness not rest on that placement: a client need not share this lock layout
(§7.5), and one flush moved outside the lock would otherwise turn a locking slip
into two datagrams under one nonce, which exposes both plaintexts and lets an
eavesdropper forge datagrams under that sequence number (`spec/transport.md`
11.2), in a session §9.5 never ends. The atomic is the guarantee; the lock is
not.

It is lock-free for cost, not for ordering: `kcp_lock → rec_lock` is the legal
direction, so a callback taking `rec_lock` from inside `ikcp_flush` would be
ordered correctly. What makes the atomic necessary is nonce uniqueness, and what
makes it cheap is that the callback needs no lock **for the sequence**; it still
takes `rec_lock` for §8.4's generation re-check (§10.3). A corollary that must
not be left implicit: **the output callback should not be reached while
`rec_lock` is already held**, or that re-check re-enters a non-reentrant
spinlock and hard-deadlocks. The operational form of that recommendation, since
the callback is reached only from a flush: **`rec_lock` is not held across
`ikcp_flush`, nor acquired from inside it.**

Two paths make this easy to get wrong, and both are ordinary operation rather
than attack:

- **Dead-link detection.** `ikcp_flush` latches dead-link mid-flush and keeps
  emitting afterwards, so writing the `quiesced` flag under `rec_lock` at the
  point of detection deadlocks on the next segment. Record it in a local and
  apply the flag **after the flush returns**, still under `kcp_lock`.
- **The RX-path ACK flush.** §8.6 writes the `quiesced → live` flag under
  `rec_lock` and the RX path then flushes to emit ACKs (§8.4, §12). The write
  must complete and release `rec_lock` **before** that flush begins; they may
  not be nested.

`atomic_fetch_add` alone cannot implement §3.6's fail-closed-on-wrap, because it
returns the pre-increment value after a sibling may already have claimed the
next. Use a compare-and-swap loop that refuses to advance past the limit.

### 10.2 `kcp_lock` — mutex

Protects the **`ikcp` object**: `ikcp_input`, `ikcp_flush`, `ikcp_create`, the
free of a released primary, and §9.4's in-place resume re-base — which walks
every `snd_buf` segment and is therefore `kcp_lock`-only work, never
`rec_lock`'s. Held for as long as a flush takes, which may be milliseconds when
a full window is retransmitted.

Object lifetime lives here, alongside flush, which is what makes §8.5's release
of the previous primary safe: the maintenance tick cannot be inside a flush of
an object another task is freeing, because both need `kcp_lock`. No
deferred-free mechanism is required.

### 10.3 Ordering and placement

**These notes recommend that `rec_lock` not be held across an acquisition of
`kcp_lock`.** Where both are needed — §8.5's promotion, §8.6's primary re-read,
§8.4's output-callback generation re-check, §9.2's tick, and the
`live`/`quiesced` transitions — take **`kcp_lock` first, then `rec_lock`**, as
the table below assigns. The tick is the one most easily got wrong: it flushes
under `kcp_lock` *and* sweeps pending expiry under `rec_lock`, and an
implementation that sweeps first while holding `rec_lock` and then flushes takes
the forbidden direction and deadlocks against a promotion holding `kcp_lock` and
waiting on `rec_lock`. Every other path takes one lock, finishes with it,
releases, and only then takes the other.

Restricting this to §8.5's promotion alone would, for §8.6, reintroduce the
use-after-free §8.6 exists to prevent — release `rec_lock`, block on `kcp_lock`,
and a promotion frees the object in between — and for §8.4 would not be
implementable at all, since the callback runs inside `ikcp_flush` with
`kcp_lock` already held.

| Operation | Lock |
| --- | --- |
| §6.1 step 4: read `admission_epoch` and `epoch_tag` for the RETRY — **compute `retry_mac` and transmit after release** | `rec_lock` |
| §6.2 step 2: pending lookup (discarding an expired record and wiping its keys, §6.3), `memcmp`, copy ADMIT out — **transmit after release** | `rec_lock` |
| §6.2 step 7: epoch CAS, stores, install pending, **the outgoing record's key wipe, and the oldest-slot scan and eviction when the table is full** — derive and transmit outside | `rec_lock` |
| §8.1 step 2: candidate selection, key/mark/generation copy | `rec_lock` |
| §8.1 step 4, primary path: recheck, accept-test, mark — **release before step 5** | `rec_lock` |
| §8.6: `ikcp_input` | `kcp_lock` |
| §8.5 (a) claim: re-check `pending_generation`, accept-test, `sn=0` test, mark, claim, **copy keys + tuple + replay window + generation into the promotion buffer**, retire the outgoing primary | `kcp_lock` held, `rec_lock` nested |
| §8.5 (b) build: set s2c `seq_full` to 1, `ikcp_create`, feed, then wipe + free the **retired** primary. `seq_full` is under neither lock (§10.1); `kcp_lock` is what excludes the flush that hosts its CAS producer | `kcp_lock` only |
| §8.5 (b) allocation failure: wipe the promotion buffer, discard the claimed record and wipe its keys **if its generation is unchanged**, then free the retired primary, set primary = none | `kcp_lock` held, `rec_lock` nested for the record and pointer |
| §8.5 (c) install: bind `conv`, install keys/tuple/window **from the promotion buffer**, **wipe the promotion buffer**, clear pending and wipe its four keys only if its generation is unchanged | `kcp_lock` held, `rec_lock` nested |
| §8.6: re-read primary + re-check generation | `kcp_lock` held, `rec_lock` nested |
| §9.2 maintenance tick: `ikcp_update` / `ikcp_flush`, **then** the pending-expiry sweep; on an epoch boundary, the `epoch_tag` recompute (§4.4), an HMAC computed outside both locks | `kcp_lock` held, `rec_lock` nested for the sweep — **never the reverse**; the recomputed tag is stored under `rec_lock` |
| RX-path ACK flush after `ikcp_input` (§8.4, §12) | `kcp_lock` only; `rec_lock` is already released |
| `live → quiesced` — dead-link latched **during** a flush, flag written **after it returns** (never inside it, §10.1) — and `quiesced → live` after a successful `ikcp_input` (§8.6) | `kcp_lock` held, `rec_lock` nested for the flag write only — **released before the ACK flush above** |
| Application send: `SEND_QUEUE_MAX` check **and** `ikcp_send`, as one operation | `kcp_lock` |
| §8.4 output callback: atomic sequence | none |
| §8.4 output callback: generation re-check | `rec_lock` nested inside the held `kcp_lock` |

**No verification of an unauthenticated inbound datagram — its MAC, its AEAD
open, HKDF, or a scalar multiplication — may run under either lock.** That is
what stops a flood from holding a lock. Two unauthenticated operations are taken
under `rec_lock`, both deliberately: §8.1 step 2's tuple lookup, which runs for
**every** envelope datagram including one matching no record, and §6.2 step 2's
`memcmp`. Both are fixed-cost and allocation-free, and both are on `rec_lock`
rather than `kcp_lock` so neither can block a flush; transmission happens after
release. The lookup is the cheaper of the two for an attacker to drive — 44
octets, no magic, no precondition — and §14.3 records what that costs. It is
still a per-packet spinlock acquisition an attacker can drive, and §11 accounts
for it.

Splitting the locks this way is what removes starvation: with flush and record
lookup on one lock, the RX path and the maintenance tick would contend for the
same mutex, a tick that gives up when the lock is busy would keep giving up, and
per §9.2 the dead-link counter it drives would never advance — so
`live → quiesced` could never fire on a busy session. With two locks a flush
blocks neither lookups nor the control path. It does block a promotion, which
holds `kcp_lock` throughout (§8.5) — once per admission, not per datagram.

Copied per-session key material is wiped on every exit path, including §6.2 step
7's abort and §7.4's, as the specification requires (`spec/transport.md` 12.2
item 8, 9.2 step 7, 10.5 step 4 and 6.4 item 5).

No scheduling preference is given to established output over admission
responses. Such a preference would be a failover veto, because a struggling
incumbent generates output continuously until dead-link and would starve every
admission response for that whole window.

---

## 11. Resource budget (device)

The point of the design is that these are **fixed** and small. Every figure is
per-device, not per-peer: pending records are a fixed `PENDING_SLOTS`-entry
array and there is one session.

| Resource | Bound |
| --- | --- |
| pre-PSK KCP allocations | 0 |
| pre-PSK heap allocations | 0 **in protocol code**; the IP stack still allocates a receive buffer per datagram before any demux runs — see the note below |
| retained challenge state | 0 — RETRY is stateless |
| pending records | `PENDING_SLOTS` × 536 B = **1 072 B** at the default 2, static array. Sized jointly with `PENDING_TTL_MS` (§2) (FINISH 256 + ADMIT 82 + 4×32 keys + tuple 18 + window 40 + counters 12) |
| primary records | 1 KCP session, plus **199 B** of per-primary metadata held outside the `ikcp` object: 4×32 keys + 18 tuple + 4 `generation` + 40 c2s replay window + 8 s2c `seq_full` + 1 quiesced/live flag. Most of it is `rec_lock` state (§10.1); the s2c `seq_full` is deliberately not (§10.1's CAS rule). `conv` is excluded — it lives inside the `ikcp` object — as is `admission_epoch`, which is device-wide; `generation` is the device-wide promotion counter (§8.5 (a)5), counted here once |
| replay state | 8 B high-water + 32 B bitmap **per window**. All device-side windows are c2s: one per live primary plus one per held pending record, so up to `1 + PENDING_SLOTS` = 3 at the default, already counted in the two rows above. The client holds one s2c window. The device has no s2c *receive* window (§8.5 (c)) |
| admission timers | 0 |
| promotion buffer (§8.5 (a)4) | **190 B** static, one device-wide: 4×32 keys + 18 tuple + 40 replay window + 4 generation. One buffer suffices because `kcp_lock` serialises promotions end to end |
| long-lived key material | `k_dev` 32 B + `k_req` 32 B + `k_resp` 32 B = **96 B**, plus `cookie_secret` 32 B (§4.2). **The domain PSK is not kept on a device** (§0), except that under the second provisioning method of `spec/transport.md` 3.2 it is handed over once and erased |
| per-input CPU cost, every path | see **§12** — not restated here |
| send queue and receive buffers | `SEND_QUEUE_MAX` is a hard cap on the application octets in `snd_queue` + `snd_buf` (§9.5), headers excluded, so it is **not** the whole per-session figure: each queued send segment adds ~60 octets of `IKCPSEG`, and `rcv_buf`, `rcv_queue` and the ack list are bounded separately by `rcv_wnd`. Worst case against free heap — two sessions whose key-holding peers ignore the advertised window (below) — is `2 × (SEND_QUEUE_MAX + s·~60 + 3·(mtu+24) + 2·rcv_wnd·(mtu − 24 + ~60) + fixed)`, `s` being the number of queued send segments, where `mtu` is **KCP's** MTU — `WIRE_MTU − ENVELOPE_LEN`, 1380 (§8.4) — throughout this section |
| X25519 code | ~7.7 KB |
| X25519 stack | ~840 B **for the scalarmult leaf only** — the same frame also carries the HKDF contexts (~300–450 B), the ADMIT construction, `ikcp_create` at promotion, the socket call chain, and Xtensa register-window spill that grows with call depth. Budget the whole path, not the leaf, against ~4 KB of usable RX stack |

**Session sizing — resident cost versus worst-case ceiling.** A distinction the
threat model turns on: `ikcp_create` allocates only a control block plus a
`3·(mtu+24)` scratch buffer (4.2 KB at KCP's `mtu` of 1380) — about **5 KB** —
and initialises four *empty* queues. `rcv_buf`, `rcv_queue`, `snd_buf` and
`snd_queue` hold no segments at creation and grow one `ikcp_malloc` at a time as
data actually arrives or is queued. So a live session's **resident** footprint
on a LAN pixel stream is a handful of segments, single-digit KB, not the window
size.

`rcv_wnd` and `SEND_QUEUE_MAX` are **ceilings**, not allocations:

| Bound | Ceiling | Reached when |
| --- | --- | --- |
| receive side | `rcv_wnd × (mtu − 24 + ~60)` — e.g. **~91 KB** at `rcv_wnd = 64`, `mtu` 1380 | a peer parks a full window of out-of-order segments; up to twice the ceiling for a key holder that ignores the advertised window (below) |
| send side | `SEND_QUEUE_MAX` (§9.5) | a vanished peer stops acking and the queue fills |

The ceiling matters only for worst-case bounding, and reaching the *receive*
ceiling requires an **authenticated** peer — segments enter `rcv_buf` only after
the AEAD opens (§8.1), so a PSK-less attacker cannot drive a session toward it.
§9.5's "size so two sessions fit" is therefore a bound on the worst case a
*legitimate* peer can create, not a description of steady state. It assumes the
peer honours the advertised window, which shrinks by whatever sits in
`rcv_queue`: a key holder that ignores it can park a full window in `rcv_buf`
while `rcv_queue` is also full, up to twice the receive ceiling. The worst-case
figures below count that case.

**Recommended values, a starting point to validate on the target, never used
unmeasured.** They are set per board, and boards should set `rcv_wnd`
explicitly:

| Constant | Recommended | Why |
| --- | --- | --- |
| `WIRE_MTU` | 1400, so KCP's `mtu` is **1380** | the datagram must not fragment. KCP is given `WIRE_MTU − ENVELOPE_LEN` (§8.4), **never** `WIRE_MTU`: a KCP `mtu` of 1400 emits 1420-octet datagrams that §3.6 drops |
| `rcv_wnd` | **8** | 8 segments ≈ 11.3 KB ceiling covers LAN-RTT pixel throughput. Raise (with `ikcp_wndsize`; the free receive window is advertised in every header's `wnd`) only after measuring |
| `SEND_QUEUE_MAX` | **6 KiB** | caps the send side against a vanished peer (§9.5) |

At those ceilings a session parked by a peer that honours the window is ~23 KB
(6.1 send + 0.3 send-segment headers + 4.2 scratch + 11.3 receive + under 1
fixed), and two are ~46 KB. Against key holders that ignore the advertised
window the receive term doubles to 22.7, so the *worst case* is ~34 KB per
session and ~68 KB for the two that §8.5 briefly holds. These notes do not
assert that this fits: measure it against the board's free heap with Wi-Fi
running. `sizeof(IKCPSEG)` is taken as ~60 on a 32-bit part; re-check against
the actual allocator, since fragmentation on a no-MMU device (§14.5) can defeat
a figure correct in total.

Two implementation constraints follow from the table rather than from security:
the pending records are a **static array**, not allocations; and the X25519 must
not share a stack frame with the receive buffer without measuring headroom
first.

**What this table does not bound.** Every row is a cost *per datagram*; none is
a cost *per second*, and the threat model grants unbounded packet rate. Three
device costs sit below this protocol entirely and cannot be refused here: the IP
stack's per-datagram buffer and its receive queue, which saturates and drops
PSK-blind before any rule in this document runs; IP reassembly (§8.1); and the
spinlock section around record lookup, which on a dual-core part stalls the
rendering core for its duration, so unauthenticated junk modulates application
timing. Sizing those is a deployment exercise; pretending they are zero is not.

A quiesced primary (§9.4) also holds far more than the pending record does —
four keys, its c2s window, the tuple, and the whole KCP object with its
`3·(mtu+24)` buffer, plus whatever `SEND_QUEUE_MAX` and `rcv_wnd` permit — and
§9.5 forbids reclaiming it. That is the largest holder of memory on the device,
and it is bounded only by `SEND_QUEUE_MAX` and `rcv_wnd`.

---

## 12. Anti-flood properties

| Input | Device cost | Response |
| --- | --- | --- |
| **every** datagram, before anything else | one address compare against §4.3's list for its family (§5 step 0) — add this to every row below | none if rejected |
| junk, no magic, unknown tuple | length check + one guarded tuple lookup (§8.1 step 2) | none |
| junk, no magic, spoofed known tuple | 1 AEAD open ≤ `WIRE_MTU`; **2** when that tuple also holds a pending record (§8.1 step 3 falls through) | none |
| junk with magic, bad `init_mac` | 1 HMAC | none |
| valid INIT | 3 HMAC (`init_mac`, cookie, `retry_mac`) | 84 B |
| FINISH, bad cookie | 1 HMAC (cookie), dies at §6.2 step 3 | none |
| FINISH, valid cookie, **stale epoch** | 1 HMAC (cookie), dies at §6.2 step 4 — this is what makes a capture one-shot (§14.4) | none |
| FINISH, no pending record, bad `client_tag` | 1 HMAC (cookie) + 1 HMAC (`client_tag`) | none |
| byte-identical FINISH, pending held | 256-octet `memcmp` | 82 B |
| FINISH on a spoofed pending tuple, mismatch | 256-octet `memcmp` + 2 HMAC | none |
| valid FINISH (PSK holder) | 3 HMAC + **2 X25519** + 1 Extract + 5 Expand | 82 B |
| valid FINISH losing the CAS | same, and **no response** | none |
| established datagram → `ikcp_input` | AEAD open + KCP segment processing, `snd_buf` walk, ACK generation | ACK, ≤ `WIRE_MTU` |
| promoting datagram (§8.5) | AEAD open + `ikcp_create` + `3·(mtu+24)` buffer + a free — **the largest per-input cost in the protocol**, and the only one that allocates. Its `rec_lock` hold in (a) includes a 190-octet copy into the promotion buffer (§10.1) | none |

The last row is why §7.2's revalidation rule is not free and why §14.4 records a
fragmentation path: promotion is an input an authenticated peer can drive.

**Client-side cost has no separate table and belongs here.** Per forged ADMIT
**in `AWAIT_ADMIT`**: one `admit_pre` HMAC, then — only if that passes — one
X25519 for the first novel `e_s` (cached thereafter, §7.4 step 4) and ~28
SHA-256 compressions for §4.5's derivation (§14.3). That cost is bounded by
`FINISH_PHASE_MS` (§2), and past `AWAIT_ADMIT` a forged ADMIT is dropped by
§7.1's state table for the price of the lookup. Per spoofed envelope at an
established client's tuple: one AEAD open over up to `WIRE_MTU` — **this** one
has no phase timer bounding it (§2, §7.5).

Every row is **bounded per datagram**, and every control-path row is fixed-size.
The envelope row is bounded but not fixed — it is `≤ WIRE_MTU`, which is
attacker-chosen within that bound, and at 1400 octets on an unaccelerated
microcontroller it is the most expensive PSK-less input in the protocol.

**None of these rows is bounded per second.** The threat model grants unbounded
packet rate, so every figure multiplies by it; "fixed cost" is not "safe". What
the design actually buys is that no input is *super*-linear and nothing
allocates.

Responses are 84 (RETRY) and 82 (ADMIT) octets against a 256-octet trigger —
0.328× and 0.320×. Keeping each under a third is the **stated ceiling**: one
third of 256 is 85.33, so **RETRY binds it with 1.3 octets to spare** (ADMIT has
3.3). Any new field in either response requires raising `REQUEST_LEN` in the
same change.

No rate limiter is specified. A global one on admission lets unrelated traffic
suppress a legitimate backup, which is a worse failure than the flood.

**Forced transmission, and why byte ratios understate it.** A captured INIT is
replayable forever from any spoofed source, and each replay forces an 84-octet
transmission. On Wi-Fi the contended resource is **airtime**: an 84-octet and a
256-octet frame differ by tens of microseconds of payload but carry the same
preamble, DIFS, backoff, SIFS and ACK — which is precisely why the airtime ratio
is near **1**, not near the 0.33 byte ratio. Worked at 802.11n 65 Mbps: ~161 µs
of fixed overhead against ~10 µs and ~32 µs of payload gives ≈0.9, and at a
lower basic rate for the device's response it exceeds 1. The attacker's octets
also need not cross the air while the device's always do on a half-duplex radio.
Sustained, this steals receive airtime from the established session, delays its
ACKs, and can drive it to dead-link and §9.4 quiesce (§14).

---

## 13. Message layer

Discussed in [`message-layer.md`](message-layer.md); the rules are
`spec/message-layer.md` 6 (compression and padding, and the categories) and
`spec/application.md` 3.5 (each kind's category). It is keyed by this document's
`k_c2s`/`k_s2c` (§4.5), with two carve-outs, whose rationale is kept here
because they are consequences of this document's threat model rather than of the
message layer's own design.

First: **compression is permitted by payload shape, in three categories.** The
message layer does not name messages (below), so the layer above assigns each of
its kinds to one of these, and the specification binds it to that assignment.

| category | what it is | compression | padding |
| --- | --- | --- | --- |
| **Control and configuration** | a command or its parameters — a mode change, a parameter write, a query and its response | not permitted | recommended, per the class ladder below |
| **Bulk content** | one self-contained blob the controller is uploading whole | permitted | recommended when uncompressed; not permitted when compressed — see below |
| **Streaming data** (pixel frames) | the streaming data plane | permitted | not permitted — see §14.4 |

**Why control and configuration must not compress.** Compression before
encryption leaks plaintext redundancy through ciphertext length, and control
content is where that matters: the compressed length of a message that mixes
fixed structure with a varying parameter is a function of that parameter.

**Why bulk content may.** The attack that motivates the first rule needs an
attacker-chosen portion co-compressed with a secret in one context. A bulk
payload has neither: it is a single blob, uploaded whole, with nothing secret
mixed into it that the controller is not already transmitting in full. What
remains is a size fingerprint identifying *which* blob was uploaded — real, and
harder to dismiss than the pixel-frame residual below, because which blob was
uploaded is **not** visible to someone watching the lights. **This residual is
accepted and is not blunted by padding**, for the reason in the next rule: the
two mechanisms cannot be combined. It is accepted because the alternative is
pushing an uncompressed multi-kilobyte blob over a link to a device with
single-digit kilobytes of headroom. A deployment that considers the fingerprint
unacceptable for its catalogue sends that blob uncompressed and padded, taking
the cost instead, as the specification recommends (`spec/message-layer.md` 6.3).

**Why pixel frames may.** The residual — roughly how uniform a scene is — is
accepted, being visible to anyone who can see the lights.

**Compression and padding are mutually exclusive per message, and this is a
limitation rather than a preference.** A padded, compressed message would need
three lengths on the wire — the padded on-wire size, the compressed block's
size, and the true plaintext size — and the header carries two
(`message-layer.md` §5). Without the compressed size a receiver cannot find the
end of the LZ4 block: a decoder given the padded length either rejects the
trailing octets or, worse, keeps parsing them. A sender therefore does not set
`FlagCompressed` on a padded message, and the specification forbids it. Closing
this properly means a third length field, which is a wire change and is not made
here.

AEAD and monotonic `MessageNum` remain mandatory in every category; the envelope
replaces neither. A receiver accepts a compressed message whatever its type
(`spec/message-layer.md` 6.1), and rejects a message whose decompressed length
is not the `OriginalSize` its header declares.

Second: **every uncompressed message outside the streaming-data category is
recommended to be padded to a fixed size class** (`spec/message-layer.md` 6.3).
Forbidding compression stops content-dependent *ratio* leakage; it does not stop
a control message's own length identifying which message it is, and that is the
same information by a different route.

The classes are the powers of two from 64 B upward, and a message's plaintext is
padded up to the smallest class that holds it. **The ladder itself has no top; a
sender's does.** A sender pads only to classes it can emit — the class plus the
16-octet tag must not exceed its `MAX_MSG_PAYLOAD` (§2) or, where it knows it,
the receiver's bound (`spec/message-layer.md` 6.2), and it may stop lower — and
a payload above its top class is sent **unpadded at its true length**, never
refused for want of a class. A receiver therefore accepts the size class of
`OriginalSize` at any height within its own bound (`message-layer.md` §7) and
needs to know nothing about the sender's ceiling.

`MAX_MSG_PAYLOAD` is itself bounded by the send queue (§2): a message that does
not fit an empty queue can never be written. "Fits" is measured the way the
implementation enforces `SEND_QUEUE_MAX` — one that accounts whole KCP segments
rounds the usable queue down to a multiple of the segment size, and the 20-octet
message header counts against it. Classes rather than one fixed size, because
this layer carries both a small control write and a multi-kilobyte upload;
padding everything to the larger is not affordable, and padding to the smaller
is impossible. Powers of two because the overhead is then bounded at under 2×
**for anything above the 64 B floor** with no knowledge of the message
inventory. (An 8-octet write pads to 64 B, which is 8×; that is the price of not
leaking which small control message it was.) Needing no inventory is the point:
**this document does not name the messages, and a padding rule that required
their sizes would go stale the first time one was added.**

`MAX_MSG_PAYLOAD` is per architecture because the ceiling is a memory question,
not a protocol one — a small microcontroller cannot queue what a large ARM
controller can. It is a **send** bound. The matching receive bound is the
receiver's own and is stated by the message layer (`message-layer.md` §7.1),
which also carries the protocol-wide `MaxPayloadSize` above both; a layer that
needs the peer's receive bound advertises it, as `DEVICE_INFO`'s `envelope` does
(`spec/application.md` 5.3). A message is still fragmented across KCP segments
sized to KCP's `mtu`, `WIRE_MTU − ENVELOPE_LEN` (§8.4).

Padding is inside the AEAD, so it is not separately visible, and the receiver
needs the true length to strip it — the existing message header already carries
a true-length field alongside the on-wire size, which is where it belongs. Pixel
frames are deliberately excluded (§14.4).

---

## 15. Test vectors

Byte-exact, and the same for every implementation. **The vectors are published
in this repository**, in
[`vectors/shieldnet-v1-vectors.json`](../vectors/shieldnet-v1-vectors.json),
generated by [`vectors/gen_vectors.py`](../vectors/gen_vectors.py) from an
implementation independent of any other — Python's standard HMAC, with HKDF
written over it, plus a general-purpose X25519 and ChaCha20-Poly1305 — so an
error shared by the implementations under test is still caught. That file is the
source of truth; an implementation's test asserts it and does not originate it.
The JSON carries the byte-level cases (key schedule, the four messages, wire
rejection cases, source classification, envelope, replay script,
reconstruction); the behavioural cases below that need a running device —
promotion interleavings, quiesce/resume, `SEND_QUEUE_MAX` — are each
implementation's own tests, and the list is what they must cover. Published so
every derivation is reproducible: a nominal PSK, a `device_id`, and the `k_dev`
derived from them (§0); nominal `cookie_secret` and `admission_epoch`; a nominal
`cookie_epoch`; and — necessarily, since they are neither per-boot secrets nor
storable — **nominal `e_c` and `e_s` private keys**.

- `L(...)` encoding of every label (an implementation's own test: the JSON
  carries the labels only inside the values that follow); `prk_psk`; `k_dev`
  from PSK+`device_id`; `prk_static`, `k_req`, `k_resp`. Two distinct PSKs under
  one `device_id`, to pin that `k_dev` depends on the PSK and not on `device_id`
  alone; and two `device_id`s under one PSK, to pin that siblings' device keys
  differ (§0).
- All four messages at their fixed lengths.
- `canonical_source` for a v4 and a v6 peer.
- §4.3's source-rejection list, accept and reject cases separately, because this
  is where two conforming implementations most plausibly diverge. The cases are
  in `source_cases` of the JSON file; the rule is `spec/transport.md` 7.2. A
  suite that tests only one v4 and one v6 address does not touch a single case
  where the two readings §4.3 describes disagree.
- `cookie_epoch` → `epoch_tag` derivation; and, as an implementation's own test,
  a FINISH whose cookie is from the previous epoch (accepted) and one from the
  epoch before that (discarded).
- `context`, `context2`.
- `init_mac`, `cookie`, `retry_mac`, `client_tag`, `admit_pre`, `admit_tag`.
- X25519 normal and all-zero-output cases; `master` and all four expanded keys.
- Envelope encrypt/decrypt; replay-window accept, duplicate-reject and
  too-old-reject at both window edges.
- Sequence reconstruction: session start; a delayed datagram below the mark;
  both directions across the 2³² boundary; `candidate == 0` and `candidate < 0`;
  and **`d32 == 0x80000000`**, the exact tie §8.3 is written longhand to pin:
  forward and backward are equidistant and the rule resolves it backward, so an
  implementation that resolves it forward, or whose signed conversion traps or
  saturates, diverges here.
- Promotion with packed `sn=0` and `sn=1`; a datagram with `sn=1` alone
  (discarded, not marked); a duplicate of the promoting datagram (no second
  promotion); a second datagram after promotion (pins the pending clear).
- ADMIT with valid `admit_tag` but corrupted `admit_pre` (pins §7.4's ordering);
  a duplicate ADMIT after commitment (pins the nonce-reuse gate).
- `pending_generation` mismatch rejection; a CAS-abort FINISH.
- **A pending record reaped or replaced during §8.5 (b)** — the interleaving
  (a)4 exists for, and the one an implementation is most likely to get wrong:
  - record expires during (b): the promotion still installs the keys **and the
    marked replay window** from the promotion buffer, and the promoting datagram
    does **not** replay against the installed primary;
  - record replaced during (b) by a valid same-tuple FINISH: the promotion
    installs the claimed admission's material, and **the replacement's slot is
    left intact** — its own promoting PUSH must still succeed;
  - allocation fails in (b) after (a)4 copied: the promotion buffer is wiped.
- A captured FINISH replayed from a **different** tuple: rejected at §6.2 step 3
  (cookie recomputation), so it cannot reach another controller's slot.
- All `PENDING_SLOTS` held, then a FINISH from a new tuple: the **oldest**
  record is evicted and its four keys wiped; the others are untouched.
- A datagram that resolved the primary at §8.1 step 2 and arrives after a
  promotion retired it: the `generation` re-check rejects it (§8.5 (a)5), and it
  does not reach `ikcp_input` or an AEAD open under the wiped keys.
- `observed_source` mismatch (§7.3 step 2).
- Quiesce/resume preserving `seq_full`, the c2s window, `conv` and `generation`,
  **and** clearing dead-link with `xmit` reset and timestamps re-based.
- The replay mark on the **established** path: a captured in-window datagram
  replayed after promotion is rejected.
- A duplicate ADMIT arriving in `AWAIT_PUSH_ACK`, not merely after promotion.
- An INIT bearing a foreign `device_id`, rejected before any MAC (§6.1 step 2).
- Two admissions across a simulated reboot, showing `cookie_secret` makes
  `cookie`, `context` and `master` differ (§4.2).
- `SEND_QUEUE_MAX` at the cap: writes refused, then accepted after drain.
- Rejection vectors: **a 10-octet datagram of each of the four types** (pins the
  §3.5 length check that precedes every field read); wrong length for each type
  individually; non-zero padding; wrong `version`; reserved `type`
  `0x03`/`0x04`; each type in the wrong direction; and, as an implementation's
  own test (not in the JSON), an INIT/FINISH `type`-byte flip in both
  directions.
- The `N > WIRE_MTU` envelope rejection.
- The byte-identical FINISH → stored-ADMIT resend path, including that it does
  **not** refresh the pending expiry (§2).
- ADMIT with a valid `admit_pre` but a corrupted `admit_tag`: the client rejects
  it and remains able to process the genuine ADMIT that follows (pins §4.5's
  deferred ephemeral wipe).
- A RETRY with an invalid `retry_mac`, pinning §7.3's check order.

A suite exercising only low sequence numbers does not test the rules most likely
to be implemented wrongly.
