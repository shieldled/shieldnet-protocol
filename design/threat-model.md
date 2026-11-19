# ShieldNet v1 — threat model and residuals

> **Design notes — informative.** The specification is
> [`spec/transport.md`](../spec/transport.md), whose Security considerations
> section states what an implementer must rely on. This document is the full
> analysis behind it.

This is section 14 of the transport design notes
([`transport.md`](transport.md)), split out; its § citations
resolve there, and the section numbering here is continuous with those notes.

Nothing in this file is required on the wire. It carries the reasoning: what the
protocol is required to do, what it closes, what it merely bounds and what it
leaves open. §14.0 indexes it.

---

## 14. Threat model

### 14.0 Matrix

An index, not a restatement: each row names a threat, its status, whether the
attacker needs key material, and the subsection that owns the reasoning. **Change a
mitigation or a residual in its home subsection, never here.** A row that disagrees
with its home is a defect in this table.

"Needs key" means the attack is unreachable without the domain PSK or a `k_dev`.
Everything marked "no" is reachable without either, by an attacker with the §14.1
baseline: arbitrary spoofed UDP, link observation, and ICMP forgery. Suppression is
not in that baseline; a row that also needs it says so in its status.

| ID | Threat | Status | Needs key | Home |
| --- | --- | --- | :---: | --- |
| T01 | One unauthenticated datagram destroys a live session | Closed | — | §14.2 |
| T02 | On-path injection into an established session | Closed | — | §14.2 |
| T03 | Cold-start squatting on a freshly booted device | Closed | — | §14.2 |
| T04 | Unbounded pre-auth memory | Closed | — | §14.2 |
| T05 | Cross-device relay within a domain | Closed | — | §14.2 |
| T06 | Cross-reboot key reuse | Closed | — | §14.2 |
| T07 | Sequence rollover ambiguity across 2³² | Closed | — | §14.2 |
| T08 | Cross-type reinterpretation of the two 256-octet requests | Closed | — | §14.2 |
| T09 | Out-of-bounds read from a truncated control datagram | Closed | — | §14.2 |
| T10 | Duplicate ADMIT resetting the client's sequence | Closed | — | §14.2 |
| T11 | Duplicate promoting datagram (nonce reuse + use-after-free) | Closed | — | §14.2, §8.5 (a) |
| T12 | Version downgrade | Closed by construction | — | §14.2, §4.7 |
| T13 | Per-datagram CPU on the envelope path | Reduced | no | §14.3 |
| T14 | Guarded-path lock acquisition, every envelope datagram | Reduced | no | §14.3 |
| T15 | Forced transmission and airtime reflection | Reduced | no | §14.3, §12 |
| T16 | Client-side cost of a forged ADMIT | Reduced | no | §14.3 |
| T17 | Abandoned primary session memory | Reduced | no | §14.3, §11 |
| T18 | IP reassembly before any rule here runs | Reduced (recommended only) | no | §14.3, §8.1 |
| T19 | Suppress-and-replay of FINISH | Reduced — needs MITM (§14.1) | no | §14.4 |
| T20 | Oldest-slot eviction | Closed — transient records, deliberate admission (§7.2), one-shot captures | — | §14.4, §6.2 |
| T21 | On-demand presence and admission-count oracle | Accepted — §14.0a asks for none of it | no | §14.4 |
| T22 | Established-session traffic analysis | Accepted — §14.0a asks for none of it | no | §14.4 |
| T23 | Controller contention | Closed by §7.2's explicit control | — | §14.4 |
| T24 | Distinguishing a wrong PSK from any other failure | Closed by design | — | §14.2, §9.3 |
| T25 | No per-controller identity; revocation is domain-wide | Out of scope (§14.0a) | — | §14.4, §4.7 |
| T26 | Unbounded key lifetime inside a live session | Accepted | — | §14.4 |
| T27 | Silence is uniform in bytes but not in cost | Accepted — subsumed by §14.1's observation grant except for an inject-only attacker | no | §14.4 |
| T28 | Memory pressure turns a promotion into a double loss | Reduced — a §9.5 sizing obligation, not an attack | no | §14.4, §9.5, §11 |
| T29 | Induced promotion churn toward fragmentation | Out of scope — allocator behaviour; drives T33 | no | §14.6 |
| T30 | Attacker-driven backoff ratchet | **Closed** — §7.2's explicit control has no backoff | — | §7.2 |
| T31 | Recovery latency for a quiet client | Closed by §7.2's explicit control | — | §14.4, §7.2 |
| T32 | `admission_epoch` exhaustion | Terminal, unreachable | — | §14.5 |
| T33 | Heap fragmentation | Out of scope — allocator behaviour; terminal if reached, unverified | no | §14.6 |
| T34 | Product and deployment fingerprint on every datagram | Accepted — §14.0a asks for none of it | no | §14.5a |
| T35 | `device_id` as a permanent unrotatable identifier | Accepted — §14.0a asks for none of it | no | §14.5a |
| T36 | A controller carries domain identifiers onto foreign networks | Accepted — bounded by §7.2's explicit control | no | §14.5a |
| T37 | The wire identifies the best physical-extraction targets | Closed by §0's per-device derivation | — | §14.5a |
| T38 | Interaction timing discloses occupancy to an off-room observer | Accepted — §14.0a asks for none of it | no | §14.5a |
| T39 | `admission_epoch` publishes raw CSPRNG output | Accepted | no | §14.5a |
| T40 | Key material at rest | Out of scope | — | §14.6 |
| T41 | Continuous jamming | Out of scope | — | §14.6 |
| T42 | The message layer above the envelope | Out of scope | — | §14.6 |
| T43 | The platform CSPRNG | Out of scope | — | §14.6 |
| T44 | Physical and side-channel attacks | Out of scope | — | §14.6 |

**Reading it.** Eighteen closed, eight reduced, nine accepted, **no open rows**,
one terminal, eight out of scope.

*Accepted* means the row is real and §14.0a asks for nothing that it violates —
mostly disclosure and correlation (§14.5a). *Reduced* means a real cost with a stated bound. Nothing
remains open against §14.0a's third
requirement, that denial be expensive, once §11's sizing obligation is met.
**No row needs key material to be reachable.** T25, the one that did, is scoped out
by §14.0a. T30 is closed because §7.2's explicit control has no backoff to
ratchet, and heap fragmentation (T29, T33), the only permanent state not shown
unreachable, is an allocator property held out of scope (§14.6) — real enough to keep on the matrix, not something the wire protocol
can address.

**Not in this table:** there is no path for an attacker without
the PSK to establish a session, take over an established one, inject a command,
recover key material, or force a key or nonce to repeat. Those goals are covered by
T01–T12 and by §8.5's promotion rules; §14.5b lists the rules that make it so.

### 14.0a What this protocol is required to do

A threat model without stated requirements drifts toward closing everything. These
are the functional requirements, and rows below are judged against them:

1. **Authenticate controllers.** Up to two controllers, **one active at a time**,
   each able to be admitted; whether they are two boxes or one box twice does not
   matter, and the protocol is not required to tell them apart. Taking control is an
   **explicit** application action (§7.2) — there is no automatic failover and no
   automatic retry.
2. **Discard anything without a valid MAC.** A handshake message that fails its MAC
   changes no state and elicits no response.
3. **Make denial expensive, not impossible.** An attacker who controls packet
   delivery can deny service to almost any protocol; the requirement is to raise the
   cost and bound the damage, not to eliminate it.

All three are met as specified: (1) by `PENDING_SLOTS` tuple-keyed records
(§6.3), one per controller at the default of 2, with no spare (§2); (2) by §6.1 step 3's `init_mac` and
§6.2 step 5's `client_tag`, both verified before any state change and before the
scalar multiplication; (3) by §12's per-input cost bounds and §14.3's honest
statement of what is merely reduced.

**Four hard assumptions.** These are design inputs, and rows below
are scoped by them rather than left open by omission:

- **Two controllers, one active, explicit enable.** Taking control is a one-shot
  application action (§7.2). There is no automatic retry, no backoff, and no
  automatic failover; if the active controller dies the standby does nothing until
  told. Distinguishing one authorised controller from another is not required.
- **PSK possession is authorisation** (§14.1). Anything a current PSK holder does
  through the protocol is legitimate, so there is no "hostile but authorised
  controller" in this model.
- **The PSK is installed out of band and does not rotate** (§4.7). Exactly one PSK is live;
  replacing it means reprovisioning every device and restarting the stack. There is
  no generation identifier on the wire, no rolling upgrade, and no revocation
  mechanism finer than replacing the PSK.
- **The PSK is not shared with any other system.** A deployment provisions a PSK
  generated for this protocol alone (§4.7). Every device holds only its own derived
  `k_dev`; nothing on a device yields another device's keys. A system that puts one
  shared secret on every device does not have that property, and a device of that
  kind sharing this PSK would undo §0's per-device isolation for the whole fleet.

### 14.1 Trust model and attacker capabilities

One pre-shared key is held by **every controller** in a domain. A device is
provisioned with `k_dev = HKDF(PSK, device_id)` and, except under the second
provisioning method of `spec/transport.md` §3.2, never with the PSK itself
(§0), so devices *are* separated from one another. Controllers are not: there is
no per-controller secret, and most of what this section cannot close follows from
that.

The attacker sends arbitrary UDP at line rate, spoofs any source, observes all
traffic on the local link, injects to either party, **may forge ICMP** to either
party, and knows this document. It holds neither the PSK nor any `k_dev`.

**Suppression is not in the baseline, and rows that need it say so.** Dropping one
specific frame while letting others through requires an **on-path** position — being
the access point, controlling it, or ARP-spoofing into a MITM. Timed RF jamming of a
single predicted frame is not a realistic capability against this deployment, and a
deauthentication kills the whole association rather than one packet. Every position
that grants selective suppression also grants **continuous** denial, which §14.6
places out of scope, so a model that grants the former while excluding the latter is
claiming an attacker who chooses the weaker of two tools it holds.

The stealth argument for that choice — continuous denial is noticed, one dropped
frame is not — does not carry here: where the device has visible output, such as lights, denial
is conspicuous either way; a device without visible output loses that argument. Rows below that require suppression are therefore scoped
to an attacker who has already achieved MITM, and are priced as *what such an
attacker additionally gains*, not as things a station on the same network can do.

**PSK possession is authorisation.** Any party holding the *current* PSK is a
legitimate client, by assumption, and nothing it does through the protocol is an
attack: filling pending slots, displacing an incumbent, holding the primary
silently, or admitting repeatedly are all things an authorised controller may do.
This document therefore models no "hostile but authorised controller", and rows
below that would otherwise need one are not threats.

There is no "retired PSK" case: §4.7 makes replacing the PSK a reprovision-and-
restart, so at any moment exactly one PSK is live and everyone holding it is
authorised. Replacing a compromised PSK is a flag day, and that is the only
revocation this document offers.

ICMP is listed because two rules depend on it and neither is optional: §7.6 and
§9.3 exist because one spoofed port-unreachable per second would otherwise make
admission permanently impossible.

*Repeated* single-frame suppression is not a separate capability: a MITM that can
drop one frame can drop one per attempt. It does not reopen downgrade, which is
closed by construction (T12, §14.2), and it does not make a capture reusable —
single-use `admission_epoch` keeps each captured FINISH one-shot (§14.4).

**The rows that rely on suppression should be taken seriously.** Those attacks need the
MITM to drop exactly one frame and then *cooperate* with the protocol — that is
not jamming (§14.6) and must not be dismissed as such. For an attacker in that
position, suppressing one FINISH is the most productive capability in this model.

### 14.2 Closed

Each row cites the mechanism that actually does the work.

| Attack | Closed by |
| --- | --- |
| One unauthenticated datagram destroys a live session | The primary is freed only inside §8.5, gated on a pending record that requires a verified `client_tag` (§6.2 step 5) and a datagram opening under `k_kcp_c2s`, or when the message layer ends the session. No unauthenticated datagram can trigger either; an on-path attacker who withholds traffic mid-message for longer than the receiver's partial-read bound can trigger the second (`spec/message-layer.md` §8 item 2), and `spec/transport.md` 17.3 does not claim availability against an on-path attacker |
| On-path injection into an established session (spoofed `conv`, forged ACKs) | §8.1 step 3 forbids reading any KCP field before the AEAD opens; §8.6 rejects a foreign `conv` |
| Cold-start squatting on a freshly booted device | Nothing reaches the primary without the DH, and §4.2 redraws `cookie_secret` and `admission_epoch` per boot, so no pre-reboot capture validates. (§2's current-epoch-only rule at boot exists to stop `current − 1` wrapping to `0xFFFFFFFF`, not to close squatting.) §4.2 also forbids serving admission before the CSPRNG is available |
| Unbounded pre-auth memory (withheld `sn=0`, out-of-order parking) | §8.5 requires PUSH `sn == 0` on the first segment and drops anything else without marking. The bound is the fixed `PENDING_SLOTS` array (§6.3, §11) and the §9.2 tick's expiry sweep — **not** PSK possession: §14.4 establishes that a captured FINISH installs a pending record without it. Scoped to protocol state; the IP stack's own pre-demux buffer is §14.3's |
| Cross-device relay within a domain | Closed three deep: `k_dev` is per-device (§0), so a sibling's `retry_mac`/`admit_pre` cannot verify at the client; `cookie_secret` is per-boot per-device (§4.2) and the cookie is recomputed over the receiving datagram's source (§6.2 step 3), so a relayed FINISH fails; and `device_id` is in `init_mac` and `context` (§3.1, §4.5) |
| Cross-reboot key reuse | `cookie_secret` is 32 octets of CSPRNG output redrawn each boot and is an input to `cookie`, hence to `context` (§4.2, §4.4). Rests on §4.2's CSPRNG requirement, not on a protocol mechanism |
| Sequence rollover ambiguity across 2³² | §8.3's `d32`/signed-`candidate` split; a forward-jump forgery gets a wrong nonce and dies in the AEAD before §8.2 marks |
| Cross-type reinterpretation of two 256-octet requests | `type` and `version` are inputs to `init_mac`, `retry_mac`, `client_tag` and `admit_pre` (§4.4) |
| Out-of-bounds read from a truncated control datagram | §3.5's length-before-field-access, applied as step 1 of §6.1, §6.2, §7.3, §7.4. §15 pins it with a 10-octet datagram of each of the four types |
| Distinguishing a wrong PSK from any other failure | §9.3's uniform silence: a controller with the wrong PSK fails exactly as a flood, a misconfiguration or an unreachable device does, so an observer learns nothing from which failure occurred. The flip side is accepted and is **not** a protocol residual — an operator cannot diagnose it either, and with the PSK installed out of band (§4.7) that is a commissioning-time cost |
| Duplicate ADMIT resetting the client's sequence | §7.1's two drop cells plus §7.5's single-thread requirement make the commit a genuine test-and-act |

**Steady-state replay within an established session** is closed by §8.1 step 4's
atomic test-and-mark against the *current* high-water mark, and §8.5's rule that
the already-marked window is not re-initialised. **The promotion window is closed
too**, by §8.5 (a) 1–4: a duplicate promoting datagram fails the
`pending_generation` re-check.

**Version downgrade** is closed by construction: only one version has ever been
assigned, and a build implements no other, so there is no fallback to negotiate
down to (§4.7). It is listed here rather than as a residual because the two things
it depends on are checkable rather than probabilistic — that the binary contains
exactly one version handler, and that the PSK is fresh. Reusing a PSK from a system
that provisions one shared secret to every device reopens it completely: one
extracted device then yields every `k_dev` (§4.7). That is a provisioning error,
not a protocol residual.

### 14.3 Reduced — bounded, with the bound stated honestly

| Residual | Real bound |
| --- | --- |
| Per-datagram CPU | Fixed only on the **control** path. The envelope AEAD open is attacker-chosen 44…1400 octets (~32× spread), and costs **two** opens while a pending record shares a tuple with the primary (§8.1 step 3's fall-through). Unbounded in aggregate |
| Guarded-path (lock) acquisition | **Every envelope datagram takes the record lock at §8.1 step 2, including one matching no tuple** — 44 octets, no magic, no captured material, no precondition. On a dual-core part this stalls the rendering core (§11), so the payoff is visible artefacts in the light output |
| Forced transmission / reflection | Byte ratio is under 1; **airtime ratio is ≈0.9 and unbounded if the attacker injects from the wired side of an AP** (§12). A replayed FINISH via §6.2 step 2 is *cheaper in device CPU* (82 octets forced for a 256-octet `memcmp`, no HMAC) but is a **worse reflector** — §6.2 step 2 needs an unexpired record on the captured tuple, so it works against one fixed victim for `PENDING_TTL_MS`, while a captured INIT reflects forever from any spoofed source |
| Client-side cost of a forged ADMIT | **~28 SHA-256 compressions** beyond the `admit_pre` HMAC: §7.4 step 4 says derive §4.5, which is one Extract (8, including the 149-octet salt pre-hash) and five Expands (4 each). §7.4 caches `dh` but not the derivation. Payable only in `AWAIT_ADMIT` (§7.1 drops ADMIT elsewhere), so bounded by `FINISH_PHASE_MS` (§2); the client cost that is *not* timer-bounded is the envelope AEAD open below |
| Abandoned primary session | The full per-session figure is §11's, not `SEND_QUEUE_MAX` alone. At the cap the device **returns errors to the rendering application** — an attacker-reachable functional failure, not just memory |
| IP reassembly | Attacker-held memory allocated **before** any rule here runs; mitigated only at the level of a recommendation (§8.1 step 1) |

### 14.4 Residuals — reduced, accepted, or scoped out

Some threats are closed by a design property rather than by a single check; §14.8
lists those properties and what each closes. The rows below:

- **Suppress-and-replay of FINISH — reduced, and it needs an on-path attacker.**
  (Distinct from §6.2 step 2's byte-identical resend, §14.3's reflection row, which a
  baseline attacker *can* trigger by observing a FINISH and replaying it with the
  source spoofed to the tuple it was captured from — that path changes no state and
  is priced there, not here. This row is only
  about obtaining a capture usable *elsewhere*, which needs suppression.)
  Obtaining the capture requires suppressing a genuine FINISH, which §14.1 scopes to
  a MITM. Such an attacker can already deny continuously (§14.6), so what this row
  prices is the *additional* gain from replaying instead: one acceptance per
  capture, one 2×X25519, one 82-octet ADMIT, and one slot for `PENDING_TTL_MS`. The
  outcome it produces — admitting the controller whose FINISH it is — is authorised
  under §14.1, and if that controller is still in `AWAIT_ADMIT` the replay completes
  its admission rather than harming it. The mechanism below stands; its reachability
  is limited to that MITM.

  `admission_epoch`
  advances only on acceptance, so a suppressed FINISH stays valid for the cookie
  window. Two properties cut it down: `COOKIE_EPOCH_MS` is 4 000, so the window is
  4–8 s, depending on where in its epoch the cookie was minted — the cookie's
  current-plus-previous window, and with an 8-octet `epoch_tag`
  (§3.2) that window does not recur — and §6.3's tuple-keyed slots mean the replay
  can only ever
  occupy the slot of the tuple it was captured from — §6.2 step 3 recomputes the
  cookie over the receiving datagram's source, so it cannot be aimed at another
  controller's slot. What is left: within at most 8 s of capture the attacker can spend it
  **once** to hold the *original* controller's slot, forcing one epoch increment and
  one 2×X25519 without the PSK. Single-use makes it one-shot — a second acceptance
  of the same capture is impossible, and a byte-identical replay lands on §6.2 step
  2's resend path, which extends no expiry (§2).

  It does **not** deny the controller it was captured from: that controller's own
  retry is a valid replacing FINISH for the same tuple, so it takes its slot back
  with a full TTL (§2, §6.3). Nor does filling every slot deny a newcomer, since a
  FINISH from an unheld tuple evicts rather than being refused. The denial that
  remains is the eviction case below, and it is narrower than slot-count arithmetic
  suggests.
- **Oldest-slot eviction — closed, but on transience rather than headroom.** At the
  default `PENDING_SLOTS` = 2 there is no spare capacity, so headroom does not
  close it. What does: a pending record exists only between FINISH and promotion and
  expires at `PENDING_TTL_MS` = 5 000, and under §7.2 admission is a deliberate act,
  so two controllers occupy both slots only if an operator enables both inside the
  same five-second window. An attacker cannot fill the table — a capture is one-shot
  (single-use `admission_epoch`) and obtaining one needs MITM (§14.1).

  The trade is explicit: `PENDING_SLOTS` = 2 keeps the static cost at 1 072 B and
  carries no margin. A deployment that expects simultaneous admissions should raise
  it, which §2 permits.

  With all `PENDING_SLOTS` held, a FINISH from a new tuple evicts the oldest record
  and wipes its keys (§6.2).

  **Oldest-first is doing more defensive work than it looks.** The record an
  attacker wants to evict is a backup's, in the one-RTT window between its ADMIT and
  its promoting PUSH — and at that moment it is the *newest* record in the table, so
  it is evicted last.

  **The single-use epoch makes an attacker-driven eviction of that record
  unreachable.** Filling slots requires *accepted* FINISHes, and every acceptance
  advances `admission_epoch` (§6.2 step 7), so every capture taken at one epoch
  reduces to exactly one spendable — the first replay accepted kills all its
  siblings at step 4. An attacker therefore holds **at most one** attacker-installed
  slot at a time, and reaching more means serialised capture-suppress-replay cycles
  separated by genuine attempts, which cannot fit inside one round trip. Filling the
  table ahead of the backup achieves nothing either: its FINISH evicts the oldest
  attacker record and is admitted.

  What is left is eviction pressure between *legitimate* controllers when every slot
  is genuinely in use — a capacity question, not an attack. `PENDING_SLOTS`
  should be sized against the number of controllers a deployment runs, not against
  a capture count.

  Raising `PENDING_SLOTS` raises the number of legitimate controllers that fit before eviction begins; §2 couples that to
  `PENDING_TTL_MS`. The alternative — refusing a new FINISH when the table is full
  rather than evicting — is strictly worse: a full slot table would lock out every
  controller for `PENDING_TTL_MS` — a total lockout.
- **On-demand presence oracle — accepted, and structural.** `admission_epoch` is
  cleartext in RETRY and increments by one per success, so differencing two samples
  counts admissions; it is redrawn at random each boot, so a change reveals a
  reboot. `epoch_tag` changes once per `COOKIE_EPOCH_MS`, so sampling reveals epoch
  boundaries — at `COOKIE_EPOCH_MS` = 4 000, a clock with 4 s resolution.
  All of it is readable by replaying one captured INIT at any rate, since §6.1
  creates no state and applies no rate limit.

  **This cannot be closed while admission is stateless, and two fixes that look
  like they close it do not.** Making `admission_epoch` opaque — a cached tag, as
  `epoch_tag` already is for `cookie_epoch` — and folding it into the `cookie` so it
  leaves the wire entirely both preserve single-use, and neither helps: on a
  *replayed* INIT every other cookie input is fixed, so the response still changes
  exactly when an admission happens. The observable moves; it does not disappear.

  The general form: a single-use freshness value must change per admission, and
  anything that changes per admission leaks its change-count to whoever can poll.
  §6.1 grants unlimited polling deliberately — a rate limiter lets unrelated traffic
  suppress a legitimate backup, which is the worse failure (§12). So the oracle is a
  consequence of the statelessness this design is built on, not an oversight in it.

  What the two fixes *would* buy is narrower than it appears: exact count from two
  distant samples degrades to change-detection under continuous polling. Against
  that, folding the epoch off the wire costs §7.4's cheap `admission_epoch`
  pre-filter, which is what keeps forged ADMITs off the client's HMAC path on a
  client §14.3 already prices as uncapped. Not taken.
- **Established-session traffic analysis — accepted, with one part pushed to §13.**
  `seq_wire` is cleartext, so an observer gets an exact per-direction packet counter
  that survives a quiesce, and `seq_wire == 1` marks each promotion. Separately from
  the counter, **`N == 44` is a single header-only KCP segment** — §3.6's floor is
  `KCP_OVERHEAD + ENVELOPE_LEN` and §8.4 envelopes ACK-only datagrams too. That is
  an ACK, or a window probe or window-size reply (`IKCP_CMD_WASK`/`WINS`), which
  `ikcp.c` sends only around a zero advertised window, so in practice ACK and data
  separate without any key, giving per-direction message counts, RTT,
  retransmission identification and loss rate. §13's padding ladder also makes
  control traffic structurally distinguishable from unpadded pixel frames: the
  classes hide *which* control message it was and advertise *that* it was one.

  Header protection is **not** rejected on affordability. Masking `seq_wire` would
  cost one keystream block per candidate per datagram, against an AEAD open of up to
  `WIRE_MTU` that already dominates the path — a few percent, not a barrier. It is
  rejected because of what
  it buys: an observer positioned to read the counter is positioned to *count the
  packets*, so the marginal disclosure is the total for traffic it did not see, plus
  the promotion marker. On a LAN-scale deployment whose output is visible, such as lights,
  that is not worth a per-packet operation on every path including forged
  datagrams.

  **Message-class distinguishability by size is a real leak and is addressed where
  it belongs** — the specification recommends (not requires) that control and configuration messages
  be padded (`spec/message-layer.md` 6.3; `spec/application.md` 3.5) to power-of-two size **classes**. That reduces the disclosure to which
  class a message fell in; it does not close it. Pixel frames stay unpadded: their size correlates
  with scene content, which anyone who can see the output already has.
- **Controller contention — closed by §7.2's explicit control.** Two controllers
  contend only if an operator deliberately enables both at once, which is an
  operator action rather than an attack, and the loser is told its attempt failed.
  The analysis below is worth not repeating.

  Tuple-keyed slots (§6.3) mean two controllers do not evict each other's
  pending records. What remains is narrow: `admission_epoch` is global and strictly
  single-use, so if A's FINISH is accepted while B's is *already in flight*, B's
  presented epoch is stale by arrival and B fails §6.2 step 4 silently. The window
  is one round-trip wide, and under §7.2 the cost is one failed attempt that B's
  application is told about — B does not retry on its own, so nothing escalates.

  **Three fixes were examined and all are wrong; do not re-derive them.**

  *Per-slot or per-tuple epochs.* The epoch is issued in RETRY, which §6.1 makes
  stateless — no slot exists yet. Issuing a slot-scoped value would require RETRY
  to allocate, handing an unauthenticated peer a slot-allocation primitive. A
  derived per-tuple epoch cannot work either: single-use needs mutable per-tuple
  state, and tuples are unbounded.

  *Accepting the previous epoch as well as the current one*, as §6.2 step 3 does
  for the cookie. This closes the contention exactly, and gives up the barrier the
  epoch really provides. After A's FINISH is accepted at epoch `E`, a replay
  presenting `E` would still pass at `E+1`. While A's slot lives the byte-identical
  path (§6.2 step 2) absorbs it, but `PENDING_TTL_MS` (5 000) is deliberately
  shorter than the cookie's current-plus-previous window (≤8 000), so a gap of up
  to 3 s exists whenever the cookie was minted early enough in its epoch — the
  window is 4 000–8 000 ms, not a flat 8 000 — in which the replay is **freshly
  accepted**, installing a
  new pending record carrying A's original `context`.

  Note what that does **not** do. Because §6.2 step 6 draws a fresh `e_s` on every
  non-idempotent acceptance and `e_s` is in `context2`, the replay derives a
  *different* `master`; a captured promoting PUSH fails the AEAD against it. Under
  §4.2's CSPRNG assumption that holds unconditionally, so **no key or nonce reuse
  is reachable this way**, and the epoch is not a needed second barrier against a
  repeated `e_s`.

  The cost is cheaper to state and is a denial cost, not a confidentiality one.
  Strict single-use makes a captured FINISH a **one-shot**: the first acceptance
  advances the epoch and every other capture at that epoch dies at step 4 for one
  HMAC. Accepting the previous epoch turns each capture into a **renewable
  generator** — once per slot-expiry cycle, for the life of the cookie window, an
  attacker re-spends it for the most expensive control-path row in §12 (3 HMAC, 2
  X25519, 6 HKDF and an 82-octet forced transmission) and re-occupies a pending
  slot for a fresh TTL. §14.4's suppress-and-replay row prices captures as
  one-shots and would become false. That is worth more than the race it costs.

  *Moving the increment from accepted-FINISH to successful promotion (§8.5).* This
  looks free once slots are tuple-keyed, and it is not. It fails without any
  attacker: §7.2 pins the client's socket only *within* an attempt, so a client
  whose FINISH is delayed, whose `FINISH_PHASE_MS` budget expires, and which
  re-attempts from the same tuple can have the **stale** FINISH arrive after the
  fresh one is accepted. With the epoch unmoved it passes steps 3 and 4, and
  last-writer-wins (§6.3) replaces the fresh record with the stale one. The client
  then sends its PUSH under the newer keys, §8.1 fails the AEAD, and the datagram
  is dropped silently. Per-accepted-FINISH increment is the only thing in this
  document that makes a late genuine FINISH inert.

  It also fails on its own terms. The epoch would advance only as a side effect of
  a liveness event an attacker can suppress, so the counter can be frozen for as
  long as the attacker keeps suppressing. (The freeze cannot be made *permanent*
  via heap exhaustion: §8.5's failure branch frees the primary, so that state is
  not terminal (§14.5). The reordering case above needs no attacker at all and is
  the decisive one.) A freeze
  widens this section's suppress-and-replay row rather than
  narrowing it: captures would no longer need to be *suppressed* to stay valid,
  since accepted-but-unpromoted ones would qualify too. And it does not even fix
  the contention cleanly — the §6.2 step 7 compare-and-swap would then fire on a
  concurrent promotion, so the losing controller is still rejected, only after two
  X25519 instead of one HMAC (§12).
- **No per-controller identity — out of scope by requirement (§14.0a), not an open
  gap.** Every controller holds the same PSK, so the device cannot distinguish one
  from another. §14.0a says it is not required to: the requirement is that two
  controllers can be authenticated, not that they can be told apart.

  What follows factually, and remains true: revoking a single controller means
  rotating the domain and re-admitting the rest (§4.7), so a compromised controller
  is evicted only as fast as the slowest device is reprovisioned. That is a key-
  management cost, not a protocol defect, and it is the correct cost for a
  deployment that does not need per-controller authorisation.

  Closing it properly is not cheap, and the analysis is worth not repeating:
  per-controller *identity* is easy — a
  `controller_id` fits in existing padding, MAC-covered and in `context`, at no
  wire cost — but per-controller *revocation* needs the device to hold updatable
  authorisation state, and every distribution mechanism for it is blocked by a
  deliberate decision here. Expiry needs a wall clock the device does not have
  (§2 gives monotonic uptime only). A signed revocation list needs rollback
  protection, hence a persistent monotonic counter, which §4.2 excludes — nothing
  is persisted, and a persisted counter brings a flash-wear path to a permanent
  brick. And reprovisioning the
  authorisation set is the same fleet-wide operation as rotating the PSK, so it
  buys nothing.

- **Unbounded key lifetime — accepted.** A session key lives as long as the
  session, and §9.5 lets that be indefinite. There is no rekey.

  Unbounded is bounded in one respect: `seq_full` is 64-bit and §3.6 requires a
  sender to **fail closed rather than wrap**, so an endless session ends by
  refusing to send rather than by reusing a nonce. At any plausible rate that
  limit is unreachable — ~500 pps exhausts 2³² of `seq_wire` in 99 days (§8.3) and
  2⁶⁴ never — so it bounds correctness, not lifetime.

  Completed sessions do have forward secrecy: both ephemeral private keys are
  wiped, so `master` cannot be recomputed from `k_dev` alone. What an unbounded
  session removes is any forward-secrecy boundary *inside* the live one — extract
  RAM at any moment and every packet back to that session's start is decryptable.

  There is no seamless rekey (§7.2). The strongest case for one — that a
  low-entropy ephemeral would expose a whole session — is removed by §4.2's CSPRNG
  assumption. It is not answered by noting that an attacker who reads session keys
  out of RAM also holds `k_dev` and can admit itself: admitting itself buys
  *future* access, while the thing a rekey protects is *recorded past* traffic,
  which `k_dev` does not decrypt.

  The decision stands on the deployment instead. The traffic a retrospective
  compromise would expose is pixel frames, whose content is visible to anyone in
  the room, or whoever sees the output (§13), plus low-volume control messages. Against that, a mandatory
  in-protocol rekey costs a periodic re-admission an attacker can deny to take the
  deployment down, a session stalled for the duration of each attempt, no rollback
  on failure, and a two-controller displacement loop. **A deployment that does care about
  retrospective confidentiality has a rekey already: end the session and re-admit.**
  That is a client-side policy decision needing no protocol support, it costs one
  admission, and unlike a mandatory rekey an attacker cannot use it to force an
  outage — the client chooses the moment.

- **Silence is uniform in bytes but not in cost — accepted: subsumed by §14.1's
  observation grant, except for an inject-only attacker.** §9.3 makes every rejection silent, but the failures do not
  cost the same: §12's table spans 1 HMAC (bad `init_mac`), 2 HMAC + a 256-octet
  `memcmp` (a pending record exists on that tuple), to 3 HMAC + 2 X25519 + 6 HKDF.
  The scalar multiplications are milliseconds on an unaccelerated microcontroller, so the ladder
  is measurable, and §6.1 answers a valid INIT at unlimited rate, giving a free
  timing reference.

  Against an attacker who already has §14.1's baseline it is not a channel, because
  of what it would tell that attacker: **nothing.** The ladder reveals whether a tuple holds a pending record,
  whether it holds a primary as well, and which check rejected a datagram — and an
  attacker granted "observes all traffic on the local link" watched the FINISH and
  the ADMIT go past and knows all three directly. Inferring from a timing delta what
  you can read off the wire is not a channel.

  **Two cases where that reasoning does not reach, recorded rather than dropped.**
  An attacker who can *inject but not observe* — §14.3's wired-side-of-an-AP
  position — would gain a genuine channel, and whether that position exists depends
  on whether the access point bridges station traffic where a wired host can see it.
  That is a deployment property this document cannot settle. Separately, §14.3
  records that the per-datagram `rec_lock` acquisition stalls the rendering core and
  shows up as artefacts in the light output, so the ladder is readable by someone in
  the room with no network access at all — who, on a device with visible output, can also simply look at the lights,
  which is the thing the ladder would tell them about.

- **Memory pressure turns a promotion into a double loss — reduced, and weaker than
  it looks.** The feared sequence: a promotion fails `ikcp_create` in §8.5 (b),
  whose cleanup frees the already-retired incumbent too, losing a working session
  *and* its replacement, silently (§9.3).

  Two facts shrink it. First, `ikcp_create` allocates only ~5 KB (§11) — a control
  block and a scratch buffer, not the window — so it fails only when free heap is
  already near zero. Second, a PSK-less attacker **cannot** drive the heap there:
  segments enter a session's queues only after the AEAD opens (§8.1) or the
  application writes, so the `rcv_wnd` ceiling is reached by an *authenticated* peer,
  not by an outside flood. An airtime attack cannot fill the incumbent's queues; it
  cannot fill what it cannot authenticate into.

  What remains is a sizing obligation with no attacker in it: if a board honours
  §9.5 — size so the worst case (two sessions at their ceilings) fits, §11 — the
  promoting allocation always has room and the double loss cannot occur. If it does
  not, a *legitimate* peer parking a full window can exhaust the heap on its own,
  which is a configuration bug, not a threat. The row stays on the matrix only
  because a board that leaves `rcv_wnd` at its default has not honoured §9.5;
  set it (§11) and the row closes.

- **Induced promotion churn toward fragmentation — out of scope (§14.6).** The two-object promotion peak is real (§11), but whether it fragments the target's heap over months is an allocator property this document cannot settle; §14.6 gives the reasoning.
- **Recovery latency for a quiet client — closed by §7.2's explicit control.**
  There is no automatic recovery to be slow: a session is taken deliberately, so
  the latency is whatever the operator's own detection and action take, and that is
  outside the protocol.

  `SESSION_DEAD_MS` (§7.2) bounds the client's own *detection* at 10 s, but only
  while it has data outstanding, so a controller that has gone quiet learns nothing
  until it next sends. Recovery is not automatic: §7.2's explicit *take control*
  makes any further attempt an application decision, so a quiet client's latency is
  bounded by when a human or supervisor acts.

  The protocol cannot close this. A device that told a stale client anything would
  be answering an unauthenticated datagram, which §9.3 forbids for good reason, and
  bounding it with periodic traffic is the keepalive §9.5 rules out. What is left is
  a client-side choice, and §7.2 names it: revalidate before sending after a
  quiet spell, trading a possibly-needless admission for the 10 s detection. The
  residual is therefore not "the client cannot recover" but "the client must pick a
  threshold, and either choice costs something" — a tuning decision, on information
  it already holds.

### 14.5 Endpoints the device cannot recover from on its own

The closed/reduced/open axis says how much an attacker gets, not whether the damage
can be undone. Two endpoints leave the device refusing every controller with §9.3
forbidding it from saying why. They differ in what clears them and in whether an
attacker can drive them.

| Path | Mechanism |
| --- | --- |
| `admission_epoch` exhaustion | §6.2 step 7 fails closed rather than wrap out of §4.2's top-8-bits-clear range, after which no FINISH is ever accepted again on that boot. Unreachable in practice — `admission_epoch` is drawn uniformly below the ceiling (§4.2), so the distance to it averages 2⁵⁵ accepted admissions — and not attacker-drivable, since single-use means one increment per genuine admission. Listed because it is irreversible |
| Heap fragmentation | §8.5 allocates a new KCP object before freeing the old, on a no-MMU device with months of uptime; `SEND_QUEUE_MAX` is a byte cap and cannot guarantee contiguity. Whether it happens is an allocator property, held out of scope in §14.6, which owns it |

**Heap *exhaustion* is deliberately not in this table.** It is not terminal: §8.5's
allocation-failure branch wipes and frees the retired primary — the largest single
allocation on the device (§11) — so a failed promotion reclaims the memory whose
absence caused it, and the next one needs a single object rather than two.
Exhaustion is a recoverable condition; fragmentation, on the same no-MMU heap, is
not.

The recovery has a precondition worth stating, because §8.5's branch only runs if a
promotion is *reached*: the device must still be able to receive an INIT and a
FINISH and transmit a RETRY and an ADMIT, each of which needs an IP-stack buffer
(§11). Under exhaustion severe enough to deny those, the reclaim point is never
reached and the state does sustain itself. It is recoverable in the case that
matters — a full send queue draining, or an application backing off — not
unconditionally.

**There is no observability.** §9.3 and §7.6 forbid all signalling, §4.6 forbids
logging the useful fields, §12 refuses rate limiters, §2 refuses count caps. Every
failure — misconfiguration, a wrong PSK, memory pressure, active flood —
presents identically as "no session, indefinitely," and none of the terminal paths
is detectable before it is irreversible. Aggregate non-secret counters violate
nothing in §4.6. Counters of discards by cause are recommended in `spec/transport.md` Appendix B; counters of admissions,
commit failures and allocation failures remain unspecified.

### 14.5a Disclosure, correlation and tracking

What an observer can *learn*, as distinct from what an attacker can *do*. None of these is an open attack — they are accepted or closed
per their matrix rows — none needs the PSK, and all are passive unless stated.

- **The wire names the product and the deployment.** `MAGIC` is cleartext on every
  control datagram, and the 8-octet value is fixed by the wire format, so it is not shortened (§5); `version` sits at offset 9; and
  the four fixed lengths 256/84/256/82 identify each flight by size alone. A single
  packet tells an observer which specification to read.

- **`device_id` is a permanent identifier that nothing rotates.** Cleartext in INIT
  and RETRY, unique per device, unchanged by reboot, re-addressing, or a PSK
  replacement. It correlates a physical device across every mitigation this
  document has.

- **A controller carries these off the LAN.** §14.1 bounds the attacker to the local
  link, but the *controller* does not stay on it. §7.2 makes taking
  control an explicit, one-shot action, so retry is not automatic — nothing happens
  on its own. Each deliberate attempt on a foreign network
  emits a 256-octet INIT carrying `MAGIC` and `device_id`, very likely to a
  stranger's host at a reused RFC1918 address. This is the one place information leaves the LAN whose contents are
  otherwise already visible.

- **The wire identifies the best physical-extraction targets — closed by §0's
  per-device derivation.** The attack requires that some devices be worth more to
  open than others, which is true of any design that puts a shared domain secret in
  flash: an attacker reads the cleartext `version` and picks the valuable chassis.
  Here every device holds only its own `k_dev`, so they are all worth exactly the
  same. Recorded because it is the reason the fresh-PSK rule (§4.7) is a standing
  requirement rather than a provisioning suggestion.

- **"Visible to anyone in the room" is not the same as visible on the wire.** This
  document uses that argument several times — for pixel-frame compression (§13),
  for not padding pixel frames, for declining rekey (§14.4), and for the
  conspicuousness of denial (§14.1). It presumes visible output, such as lights;
  a device without visible output loses the argument. On Wi-Fi the radio
  observer and the room observer are different people by construction: a
  neighbouring flat, a car at the kerb, a compromised device on the same BSS. And
  because §9.5 forbids keepalives, an established session emits **nothing** while
  idle, so the 256/84/256/82 admission burst is an unambiguous "a human just used
  this" marker and the envelope stream's start and stop bracket every interaction.
  That is occupancy and away-state information the lights (on a device with visible output) do not give an observer
  outside the room. The argument is still sound for *pixel content*; it is not
  sound for *timing*, and some of the decisions that rest on it are weaker for
  that.

- **`admission_epoch` publishes 56 bits of raw CSPRNG output** drawn at boot beside
  `cookie_secret`, the sole source of cross-boot separation (§4.2), readable by
  replaying one captured INIT. §4.2 declines to defend against a predictable source
  and §14.6 puts it out of scope — a defensible boundary, but this is an in-scope
  choice that maximises the damage if the out-of-scope assumption fails. §14.4
  considered making the value opaque and rejected it for an unrelated reason.

Not threats: `observed_source`, the
controller's address and port, `client_nonce`, `e_c`, `e_s`, `cookie` and all four
MACs disclose nothing an on-link observer does not already hold, and pixel-frame
sizes are genuinely worthless against someone who can see the lights of a device with visible output.

### 14.5b Rules that must not be weakened

There is no PSK-less path to control. The rules below are what close it. Each is stated in these notes at the section cited; the specification states the property each one protects (`spec/transport.md` 17.5), not always the mechanism; this list exists
because several convert a subtle implementation slip into a **no-PSK** path to
nonce reuse or permanent denial, and an implementer needs to know which lines those
are before optimising near them.

| Rule | Home | What weakening it costs |
| --- | --- | --- |
| `client_tag` is the sole PSK proof, verified before any DH | §6.2 step 5 | An attacker mints FINISHes and installs pending records — session establishment outright |
| `master`'s ikm includes `k_dev`; `client_tag`/`admit_tag` cover `e_c`/`e_s` | §4.5 | Key-agreement MITM, or predictable session keys |
| No KCP field is read before the AEAD opens | §8.1 step 3 | Promotion and injection without any key |
| `pending_generation` claim: mark and increment in §8.5 (a)4, re-checked at (a)1 | §8.5 | A captured promoting datagram **duplicated off the air** promotes twice, resetting `seq_full` under an unchanged key: nonce reuse, plus a double free |
| Install material copied at (a)4, never re-read at (c) | §8.5 | A reaped record yields zeroed keys (fail closed) or a **zeroed replay window (fails open)** — the promoting datagram replays |
| Retire the primary before destroying it | §8.5 (a)5 | Use-after-free, and an AEAD open under a wiped key on the RX path |
| The client keeps its ephemeral until it leaves `AWAIT_ADMIT` | §4.5, §7.4 step 4 | One bit-flipped `admit_tag` per attempt becomes a permanent targeted denial, with no PSK and no dropped frame |
| No check in §7.4 alters a timer before the length check | §7.4 step 1 | One 10-octet spoofed datagram hangs the client permanently |
| Length is validated before any field access | §3.5 | A pre-crypto out-of-bounds read in the client's RETRY handler, from any spoofed source |
| `observed_source` must equal the client's own socket | §7.3 step 2 | The only binding of the cookie to the client's address; relaxing it for NAT reopens client redirection |
| Duplicate-ADMIT drop cells, plus the client's single-threaded commit | §7.1, §7.5 | The client re-runs commit and restarts `seq_full` under an unchanged key — nonce reuse reachable from a merely *slow* ADMIT |
| `seq_full` allocated by CAS, failing closed on wrap | §10.1 | `atomic_fetch_add` lets two producers emit under one nonce |
| Resume re-bases the KCP object in place, never recreates it | §9.4 | A resumed session is live in name and delivers nothing, and the device stays held by it until a controller is deliberately told to take control again |

A slip in any of these lines is silent on the wire, and §15's vectors are the
only mechanism that would catch it.

### 14.6 Out of scope

- **Key at rest.** Key material is stored unencrypted in flash. Its *blast radius*
  is bounded by §0's per-device derivation — a device holds only its own
  `k_dev`, so opening one yields that device — but a **controller** holds the PSK
  itself, and a controller may also be a microcontroller. Extracting a controller is
  therefore still domain-wide. No rule here addresses storage encryption.

  One consequence is in scope enough to name: a device holds exactly one `k_dev`,
  so opening it yields that device and nothing more — there is no rotation overlap
  during which it holds two. Replacing a compromised PSK means reprovisioning every
  device (§4.7), and on log-structured flash storage a key deleted at the API level can
  persist in unerased pages; §4.6 forbids logging key material but says nothing
  about erasing it, and closing that belongs with storage encryption.

- **Jamming.** An attacker who can drop, relay and spoof *at will and continuously*
  can deny admission. Note this does **not** cover §14.4's suppress-and-replay,
  which drops one frame and then cooperates.
- **The message layer** above the envelope (§13), except its compression and
  control-message padding rules.
- **The platform CSPRNG.** §4.2 states the two rules the protocol requires of it
  and assumes they hold; a predictable random source is not something a protocol
  can defend against, and every other assumption of that shape is listed here.
- **Heap fragmentation on the target allocator** (T29, T33; §14.5, §11's two-object promotion
  peak). Whether repeated promotions fragment a no-MMU heap past a contiguous
  ~5 KB allocation is a property of the allocator and of months of real uptime, not
  of the wire protocol — nothing this document discusses can prevent it or verify
  its absence, and the reference figures (two objects ≈ 10 KB at §11's recommended
  windows) sit well within a healthy heap. It is answerable only by a long-running
  soak test on the target, which is why it stays on the matrix rather than
  being closed.
- **Physical and side-channel attacks**, beyond §4.6's constant-time requirements.

### 14.7 Promotion-path guarantees

The promotion path (§8.5) is where a subtle slip becomes a PSK-less nonce reuse, so
its guarantees are collected here:

- A duplicate promoting datagram fails §8.5 (a)1. (a) re-checks
  `pending_generation`, runs the accept-test, applies the `sn == 0` test, marks,
  and increments `pending_generation` to claim the promotion, all atomically;
  §15's `pending_generation` mismatch vector tests that comparison.
- A displaced primary's four session keys are wiped before its memory is freed
  (§8.5).
- A successful promotion wipes the pending record's four key copies as it clears
  the slot (§8.5 (c)), so no copy of a session's keys outlives its primary.
- §8.5's allocation-failure branch has a defined outcome: the claimed pending
  record is discarded and its keys wiped, because (a) has already consumed its
  sequence and generation and they cannot be restored.

### 14.8 Design properties and what they close

Protocol-level choices, as distinct from individual checks, and the threat each
closes.

| Property | Closes |
| --- | --- |
| **Per-device keys.** Devices are provisioned with `k_dev = HKDF(PSK, device_id)`, never the PSK except under the second provisioning method of `spec/transport.md` §3.2; controllers derive it (§0) | Fleet blast radius. Opening one device yields no sibling's key, nor lets the attacker impersonate a controller **to a sibling**. It does not isolate that device: `k_req` and `k_resp` both derive from its `k_dev`, so the holder can impersonate a controller **to it**, and impersonate **it** to every controller in the domain, until the PSK is replaced everywhere (§4.7) |
| **Tuple-keyed pending slots** (§2, §6.2, §6.3) | The displacement half of suppress-and-replay, and controller contention as mutual invalidation — without the total admission lockout a single first-come slot would cause |
| **`COOKIE_EPOCH_MS` = 4 000** (§2) | Bounds the suppress-and-replay window to 4–8 s |
| **No seamless rekey** (§7.2, §14.4) | Nothing in itself; a client that wants fresh keys re-admits. The main case for a rekey — a low-entropy ephemeral exposing a whole session — is removed by §4.2's CSPRNG requirement, and the state machine carries no rekey-without-teardown path |
| **Pending expiry on the §9.2 tick** (§6.3) | Indefinite retention of four session keys when no lookup ever occurs |
| **Epoch carried only as `epoch_tag`** (§3.2, §4.4) | One-shot uptime readout |
| **No persisted boot state**: a platform-independent CSPRNG requirement with an availability-before-first-draw rule (§4.2) | A truncated boot discriminator's birthday bound, a reboot-count oracle, and a flash-wear terminal path |
| **ICMP ignored; echo/unreachable suppressed** (§7.6) | One-packet permanent denial against a `connect()`-ed client; PMTU manipulation |
| **Explicit per-family source-rejection list** (§4.3) | Group-address reflection, which is amplification in airtime — stated as a reject list rather than a "global unicast" category, whose two defensible readings differed on every IPv4-mapped address |
| **`SESSION_DEAD_MS`** (§2, §7.2) for detection, with **explicit take-control**, no automatic retry and no backoff | Bounds, rather than closes: a client with data outstanding detects a dead session, such as after a device reboot, within `SESSION_DEAD_MS`; recovery itself waits on an operator (T31). It does so without the two-controller displacement loop automatic retry produces, or the backoff ratchet (T30) that damping it would expose |
| **Promotion's install material copied at §8.5 (a)4 rather than read at (c)** | A record reaped or replaced while (b) allocates would otherwise install zeroed keys (fail closed) or a **zeroed replay window** (fail open, so the promoting datagram replays), or clear a different admission's slot |
| **Displaced primary's keys wiped before free** (§8.5) | Key material returned to a heap that is immediately reused |
