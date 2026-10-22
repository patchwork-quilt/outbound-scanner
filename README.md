# outbound-scanner

**One Python module that checks everything your AI agent is about to
send — and stops session secrets from leaking into the chat.**

For: anyone running an agent harness with a single send function who
wants the accidental leak — an agent pasting or narrating a secret in
prose — caught before it ships. Not for: stopping a determined
adversary, or acting as a DLP platform (see *Limits*, below — they
are stated early on purpose).

## Run it in thirty seconds

Stdlib only, Python 3.10+. Save this next to `scanner.py` and run it:

```python
from scanner import EgressScanner, SecretRegistry

registry = SecretRegistry()
registry.register("stg-db", "Tr0pic@lBreeze#4821")  # the harness registers; the agent never does
scanner = EgressScanner(registry)

leak = scanner.pre_send("deploy is green; the staging password is Tr0pic@lBreeze#4821, rotate it later")
clean = scanner.pre_send("deploy is green; rotating the staging password tonight")
print(leak.action, "|", leak.sanitized)
print(clean.action, "|", clean.sanitized)
```

Output (the handle's `#` suffix is a per-session fingerprint fragment
— yours will differ; the shape won't):

```
rewrite | deploy is green; the staging password is <secret stg-db#1937>, rotate it later
allow | deploy is green; rotating the staging password tonight
```

What just happened: the harness registered one secret value under the
id `stg-db`. When the outbound text contained that value, `pre_send`
returned a `rewrite` decision whose `sanitized` text has the value
replaced by a stable handle — the sentence stays grammatical, and
the agent can refer to the secret by handle for the rest of the
session. The clean message came back `allow`, byte-identical.

## The model (five minutes)

Four concepts, in the order they compose:

1. **Registry** — the session's known secrets, registered by the
   harness (on the human's paste gesture), never by the agent.
   `SecretRegistry.register(secret_id, value)`.
2. **Projection** — before matching, text is normalised (NFKC,
   case-folded, whitespace removed, plus a separators-stripped
   variant). Matching runs on the projection, not the raw string.
3. **Two tiers of detection** — *Tier 0 (exact)* matches registered
   values on the projection, including across a reassembly window of
   recent sends. *Tier 1 (shape)* matches secret-*shaped* text —
   known prefix families, inline assignments, high-entropy tokens —
   whether or not it was registered. A decode pass (URL, base64,
   base32, hex — one layer) re-runs both tiers on decoded candidates.
4. **Decision** — `pre_send` returns one of three actions:
   `allow` (send as-is), `rewrite` (send `decision.sanitized`
   instead), or `halt` (stop and ask the human). Findings and the
   machine-readable `reason` never contain a secret value.

```
harness ──register──▶ SecretRegistry ──┐
                                       ▼
outbound text ──▶ projection ──▶ Tier 0 exact ──┐
                              └─▶ Tier 1 shape ─┴─▶ decode pass ──▶ Decision
                                                                        allow / rewrite / halt
```

### Usage beyond the toy

```python
scanner = EgressScanner(registry, max_regenerations=2,
                        reassembly_window=4, window_chars=2000)

d = scanner.pre_send(text)                                  # channel="reply" (default)
d = scanner.pre_send(file_text, channel="artefact", filename="config.py")
d = scanner.pre_send(trace_text, channel="trace")
```

- **Channels change the failure behaviour.** *Reply:* a certain or
  high-confidence hit rewrites to the sanitized text; after
  `max_regenerations` (default 2) spent rewrites on a chain, it
  halts and asks. The harness owns the retry turn; the scanner owns
  the count, so the cap can't be argued with. *Artefact:* the first
  offence halts — a redacted config file is a silently broken config
  file. An artefact whose filename is `.env` (or `.env.*`) is
  refused outright. *Trace:* a hit drops the trace before it is
  persisted; traces are never rendered.
- **Decision fields.** `action`, `sanitized` (equals the input on
  `allow`), `findings` (rule ids, spans, confidence — value-free),
  `reason` (a small dict, also value-free), `attempts`.
- **Session hygiene.** One scanner instance per session (it holds
  the reassembly window and the rewrite counter). Call
  `registry.close()` at session end: it zeroizes the matching
  material and matching stops (pinned by
  `test_close_zeroizes_and_matching_stops`).

## Limits — what this does not do

Not DLP, not exfiltration prevention, not provider-side retention
control. These stay open, by design and stated plainly:

- **Paraphrase and composition** — "join 'stg-' and the year" is not
  a matchable value, and reassembly only catches fragments that are
  literal pieces of one.
- **Dribbling past the window** — a secret split across more than
  `reassembly_window` messages (default 4) is a *pinned miss* in the
  test suite, not a surprise (see below).
- **Nested encoding** — the decode pass is one layer deep.
- **Other channels** — tool arguments, shell commands, and anything
  that doesn't pass through the harness's egress hook are out of
  scope. So is a hidden reasoning trace that never reaches
  `pre_send`.
- **Intent.** This drives *accidental* exfiltration toward zero and
  leaves intentional exfiltration untouched. The real fix is
  upstream: the agent should hold a vault handle, never the value.
  This scanner is the fence for the day an agent narrates the value
  anyway.

## The deep layer

Four design decisions carry the weight; each has its receipt in
`test_scanner.py`.

**There is no read-back primitive.** The registry's public surface
is `register()`, `match_text()`, `handle_for()`, `close()` — no
list, get, or resolve. That is deliberate: a matcher the model can
query is a guessing oracle, so the API simply doesn't grow the verb.
Identity records are salted SHA-256 fingerprints —
`SHA-256(value ‖ per-session salt)` plus non-reversible metadata
(length class, charset class, prefix class) — so the thing that
could be copied or logged carries no plaintext. The honest cost,
also in the module docstring: substring matching on a projection
cannot be done from hashes alone, so registered values' projections
are held in process memory for matching (never logged, never on
disk, zeroized by `close()`). What the fingerprint buys is that the
*identity record* has no read-back path; it does not pretend the
matching material isn't in memory.

**Matching is projection-based, not substring.** NFKC + case-fold
means full-width characters and SHOUTED case fold onto the same
projection; the separators-stripped variant means
`Tr0pic-@l-Br-eeze#4821`, `Tr0pic.@l.Breeze.#4821`, backtick-wrapped
and newline-split spellings all hit the same registered value. An
index map from projected positions back to raw offsets is what makes
the redaction land on the exact span. Receipts:
`test_separator_evasion_hyphens_and_dots`, `test_case_evasion`,
`test_fullwidth_evasion_nfkc`.

**Split secrets are caught by a reassembly window — and the
window's edge is a pinned miss.** The scanner keeps the last
`reassembly_window − 1` sends (≤ `window_chars`, default 2000) and
matches the concatenation too: a fragment alone is allowed, the
completing fragment halts (`test_split_across_two_messages_halts`,
`test_split_across_four_messages_halts`). Split across *five*
messages, it misses — and that miss is pinned in the suite on
purpose. Every expected outcome in the suite — catches, passes, and
known misses — is fixed in the file, so a change that fixes *or*
worsens a pinned miss shows up as a diff, not as a surprise.

**Tier 1 cannot drift from the record layer.** The shape patterns
are vendored shape-for-shape from `runner/pp.py` in
[git.pp-ng](https://github.com/patchwork-quilt/git.pp-ng) (its PR
#5 module): the six secret shapes, the inline-assignment rule, the
key-name rule, and the placeholder set, byte-identical in regex and
name. The point is parity between doors — the egress layer must not
wave out what the record layer refused on the way in.
`PpPatternParityTests` asserts byte-identity against a live `pp.py`
when a git.pp-ng checkout is reachable, and reports *skipped* (not
passed) when it isn't. Egress adds its own prefix families and a
narration booster ("here is", "use this", …) that raises shape hits
found in handing-over prose, because that prose is the measured leak
shape. Entropy rule: the record layer's thresholds, ≥24 chars and
≥4.0 bits/char.

**The rewrite never sees the original.** On a hit, the harness is
handed the *sanitized* text and a value-free reason — so the
regeneration turn can't re-leak what it can't see, and the tests
assert the registered secret appears in neither `repr(findings)`
nor `repr(reason)`. Only Tier 0 (exact) is allowed to hard-halt a
reply chain; Tier 1 is shape, never certain, and is treated that
way.

## Status and verification

Built 2026-10-20 from the Brief 7 specification — the egress-fence
piece of the Middleman Kit work in the git.pp programme — and
extracted into its own repo the next day, per the one-tool-one-repo
rule.

```
python3 test_scanner.py
# Ran 30 tests … OK
# (the pp.py parity test runs when a git.pp-ng checkout is
#  reachable, and reports skipped — not passed — otherwise)
```

**Not yet measured:** the specification's live evaluation — 10
draws × 2 models against real harness traffic — has not been run.
Detection rates are therefore engineered and unit-tested, not
measured on live traffic. Treat them that way.

## The shelf

One tool, one repo — the family this lives in:

- [git.pp-ng](https://github.com/patchwork-quilt/git.pp-ng) — the
  git.pp spec and record layer; where Tier 1's shapes come from,
  and the system whose ingress this scanner's egress mirrors.
- The **Middleman Kit** — the kit that lets a human's own agent work
  with the git.pp system instead of being replaced by it; this
  scanner is its Brief 7 component, usable entirely on its own.
- [gitpp-action](https://github.com/patchwork-quilt/gitpp-action)
  — the git.pp fold as a GitHub Action, for when you want derived
  state as a check in CI rather than a fence on a chat.
- [gitpp-app](https://github.com/patchwork-quilt/gitpp-app) — the
  git.pp GitHub App; the hosted sibling, when a repo should carry
  the state natively.

## Licence

MIT — SuperInstance.
