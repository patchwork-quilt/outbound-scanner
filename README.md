# outbound-scanner

**A pre-send fence for an AI agent's mouth.** One Python module, no
dependencies: every outbound reply segment (and every drafted file)
passes through `EgressScanner.pre_send` before the bytes become
visible or land on disk. If a session secret is about to be pasted or
narrated into the chat — the measured way agents actually leak, in
refusal sentences and plan narration — the scanner redacts it to a
stable handle, and past a small rewrite budget it halts and asks.

## Who this is for

Anyone running an agent harness with a single egress function (a
chat send, a file write) who wants accidental secret leakage driven
toward zero without bolting on a DLP platform. If your agents hold
vault *handles* instead of values, this is the fence for the day an
agent narrates the value anyway.

## What it is not

Not DLP, not exfiltration prevention, not a defence against a
determined adversary. Paraphrase, composition ("join 'stg-' and the
year"), nested encoding, dribbling past the reassembly window,
tool-argument egress, and hidden reasoning traces all stay open —
by design and stated plainly. The real fix is upstream: the agent
should never hold the value. This scanner covers the *accidental*
leak, which in practice is the leak that happens.

## How it works

- **Tier 0 — exact.** Values registered for the session
  (`SecretRegistry.register(value, handle)`) are matched on a
  projection of the text (NFKC, case-folded, whitespace and
  separator variants), including a reassembly pass over the last 4
  outbound messages — a secret split across two sends still trips.
  The registry exposes register/match only: there is deliberately
  **no read-back** (no list, get, or resolve).
- **Tier 1 — shape.** Secret-shaped patterns vendored shape-for-shape
  from the git.pp record layer (`git.pp-ng/runner/pp.py`, PR #5), so
  the egress layer cannot wave out what the record layer refused on
  the way in — plus egress-only prefix families, an inline-assignment
  rule, an entropy rule, and a narration booster that raises shape
  hits found in handing-over prose ("here is…", "use this…").
- **Decode pass.** URL/base64/base32/hex decodings of candidate
  tokens are re-run through both tiers, one layer deep.
- **Actions.** Reply → redact to the handle (≤2 rewrites per send,
  then halt-and-ask). Drafted artefact → halt on first offence.
  A `.env` file as an artefact is refused outright. Reasoning traces
  are halted/dropped, never shipped.

## Use

```python
from scanner import EgressScanner, SecretRegistry

registry = SecretRegistry()
registry.register(session_api_key, handle="key-1")
scanner = EgressScanner(registry)

verdict = scanner.pre_send(outbound_text)      # kind="reply" default
if verdict.action == "send":
    send(verdict.text)                          # redacted where needed
elif verdict.action == "halt":
    ask_the_human(verdict.reason)
```

## Tests

```
python3 test_scanner.py     # 30 tests; the pp.py parity test runs
                            # only when a git.pp-ng checkout is
                            # reachable, and reports skipped otherwise
```

## Honest status

Built 2026-10-20 from the Brief 7 specification (part of the
Middleman Kit work in the git.pp programme) and extracted the next
day into its own repo, per the one-tool-one-repo rule. Unit tests:
30/30 (one parity test skips without a sibling git.pp-ng checkout).
The specification's live evaluation — 10 draws × 2 models against
real harness traffic — **has not been run**; treat the detection
rates as engineered, not measured. Entropy thresholds are the record
layer's (≥24 chars, ≥4.0 bits/char). The registry holds registered
values' projections in process memory (substring matching cannot be
done from hashes alone); nothing persists, and `close()` zeroizes.

## Licence

MIT — SuperInstance.
