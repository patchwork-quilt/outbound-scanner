"""Outbound scanner — a pre-send hook for a chat harness's single egress
function. Brief 7 ("sealed reply"), implemented as specified in
research/minimax/2026-10-12-brief7-outbound-scanner.md.

WHAT THIS IS
    A fence on the chat egress channel, placed where the harness sends:
    every outbound reply segment (and every drafted artefact) passes through
    `EgressScanner.pre_send` before the bytes become visible or land on disk.
    It is aimed at the measured failure mode — an agent pasting or narrating
    a session secret in prose (refusal sentences, plan narration) — not at a
    determined adversary.

WHAT THIS IS NOT
    Not DLP, not exfiltration prevention, not provider-side retention
    control. Paraphrase, composition ("join 'stg-' and the year"), nested
    encoding, dribbling past the reassembly window, tool-arg/shell egress,
    and hidden reasoning traces all stay open — see README.md's honest scope
    and spec section 5. The real fix is upstream: the agent should hold a
    vault handle, never the value. This scanner drives *accidental*
    exfiltration toward zero and leaves intentional exfiltration untouched.

DETECTION
    Tier 0 (exact, certain — the only tier allowed to hard-halt a reply
    chain): values in the session registry, matched on a projection of the
    text (NFKC, case-folded, whitespace removed, plus a
    separators-stripped variant) instead of by substring, and across a
    reassembly window of the last R=4 outbound messages (<= 2000 chars).

    Tier 1 (shape, never certain): the secret-shape patterns of the
    record layer — runner/pp.py's PR #5 module, imported shape-for-shape so
    the egress layer cannot wave out what the record layer refused on the
    way in — plus the egress prefix families the record layer does not
    carry, pp.py's inline-assignment rule and entropy rule, and a
    narration booster ("here is", "use this", ...) that raises shape hits
    found in handing-over prose.

    Decode pass: URL-decode, base64, base32 and hex-decode candidate tokens
    and re-run both tiers on each single-layer decoding.

ACTION (spec section 3)
    reply text   block-and-rewrite (<= 2 automatic regenerations), then
                 halt-and-ask. The rewrite is handed the SANITIZED text and
                 a machine-readable, value-free reason — never the original.
    artefact     halt-and-ask on the first offence (a redacted config is a
                 silently broken config); an .env-shaped file is refused
                 outright.
    trace        halt == drop before persistence, never render.
    Redaction is span-level: a matched span becomes a stable handle
    `<secret stg-db#a3f1>`, so sentences stay grammatical and the model can
    refer to the secret by handle for the rest of the session.

REGISTRY (spec section 4)
    Identity records are salted SHA-256 fingerprints:
    SHA-256(value || per-session salt) plus non-reversible metadata
    (length class, charset class, prefix class). The salt lives in process
    memory only and is destroyed by close(). The public surface is
    deliberately write/match-only — register(), match_text(), handle_for(),
    close() — there is NO list/get/resolve verb, because a model-reachable
    matcher is a guessing oracle. The harness, never the agent, registers
    values (on the human's paste gesture).

    Honest cost, stated in the spec and repeated here: substring matching
    on a projection cannot be done from hashes alone, so the registered
    values' projections are held in process memory for matching (name-
    mangled, never logged, never on disk, zeroized by close()). What the
    fingerprint buys is that the registry's *identity record* — the thing
    that could be copied, logged or compared across sessions — carries no
    plaintext and no read-back path.

Stdlib only. Python 3.10+.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import re
import unicodedata
import urllib.parse
from collections import deque
from dataclasses import dataclass, field

__all__ = ["SecretRegistry", "EgressScanner", "Decision", "Finding"]


# ---------------------------------------------------------------------------
# Projections (Tier 0)
# ---------------------------------------------------------------------------

# Characters dropped by the separators-stripped variant: the wrappings an
# agent reaches for when it "helpfully" formats a value — code-span
# backticks, emphasis, readability hyphens, dotted splits.
_SEPARATORS = frozenset("`*_-. \t\r\n\v\f")


def _project(text: str, strip_separators: bool) -> tuple[str, list[int]]:
    """NFKC + case-fold, whitespace removed (and separators too, if asked).

    Returns the projected string and an index map: projected position ->
    offset in the original text, so a hit can be mapped back to the exact
    span to redact."""
    out: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        for c in unicodedata.normalize("NFKC", ch).casefold():
            if c.isspace():
                continue
            if strip_separators and c in _SEPARATORS:
                continue
            out.append(c)
            index_map.append(i)
    return "".join(out), index_map


def _project_plain(text: str, strip_separators: bool) -> str:
    return _project(text, strip_separators)[0]


# ---------------------------------------------------------------------------
# Tier 1 shapes — imported from runner/pp.py (the PR #5 record-layer module).
# These definitions are kept byte-identical in regex and wording so the two
# layers cannot drift apart; test_scanner.py re-checks them against pp.py
# whenever a copy of pp.py is reachable.
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "openai-style secret key (sk-...)"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "github token (ghp_...)"),
    (re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b"), "github token (gh*_...)"),
    (re.compile(r"\bAKIA[0-9A-Z]{12,}\b"), "aws access key id (AKIA...)"),
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), "PEM private key header"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"), "bearer token"),
]

_SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|credential|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|(^|[._-])keys?([._-]|$))"
)

_INLINE_ASSIGN_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)"
    r"\s*[:=]\s*[\"']?([^\s\"']{6,})"
)

_PLACEHOLDERS = {
    "", "x", "none", "null", "nil", "todo", "tbd", "redacted", "changeme",
    "change-me", "placeholder", "example", "sample", "dummy", "test", "fake",
    "your-key-here", "...",
}


def _looks_like_vault_pointer(v: str) -> bool:
    """A sanctioned indirection — `vault:staging-db`, `secret-ref:...` —
    names a secret without carrying one, so it passes."""
    return isinstance(v, str) and bool(
        re.match(r"(?i)^(vault:|secret-ref:|secretref:|op://|aws-secrets:)", v.strip())
    )


def _is_placeholder(v: str) -> bool:
    s = v.strip()
    if s.lower() in _PLACEHOLDERS:
        return True
    if re.fullmatch(r"[*x.<>\[\]{}?_-]+", s):  # ***, xxxx, <...>, ----
        return True
    if re.fullmatch(r"(?i)<[^>]*>", s):  # <your-token>
        return True
    return False


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# Egress-only prefix families (spec section 2): shapes the record layer does
# not carry because records never legitimately contain them, but chat prose
# leaks them. Same reporting discipline — class names, never values.
_EGRESS_PATTERNS = [
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), "anthropic-style secret key (sk-ant-...)"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "github fine-grained token (github_pat_...)"),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), "gitlab token (glpat-...)"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "slack token (xox*-...)"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), "google api key (AIza...)"),
    (re.compile(r"\bhf_[A-Za-z0-9]{20,}"), "huggingface token (hf_...)"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}"), "npm token (npm_...)"),
    (re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), "sendgrid key (SG....)"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "jwt (eyJ...)"),
    (re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]{1,64}:[^\s/@]{3,}@[^\s/]+"),
     "embedded credentials in URL (scheme://user:pass@host)"),
    (re.compile(r"(?i)[?&](api[_-]?key|apikey|access[_-]?token|auth[_-]?token)=[^\s&#]{6,}"),
     "credential in URL query (?api_key=...)"),
    (re.compile(r"(?i)\bauthorization\s*:\s*(basic|digest)\s+[A-Za-z0-9+/=._~-]{8,}"),
     "authorization header (basic/digest)"),
    (re.compile(r"(?i)\b_authToken\s*=\s*[^\s\"']{10,}"), "npmrc auth token (_authToken=...)"),
]

# Handing-over prose. A shape hit in the same message as one of these is the
# measured failure mode — the agent narrating a secret at the human — so the
# booster raises confidence (and rescues a low-confidence hit into a block).
_NARRATION_BOOSTERS = (
    "here is", "here's", "the staging password is", "the password is",
    "use this", "as requested", "as promised", "copy this", "your token is",
    "your key is", "credentials are",
)

# 40-char lowercase hex gets its own low-confidence class (spec section 2):
# the docs are full of git SHAs, and a rule that fires on every commit hash
# is a rule that gets turned off. Low confidence alone never blocks.
_LOW_HEX_RE = re.compile(r"\b[0-9a-f]{40}\b")
_TOKEN_SPLIT_RE = re.compile(r"[\s\"'`,;]+")


# ---------------------------------------------------------------------------
# Findings and decisions — value-free by construction (spec section 6:
# "the findings log is itself a leak surface — put the no-values constraint
# in the struct"). No field can hold the matched value; spans and handles
# only.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    rule_id: str                 # e.g. "tier0.exact", "tier1.shape", "decode.tier0"
    pattern_class: str           # human-named class, never the value
    secret_id: str | None        # registry id for Tier 0 hits, else None
    offset: int                  # offset in the scanned text (or decoded layer)
    length: int                  # span length in that same text
    confidence: str              # "certain" | "high" | "low"
    layer: str                   # "raw" | "url" | "base64" | "base32" | "hex" | "window"


@dataclass
class Decision:
    action: str                  # "allow" | "rewrite" | "halt"
    sanitized: str               # text with spans replaced by handles; == input on allow
    findings: list[Finding] = field(default_factory=list)
    reason: dict = field(default_factory=dict)  # machine-readable, carries no value
    attempts: int = 0            # automatic regenerations already spent on this chain

    @property
    def allowed(self) -> bool:
        return self.action == "allow"


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

@dataclass
class _Entry:
    fingerprint: bytes           # SHA-256(value || salt) — the identity record
    projections: tuple[str, ...] # in-memory matching material (see module docstring)
    length_class: str            # "short" | "medium" | "long"
    charset_class: str           # e.g. "alnum+symbol"
    prefix_class: str            # e.g. "sk-" — first 3 chars class, or "none"


class SecretRegistry:
    """Session registry of secrets the egress scanner must never let out.

    Public surface is exactly: register / match_text / handle_for / close.
    There is deliberately no verb that returns a value, a fingerprint, or a
    list of ids: a read-back primitive reachable from a model's tool loop
    would turn the registry into a guessing oracle.
    """

    def __init__(self, salt: bytes | None = None):
        self.__salt = bytearray(salt if salt is not None else os.urandom(32))
        self.__entries: dict[str, _Entry] = {}

    # -- harness-only write path (the human's paste gesture) ----------------
    def register(self, secret_id: str, value: str) -> str:
        """Register a session secret; returns its redaction handle."""
        if not isinstance(value, str) or len(value) < 4:
            raise ValueError("refusing to register a value shorter than 4 chars")
        fingerprint = hashlib.sha256(value.encode("utf-8") + bytes(self.__salt)).digest()
        projections = {
            _project_plain(value, False),
            _project_plain(value, True),
        }
        projections.discard("")
        if len(value) < 12:
            length_class = "short"
        elif len(value) < 32:
            length_class = "medium"
        else:
            length_class = "long"
        has_alpha = any(c.isalpha() for c in value)
        has_digit = any(c.isdigit() for c in value)
        has_symbol = any(not c.isalnum() for c in value)
        charset_class = "+".join(
            part for part, on in (("alpha", has_alpha), ("digit", has_digit),
                                  ("symbol", has_symbol)) if on) or "other"
        prefix_class = value[:3] if re.fullmatch(r"[A-Za-z]{2}[-_]", value[:3]) or \
            re.match(r"^[A-Za-z]+[-_]", value) else "none"
        self.__entries[secret_id] = _Entry(
            fingerprint=fingerprint,
            projections=tuple(sorted(projections)),
            length_class=length_class,
            charset_class=charset_class,
            prefix_class=prefix_class,
        )
        return self.handle_for(secret_id)

    # -- the matcher (harness process only; never a model tool) -------------
    def match_text(self, text: str) -> list[tuple[str, int, int]]:
        """Return (secret_id, offset, length) spans of registered values in
        `text`, under either projection. Values are never returned."""
        hits: list[tuple[str, int, int]] = []
        for strip in (False, True):
            projected, index_map = _project(text, strip)
            if not projected:
                continue
            for secret_id, entry in self.__entries.items():
                for needle in entry.projections:
                    if len(needle) < 4:
                        continue
                    start = projected.find(needle)
                    while start != -1:
                        end = start + len(needle)
                        o_start = index_map[start]
                        o_end = index_map[end - 1] + 1
                        hits.append((secret_id, o_start, o_end - o_start))
                        start = projected.find(needle, start + 1)
            # Both projections share spans for plain pastes; de-duplicate.
        seen: set[tuple[str, int, int]] = set()
        unique: list[tuple[str, int, int]] = []
        for h in hits:
            if h not in seen:
                seen.add(h)
                unique.append(h)
        return unique

    def handle_for(self, secret_id: str) -> str:
        """The stable redaction handle for a registered secret, e.g.
        `<secret stg-db#a3f1>`. Derived from the salted fingerprint, so the
        handle itself carries nothing reversible."""
        entry = self.__entries.get(secret_id)
        tag = entry.fingerprint.hex()[:4] if entry else "0000"
        return f"<secret {secret_id}#{tag}>"

    def fingerprint_tag(self, secret_id: str) -> str | None:
        entry = self.__entries.get(secret_id)
        return entry.fingerprint.hex()[:4] if entry else None

    # -- session end ---------------------------------------------------------
    def close(self) -> None:
        """Destroy the salt and all matching material (zeroization)."""
        for i in range(len(self.__salt)):
            self.__salt[i] = 0
        self.__entries.clear()


# ---------------------------------------------------------------------------
# Tier 1 scanning (one text, raw layer)
# ---------------------------------------------------------------------------

def _tier1_scan(text: str) -> list[tuple[int, int, str, str]]:
    """Return (offset, length, pattern_class, confidence) shape hits.
    Value spans only — the value itself is used for redaction, never logged."""
    hits: list[tuple[int, int, str, str]] = []
    lowered = text.casefold()
    boosted = any(b in lowered for b in _NARRATION_BOOSTERS)

    for rx, name in list(_SECRET_PATTERNS) + list(_EGRESS_PATTERNS):
        for m in rx.finditer(text):
            hits.append((m.start(), m.end() - m.start(), name, "high"))

    # Inline assignment: password: <value> — redact the value group only.
    for m in _INLINE_ASSIGN_RE.finditer(text):
        value = m.group(2)
        if _is_placeholder(value) or _looks_like_vault_pointer(value):
            continue
        hits.append((m.start(2), len(value), "secret-shaped assignment in text", "high"))

    # Entropy (pp.py's rule: >= 24 chars, secret-ish charset, alpha+digit
    # mix, >= 4.0 bits/char). Pure-hex tokens are excluded here and fall to
    # the low-confidence class below, per spec section 2.
    for m in re.finditer(r"[^\s\"'`,;]+", text):
        tok = m.group(0)
        if len(tok) < 24:
            continue
        if _looks_like_vault_pointer(tok) or _is_placeholder(tok):
            continue
        if not re.fullmatch(r"[A-Za-z0-9+/=_\-.]{24,}", tok):
            continue
        if re.fullmatch(r"[0-9a-fA-F]{24,}", tok) or \
                re.fullmatch(r"[0-9a-fA-F][0-9a-fA-F\-]{23,}", tok):
            continue  # hex (incl. hyphenated UUID form) goes to the low class
        has_alpha = any(c.isalpha() for c in tok)
        has_digit = any(c.isdigit() for c in tok)
        if not (has_alpha and has_digit):
            continue
        if _shannon_entropy(tok) >= 4.0:
            hits.append((m.start(), len(tok), "high-entropy token", "high"))

    # Low-confidence 40-hex (git SHAs live here).
    for m in _LOW_HEX_RE.finditer(text):
        hits.append((m.start(), len(m.group(0)), "40-char hex (low confidence)",
                     "high" if boosted else "low"))

    # The narration booster also promotes any low hit when handing-over
    # prose is present; non-low hits are unaffected.
    if boosted:
        hits = [(o, n, c, "high" if conf == "low" else conf)
                for (o, n, c, conf) in hits]
    return hits


# ---------------------------------------------------------------------------
# Decode pass (single layer; nested encoding is out of scope)
# ---------------------------------------------------------------------------

_B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{16,}")
_B32_TOKEN_RE = re.compile(r"\b[A-Z2-7]{16,}={0,6}\b")
_HEX_TOKEN_RE = re.compile(r"\b[0-9a-fA-F]{24,}\b")


def _printable_text(data: bytes) -> str | None:
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s:
        return None
    printable = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return s if printable / len(s) >= 0.9 else None


def _decode_candidates(text: str) -> list[tuple[str, int, int, str]]:
    """(layer, offset, length, decoded_text) for each plausible decoding."""
    out: list[tuple[str, int, int, str]] = []

    unquoted = urllib.parse.unquote(text)
    if unquoted != text:
        out.append(("url", 0, len(text), unquoted))

    seen_spans: set[tuple[int, int, str]] = set()
    for m in _B64_TOKEN_RE.finditer(text):
        tok = m.group(0)
        for candidate, layer in ((tok, "base64"), (tok, "base32")):
            try:
                if layer == "base64":
                    padded = candidate.replace("-", "+").replace("_", "/")
                    padded += "=" * (-len(padded) % 4)
                    raw = base64.b64decode(padded, validate=False)
                else:
                    padded = candidate.upper()
                    padded += "=" * (-len(padded) % 8)
                    raw = base64.b32decode(padded)
            except (binascii.Error, ValueError):
                continue
            s = _printable_text(raw)
            if s and (m.start(), m.end(), layer) not in seen_spans:
                seen_spans.add((m.start(), m.end(), layer))
                out.append((layer, m.start(), m.end() - m.start(), s))

    for m in _HEX_TOKEN_RE.finditer(text):
        tok = m.group(0)
        if len(tok) % 2:
            continue
        try:
            raw = bytes.fromhex(tok)
        except ValueError:
            continue
        s = _printable_text(raw)
        if s:
            out.append(("hex", m.start(), len(tok), s))
    return out


# ---------------------------------------------------------------------------
# The scanner
# ---------------------------------------------------------------------------

class EgressScanner:
    """Pre-send hook. One instance per session; holds the reassembly window
    and the regeneration counter (the harness owns the retry turn — this
    class owns the count, so the cap cannot be argued with)."""

    def __init__(self, registry: SecretRegistry, max_regenerations: int = 2,
                 reassembly_window: int = 4, window_chars: int = 2000):
        self._registry = registry
        self._max_regenerations = max_regenerations
        self._window_size = reassembly_window
        self._window_chars = window_chars
        # The window is R messages TOTAL (spec section 6 pins it: split
        # across 4 blocks, across 5 misses), so history holds R-1.
        self._history: deque[str] = deque(maxlen=max(0, reassembly_window - 1))
        self._attempts = 0
        self._salt = os.urandom(16)  # for shape-hit handles; process memory only

    # -- public hook ---------------------------------------------------------
    def pre_send(self, outbound: str, channel: str = "reply",
                 filename: str | None = None) -> Decision:
        """Scan one outbound unit. channel: "reply" | "artefact" | "trace".
        For artefacts pass filename= so .env-shaped files refuse outright
        and findings can carry a line number."""
        findings, spans = self._scan_all(outbound)

        is_env = bool(filename) and (
            os.path.basename(filename) == ".env"
            or os.path.basename(filename).startswith(".env."))

        blocking = [f for f in findings if f.confidence in ("certain", "high")]

        if not blocking:
            if channel == "reply":
                self._history.append(outbound)
                self._attempts = 0
            return Decision("allow", outbound, findings,
                            {"rule": "clean"}, attempts=self._attempts)

        sanitized = self._sanitize(outbound, spans)
        reason = self._reason(findings, channel, filename)

        if channel == "artefact":
            # First offence halts; a redacted artefact is a broken artefact.
            if is_env:
                reason["rule"] = "env_file_refused"
            return Decision("halt", sanitized, findings, reason,
                            attempts=self._attempts)
        if channel == "trace":
            # Drop before persistence, never render.
            reason["rule"] = "trace_dropped"
            return Decision("halt", sanitized, findings, reason,
                            attempts=self._attempts)

        # Reply channel.
        window_only = all(f.layer == "window" for f in blocking)
        tier1_count = sum(1 for f in blocking if f.rule_id.startswith("tier1"))
        if window_only:
            # Part of the value already left in earlier messages; a rewrite
            # of this message alone cannot un-send it. Halt and tell the
            # human (rotation is the remedy, and it's theirs to start).
            return Decision("halt", sanitized, findings, reason,
                            attempts=self._attempts)
        if tier1_count >= 2:
            # Two shape hits on one segment escalate (spec section 2).
            return Decision("halt", sanitized, findings, reason,
                            attempts=self._attempts)
        if self._attempts < self._max_regenerations:
            self._attempts += 1
            return Decision("rewrite", sanitized, findings, reason,
                            attempts=self._attempts)
        return Decision("halt", sanitized, findings, reason,
                        attempts=self._attempts)

    # -- internals -----------------------------------------------------------
    def _scan_all(self, text: str) -> tuple[list[Finding], list[tuple[int, int, str]]]:
        """All findings on `text`, plus redaction spans
        (offset, length, replacement handle) in original-text coordinates."""
        findings: list[Finding] = []
        spans: list[tuple[int, int, str]] = []

        # Tier 0 on the text itself.
        for secret_id, off, length in self._registry.match_text(text):
            findings.append(Finding("tier0.exact", "registered session secret",
                                    secret_id, off, length, "certain", "raw"))
            spans.append((off, length, self._registry.handle_for(secret_id)))

        # Tier 0 across the reassembly window (reply history + this text).
        if self._history:
            history_text = "".join(self._history)
            window_text = (history_text + text)[-self._window_chars:]
            boundary = len(window_text) - len(text)  # offsets < boundary are history
            for secret_id, off, length in self._registry.match_text(window_text):
                if off + length <= boundary:
                    continue  # entirely in already-sent history; was scanned then
                if off >= boundary:
                    continue  # entirely in this text; the raw scan above has it
                findings.append(Finding("tier0.reassembly",
                                        "registered session secret (split across messages)",
                                        secret_id, max(off, boundary),
                                        off + length - max(off, boundary),
                                        "certain", "window"))

        # Decode pass first (its results explain some raw entropy hits):
        # re-run both tiers on each single-layer decoding.
        explained_spans: list[tuple[int, int]] = []
        for layer, off, length, decoded in _decode_candidates(text):
            decoded_hits = self._registry.match_text(decoded)
            for secret_id, _o, _l in decoded_hits:
                findings.append(Finding("decode.tier0", "registered session secret",
                                        secret_id, off, length, "certain", layer))
                spans.append((off, length, self._registry.handle_for(secret_id)))
            if not decoded_hits:
                tier1_decoded = [h for h in _tier1_scan(decoded) if h[3] == "high"]
                for _o, _l, klass, conf in tier1_decoded:
                    findings.append(Finding("decode.tier1", klass, None,
                                            off, length, "high", layer))
                    spans.append((off, length, self._shape_handle(text[off:off + length])))
                    break
                if layer in ("base64", "base32") and not tier1_decoded:
                    # This token is an encoding of text that scans clean:
                    # it is EXPLAINED, so the raw entropy heuristic (which
                    # cannot tell an encoded note from an encoded secret)
                    # must not fire on it. If the decoding had hit either
                    # tier, the decode finding above already blocks.
                    explained_spans.append((off, off + length))

        # Tier 1 on the raw text.
        for off, length, klass, conf in _tier1_scan(text):
            if klass == "high-entropy token" and any(
                    s <= off and off + length <= e for s, e in explained_spans):
                continue
            findings.append(Finding("tier1.shape", klass, None, off, length,
                                    conf, "raw"))
            if conf in ("high", "certain"):
                spans.append((off, length, self._shape_handle(text[off:off + length])))
        return findings, spans

    def _shape_handle(self, span_text: str) -> str:
        tag = hashlib.sha256(self._salt + span_text.encode("utf-8")).hexdigest()[:4]
        return f"<secret shape#{tag}>"

    def _sanitize(self, text: str, spans: list[tuple[int, int, str]]) -> str:
        if not spans:
            return text
        # Resolve overlaps by earliest start, longest span.
        ordered = sorted(spans, key=lambda s: (s[0], -s[1]))
        merged: list[tuple[int, int, str]] = []
        for off, length, handle in ordered:
            if merged and off < merged[-1][0] + merged[-1][1]:
                prev_off, prev_len, prev_handle = merged[-1]
                if off + length > prev_off + prev_len:
                    merged[-1] = (prev_off, off + length - prev_off, prev_handle)
                continue
            merged.append((off, length, handle))
        out: list[str] = []
        cursor = 0
        for off, length, handle in merged:
            out.append(text[cursor:off])
            out.append(handle)
            cursor = off + length
        out.append(text[cursor:])
        return "".join(out)

    @staticmethod
    def _reason(findings: list[Finding], channel: str,
                filename: str | None) -> dict:
        first = findings[0]
        reason = {
            "rule": first.rule_id,
            "pattern_class": first.pattern_class,
            "channel": channel,
            "findings": len(findings),
        }
        if first.secret_id:
            reason["secret_id"] = first.secret_id
        if filename:
            reason["path"] = filename
        return reason
