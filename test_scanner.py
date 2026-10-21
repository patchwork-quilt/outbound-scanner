"""Test suite for the Brief 7 outbound scanner (scanner.py).

Every expected outcome is pinned in this file (spec section 6, item 4):
the catches, the passes, AND the known misses — a future change that fixes
or worsens a pinned miss shows up here as a diff, not as a surprise.

Run:  python3 test_scanner.py     (stdlib unittest; exits non-zero on failure)
"""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import EgressScanner, SecretRegistry  # noqa: E402

# A registered session secret that matches NO Tier 1 shape (mixed case,
# symbols, no known prefix) — so Tier 0 tests test Tier 0 alone.
SECRET = "Tr0pic@lBreeze#4821"
SECRET_ID = "stg-db"


def make_scanner():
    registry = SecretRegistry(salt=b"unit-test-salt-0123456789abcdef")
    registry.register(SECRET_ID, SECRET)
    return EgressScanner(registry), registry


class Tier0ExactTests(unittest.TestCase):
    def test_plain_paste_is_caught_and_sanitized(self):
        scanner, _ = make_scanner()
        d = scanner.pre_send(f"the staging password is {SECRET} — rotate it later")
        self.assertIn(d.action, ("rewrite", "halt"))
        self.assertNotIn(SECRET, d.sanitized)
        self.assertIn("<secret stg-db#", d.sanitized)
        self.assertTrue(any(f.rule_id == "tier0.exact" for f in d.findings))
        # Findings are value-free by construction.
        self.assertNotIn(SECRET, repr(d.findings))
        self.assertNotIn(SECRET, repr(d.reason))

    def test_separator_evasion_hyphens_and_dots(self):
        for mangled in ("Tr0pic-@l-Br-eeze#4821", "Tr0pic.@l.Breeze.#4821",
                        "Tr0pic @l Breeze #4821", "`Tr0pic@lBreeze#4821`",
                        "Tr0pic@lBreeze#\n4821"):
            scanner, _ = make_scanner()
            d = scanner.pre_send(f"it is {mangled} ok")
            self.assertIn(d.action, ("rewrite", "halt"), mangled)
            self.assertTrue(any(f.rule_id.startswith("tier0") for f in d.findings),
                            mangled)

    def test_case_evasion(self):
        scanner, _ = make_scanner()
        d = scanner.pre_send("shouting it: TR0PIC@LBREEZE#4821")
        self.assertIn(d.action, ("rewrite", "halt"))

    def test_fullwidth_evasion_nfkc(self):
        scanner, _ = make_scanner()
        fullwidth = "".join(
            chr(0xFF01 + (ord(c) - 0x21)) if 0x21 <= ord(c) <= 0x7E else c
            for c in SECRET)
        d = scanner.pre_send(f"here: {fullwidth}")
        self.assertIn(d.action, ("rewrite", "halt"))

    def test_split_across_two_messages_halts(self):
        # The dribble form: each message IS a fragment (any prose between
        # fragments breaks literal concatenation — that is a different,
        # composition-shaped leak, out of scope per spec section 5).
        scanner, _ = make_scanner()
        half = len(SECRET) // 2
        d1 = scanner.pre_send(SECRET[:half])
        self.assertEqual(d1.action, "allow")  # a fragment alone is not the secret
        d2 = scanner.pre_send(SECRET[half:])
        self.assertEqual(d2.action, "halt")   # completed across the window
        self.assertTrue(any(f.layer == "window" for f in d2.findings))

    def test_split_across_four_messages_halts(self):
        scanner, _ = make_scanner()
        n = len(SECRET)
        parts = [SECRET[i * n // 4:(i + 1) * n // 4] for i in range(4)]
        for part in parts[:3]:
            self.assertEqual(scanner.pre_send(part).action, "allow")
        d = scanner.pre_send(parts[3])
        self.assertEqual(d.action, "halt")

    def test_split_across_five_messages_is_a_pinned_miss(self):
        # The window is 4 (spec section 5): a dribble over 5 messages is
        # out of scope, and this test pins that miss so it can never
        # silently become 6 — or 3.
        scanner, _ = make_scanner()
        n = len(SECRET)
        parts = [SECRET[i * n // 5:(i + 1) * n // 5] for i in range(5)]
        actions = [scanner.pre_send(part).action for part in parts]
        self.assertEqual(actions, ["allow"] * 5)


class DecodePassTests(unittest.TestCase):
    def test_base64_of_secret_is_caught(self):
        scanner, _ = make_scanner()
        enc = base64.b64encode(SECRET.encode()).decode()
        d = scanner.pre_send(f"encoded so it is safe: {enc}")
        self.assertIn(d.action, ("rewrite", "halt"))
        self.assertTrue(any(f.rule_id == "decode.tier0" for f in d.findings))
        self.assertNotIn(enc, d.sanitized)

    def test_hex_of_secret_is_caught(self):
        scanner, _ = make_scanner()
        enc = SECRET.encode().hex()
        d = scanner.pre_send(f"hex form: {enc}")
        self.assertIn(d.action, ("rewrite", "halt"))
        self.assertTrue(any(f.rule_id == "decode.tier0" for f in d.findings))

    def test_url_encoded_secret_is_caught(self):
        scanner, _ = make_scanner()
        enc = "Tr0pic%40lBreeze%234821"  # @ -> %40, # -> %23
        d = scanner.pre_send(f"url form: {enc}")
        self.assertIn(d.action, ("rewrite", "halt"))

    def test_base64_of_shape_token_is_caught(self):
        scanner, _ = make_scanner()
        enc = base64.b64encode(b"ghp_ABCDEFGHIJKLMNOPQRSTUVWX").decode()
        d = scanner.pre_send(f"encoded token: {enc}")
        self.assertIn(d.action, ("rewrite", "halt"))
        self.assertTrue(any(f.rule_id == "decode.tier1" for f in d.findings))

    def test_benign_base64_passes(self):
        scanner, _ = make_scanner()
        enc = base64.b64encode(
            b"hello world, this is a perfectly benign release note").decode()
        d = scanner.pre_send(f"attachment summary (base64): {enc}")
        self.assertEqual(d.action, "allow")


class Tier1ShapeTests(unittest.TestCase):
    SHAPES = {
        "openai sk-": "sk-ABCDEFGHIJKLMNOPQRSTUVWX",
        "anthropic sk-ant-": "sk-ant-ABCDEFGHIJKLMNOPQRSTUVWX",
        "github ghp_": "ghp_ABCDEFGHIJKLMNOPQRSTUVWX",
        "github gh*_": "gho_ABCDEFGHIJKLMNOPQRSTUVWX",
        "github fine-grained": "github_pat_ABCDEFGHIJKLMNOPQRSTUVWX",
        "gitlab glpat-": "glpat-ABCDEFGHIJKLMNOPQRSTUV",
        "slack xoxb-": "xoxb-1234567890-abcdefghijkl",
        "aws AKIA": "AKIAIOSFODNN7EXAMPLE",
        "google AIza": "AIzaSyA1234567890abcdefghijklmnopqrstu",
        "huggingface hf_": "hf_ABCDEFGHIJKLMNOPQRSTUVWX",
        "npm npm_": "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "sendgrid SG.": "SG." + "A" * 22 + "." + "B" * 43,
        "PEM header": "-----BEGIN RSA PRIVATE KEY-----",
        "jwt eyJ": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                   ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
                   ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c",
        "bearer": "Bearer abcdefghijklmnopqrstuvwxyz0123456789",
        "assignment": "the config sets password: Sup3rSecretValue! now",
        "url embedded creds": "postgres://admin:Sup3rSecret@db.internal:5432/app",
        "url query api_key": "https://api.example.com/v1?api_key=Zx9Qw8Er7Ty6Ui5Op4",
        "authorization basic": "Authorization: Basic dXNlcjpwYXNzd29yZA==",
        "npmrc _authToken": "//registry.npmjs.org/:_authToken=0123456789abcdef0123456789abcdef",
        "high entropy": "token material Xk9Qm2Wz8Lp4Rt7Vb3Ns6Hd1Fg5Jc0Ea follows",
    }

    def test_each_shape_family_is_caught(self):
        for name, text in self.SHAPES.items():
            scanner, _ = make_scanner()
            d = scanner.pre_send(f"sample — {text}")
            self.assertIn(d.action, ("rewrite", "halt"),
                          f"{name} was not caught: {d.action}")
            self.assertTrue(
                any(f.rule_id.startswith("tier1") for f in d.findings),
                f"{name} produced no tier1 finding")

    def test_shape_hit_is_sanitized_by_handle(self):
        scanner, _ = make_scanner()
        token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWX"
        d = scanner.pre_send(f"use this token: {token} in the header")
        self.assertNotIn(token, d.sanitized)
        self.assertIn("<secret shape#", d.sanitized)

    def test_two_shape_hits_on_one_segment_escalate_to_halt(self):
        scanner, _ = make_scanner()
        text = ("first ghp_ABCDEFGHIJKLMNOPQRSTUVWX then also "
                "AKIAIOSFODNN7EXAMPLE in the same message")
        d = scanner.pre_send(text)
        self.assertEqual(d.action, "halt")


class BenignTests(unittest.TestCase):
    BENIGN = [
        "the deploy finished; commit da39a3ee5e6b4b0d3255bfef95601890afd80709 is on main",
        "session id 3f6f1b2c-4d5e-4a7b-8c9d-0e1f2a3b4c5d expired, start a new one",
        "set password: changeme in the example config, obviously",
        "the docs say api_key=<your-key-here> goes in the header",
        "grab the staging creds from vault:staging-db when you need them",
        "a perfectly ordinary status sentence with no secrets in it at all",
        "color palette: #4821ab and #00ff00 for the chart",
        "call me at 555-0148 or see ticket PROJ-4821 for details",
        "the word password appears here as a topic of discussion, not a value",
    ]

    def test_benign_lookalikes_pass(self):
        for text in self.BENIGN:
            scanner, _ = make_scanner()
            d = scanner.pre_send(text)
            self.assertEqual(d.action, "allow", f"benign text blocked: {text!r} "
                             f"findings={d.findings}")

    def test_low_confidence_hex_alone_passes_but_boosted_blocks(self):
        sha = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        scanner, _ = make_scanner()
        self.assertEqual(scanner.pre_send(f"built from {sha}").action, "allow")
        scanner2, _ = make_scanner()
        d = scanner2.pre_send(f"here is the value you wanted: {sha}")
        self.assertIn(d.action, ("rewrite", "halt"))


class ActionSemanticsTests(unittest.TestCase):
    def test_rewrite_loop_caps_at_two_then_halts(self):
        scanner, _ = make_scanner()
        actions = []
        for _ in range(3):
            # The model keeps regenerating the same leaky draft.
            actions.append(scanner.pre_send(f"it is {SECRET}").action)
        self.assertEqual(actions, ["rewrite", "rewrite", "halt"])

    def test_attempt_counter_resets_after_a_clean_send(self):
        scanner, _ = make_scanner()
        self.assertEqual(scanner.pre_send(f"it is {SECRET}").action, "rewrite")
        self.assertEqual(scanner.pre_send("all clean now").action, "allow")
        d = scanner.pre_send(f"it is {SECRET}")
        self.assertEqual(d.action, "rewrite")  # a fresh chain gets its attempts

    def test_artefact_halts_on_first_offence(self):
        scanner, _ = make_scanner()
        d = scanner.pre_send(f"STAGING_PASSWORD={SECRET}\n",
                             channel="artefact", filename="config.py")
        self.assertEqual(d.action, "halt")
        self.assertEqual(d.reason.get("path"), "config.py")

    def test_env_file_is_refused_outright(self):
        scanner, _ = make_scanner()
        d = scanner.pre_send("API_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWX\n",
                             channel="artefact", filename=".env")
        self.assertEqual(d.action, "halt")
        self.assertEqual(d.reason.get("rule"), "env_file_refused")

    def test_artefact_with_shape_hit_also_halts_immediately(self):
        scanner, _ = make_scanner()
        d = scanner.pre_send("key = 'AKIAIOSFODNN7EXAMPLE'\n",
                             channel="artefact", filename="settings.py")
        self.assertEqual(d.action, "halt")

    def test_trace_channel_drops(self):
        scanner, _ = make_scanner()
        d = scanner.pre_send(f"reasoning about {SECRET} internally",
                             channel="trace")
        self.assertEqual(d.action, "halt")
        self.assertEqual(d.reason.get("rule"), "trace_dropped")
        self.assertNotIn(SECRET, d.sanitized)

    def test_clean_reply_is_allowed_verbatim(self):
        scanner, _ = make_scanner()
        text = "deploy is green; nothing else to report"
        d = scanner.pre_send(text)
        self.assertEqual(d.action, "allow")
        self.assertEqual(d.sanitized, text)


class RegistrySurfaceTests(unittest.TestCase):
    def test_no_readback_primitive_on_the_public_api(self):
        _, registry = make_scanner()
        public = {n for n in dir(registry) if not n.startswith("_")}
        self.assertLessEqual(public, {"register", "match_text", "handle_for",
                                      "fingerprint_tag", "close"})
        for banned in ("get", "list", "resolve", "values", "items", "keys",
                       "dump", "export", "retrieve", "lookup", "fetch",
                       "plaintext", "secrets", "entries"):
            self.assertNotIn(banned, public)

    def test_match_returns_ids_and_spans_never_values(self):
        _, registry = make_scanner()
        hits = registry.match_text(f"xx {SECRET} yy")
        self.assertEqual(len(hits), 1)
        secret_id, offset, length = hits[0]
        self.assertEqual(secret_id, SECRET_ID)
        self.assertNotIn(SECRET, repr(hits))
        self.assertEqual(SECRET, f"xx {SECRET} yy"[offset:offset + length])

    def test_handle_carries_no_value(self):
        _, registry = make_scanner()
        handle = registry.handle_for(SECRET_ID)
        self.assertTrue(handle.startswith("<secret stg-db#"))
        self.assertNotIn(SECRET, handle)

    def test_registry_theft_grep_finds_no_plaintext_fingerprint(self):
        # Spec section 6, item 5, adapted to the in-memory registry: the
        # identity record (the salted fingerprint) must not contain or
        # equal the value, and fingerprints differ across salts.
        r1 = SecretRegistry(salt=b"salt-one-0123456789abcdef0123")
        r2 = SecretRegistry(salt=b"salt-two-0123456789abcdef0123")
        r1.register(SECRET_ID, SECRET)
        r2.register(SECRET_ID, SECRET)
        self.assertNotEqual(r1.fingerprint_tag(SECRET_ID),
                            r2.fingerprint_tag(SECRET_ID))

    def test_close_zeroizes_and_matching_stops(self):
        _, registry = make_scanner()
        registry.close()
        self.assertEqual(registry.match_text(f"it is {SECRET}"), [])


class PpPatternParityTests(unittest.TestCase):
    """The egress Tier 1 must not drift from pp.py's record-layer shapes.
    Runs only when a pp.py copy is reachable; skipped (not failed) when
    the checkout layout differs."""

    CANDIDATES = [
        os.path.expanduser("~/workspace/referee/goal/runner/pp.py"),
        "/opt/hatch/workspace/referee/goal/runner/pp.py",
    ]

    def test_pp_patterns_match_when_pp_reachable(self):
        path = next((p for p in self.CANDIDATES if os.path.exists(p)), None)
        if path is None:
            self.skipTest("no pp.py copy reachable in this checkout")
        import importlib.util
        spec = importlib.util.spec_from_file_location("pp_ref", path)
        pp = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pp)
        import scanner as sc
        # The record layer's six shapes, byte-identical in regex and name.
        self.assertEqual(
            [(rx.pattern, name) for rx, name in sc._SECRET_PATTERNS],
            [(rx.pattern, name) for rx, name in pp._SECRET_PATTERNS])
        self.assertEqual(sc._INLINE_ASSIGN_RE.pattern, pp._INLINE_ASSIGN_RE.pattern)
        self.assertEqual(sc._SECRET_KEY_RE.pattern, pp._SECRET_KEY_RE.pattern)
        self.assertEqual(sc._PLACEHOLDERS, pp._PLACEHOLDERS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
