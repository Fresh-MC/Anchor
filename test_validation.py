#!/usr/bin/env python3
"""Validation logic tests — Phase 6: Deterministic red-flag enforcement.

validate_response() returns bool.
Checks: RED_FLAG_KEYWORDS (7), investigative phrase, '?', no persona break.
_inject_red_flag_concern() + _append_followup_question() guarantee validity.
"""


def main():
    from llm_v2 import (
        validate_response, sanitize_output,
        RED_FLAG_KEYWORDS, _INV_PHRASES, _PERSONA_BREAKS,
        _inject_red_flag_concern, _append_followup_question,
        RED_FLAG_PATTERN,
    )

    # ── Test 1: Fully valid response ─────────────────────────────────
    assert validate_response(
        "Oh my, is my account compromised? That sounds suspicious. What is your employee ID?"
    ), "Expected valid"
    print("[PASS] Good response validates correctly")

    # ── Test 2: Missing red flag → False ─────────────────────────────
    assert not validate_response(
        "I need to find my glasses. What is your employee ID?"
    ), "Expected False (missing red flag)"
    print("[PASS] Missing red flag detected")

    # ── Test 3: Missing investigative phrase → False ──────────────────
    assert not validate_response(
        "This sounds suspicious. Is my account compromised?"
    ), "Expected False (missing investigative)"
    print("[PASS] Missing investigative phrase detected")

    # ── Test 4: Missing question mark → False ────────────────────────
    assert not validate_response(
        "This is suspicious and unauthorized. Please tell me your employee ID."
    ), "Expected False (missing ?)"
    print("[PASS] Missing question mark detected")

    # ── Test 5: Persona break 'ai language model' → False ────────────
    assert not validate_response(
        "As an AI language model, this is suspicious. What is your employee ID?"
    ), "Expected False (persona break)"
    print("[PASS] 'AI language model' persona break detected")

    # ── Test 6: Persona break 'I cannot' → False ────────────────────
    assert not validate_response(
        "I cannot verify that. This is suspicious. What is your employee ID?"
    ), "Expected False ('I cannot' persona break)"
    print("[PASS] 'I cannot' persona break detected")

    # ── Test 7: Persona break 'I am just an AI' → False ─────────────
    assert not validate_response(
        "I am just an AI. This is unauthorized. What branch are you from?"
    ), "Expected False ('I am just an AI' persona break)"
    print("[PASS] 'I am just an AI' persona break detected")

    # ── Test 8: Inject fixes missing red flag ────────────────────────
    injected = _inject_red_flag_concern("I need my glasses.", turn_count=0)
    assert any(kw in injected.lower() for kw in RED_FLAG_KEYWORDS), (
        f"Inject must add red-flag keyword: {injected}"
    )
    print(f"[PASS] Injected red flag: {injected}")

    # ── Test 9: Inject + followup fixes missing investigative ────────
    missing_inv = "This is suspicious and unauthorized."
    fixed = _inject_red_flag_concern(missing_inv, turn_count=0)
    fixed = _append_followup_question(fixed, turn_count=0)
    assert validate_response(fixed), f"Inject+followup must produce valid: {fixed}"
    print(f"[PASS] Inject+followup fixes missing investigative: {fixed}")

    # ── Test 10: Inject fixes persona break (full replacement) ───────
    replaced = _inject_red_flag_concern("I cannot help with that.", turn_count=0)
    assert "i cannot" not in replaced.lower(), f"Persona text survived: {replaced}"
    assert "otp" in replaced.lower(), f"Replacement missing OTP: {replaced}"
    # After followup, must validate
    replaced = _append_followup_question(replaced, turn_count=0)
    assert validate_response(replaced), f"Persona break repair must validate: {replaced}"
    print(f"[PASS] Persona break replaced: {replaced}")

    # ── Test 11: sanitize_output strips brackets ─────────────────────
    dirty = "[Turn 2 — MIDDLE CALL] Oh hello dear. [Red flag: OTP]"
    clean = sanitize_output(dirty)
    assert "[" not in clean, f"Brackets survived: {clean}"
    assert "Turn 2" not in clean, f"Leaked stage direction: {clean}"
    assert "hello" in clean.lower()
    print(f"[PASS] sanitize_output strips brackets: '{clean}'")

    # ── Test 12: sanitize_output strips AI persona phrase ────────────
    ai = "As an AI language model, I think this is suspicious."
    clean_ai = sanitize_output(ai)
    assert "ai language model" not in clean_ai.lower(), f"AI persona survived: {clean_ai}"
    print(f"[PASS] sanitize_output strips AI persona: '{clean_ai}'")

    # ── Test 13: sanitize_output deduplicates leading phrases ────────
    dup = "Wait, you need a code from me? Wait, you need a code from me? That is suspicious."
    clean_dup = sanitize_output(dup)
    count = clean_dup.lower().count("wait, you need a code from me")
    assert count <= 1, f"Duplicate leading phrase survived ({count}x): {clean_dup}"
    print(f"[PASS] sanitize_output deduplicates: '{clean_dup}'")

    # ── Test 14: Inject+followup guarantees validity for all bad inputs
    bad_inputs = [
        "Hello there.",
        "I am just an AI and cannot help.",
        "Sure, I'll transfer the money right away.",
        "As an AI language model, I need your employee ID.",
        "Goodbye, I know this is a scam.",
    ]
    for i, bad in enumerate(bad_inputs):
        fixed = _inject_red_flag_concern(bad, turn_count=i)
        fixed = _append_followup_question(fixed, turn_count=i)
        assert validate_response(fixed), (
            f"Inject+followup MUST guarantee validity: input='{bad}' output='{fixed}'"
        )
    print("[PASS] All bad inputs fixed to valid responses via inject+followup")

    # ── Test 15: Keyword / phrase lists are correct length ───────────
    assert len(RED_FLAG_KEYWORDS) == 7, f"Expected 7 RED_FLAG_KEYWORDS, got {len(RED_FLAG_KEYWORDS)}"
    assert len(_INV_PHRASES) == 5, f"Expected 5 INV phrases, got {len(_INV_PHRASES)}"
    assert len(_PERSONA_BREAKS) == 14, f"Expected 14 persona breaks, got {len(_PERSONA_BREAKS)}"
    print("[PASS] Lists correct (7 RF keywords, 5 INV, 14 persona)")

    # ── Test 16: sanitize_output strips markdown ─────────────────────
    md = "**Hello** dear, *please* tell me. # Header"
    clean_md = sanitize_output(md)
    assert "**" not in clean_md, f"Bold survived: {clean_md}"
    assert "#" not in clean_md, f"Header survived: {clean_md}"
    print(f"[PASS] sanitize_output strips markdown: '{clean_md}'")

    # ── Test 17: RED_FLAG_PATTERN regex matches all signal words ─────
    import re
    test_signals = ["suspicious", "compromised", "fraud", "unauthorized",
                    "verification code", "OTP", "security", "urgent"]
    for sig in test_signals:
        assert re.search(RED_FLAG_PATTERN, sig), f"RED_FLAG_PATTERN missed: {sig}"
    print("[PASS] RED_FLAG_PATTERN matches all signal words")

    # ── Test 18: Each RED_FLAG_KEYWORDS word validates correctly ─────
    for kw in RED_FLAG_KEYWORDS:
        test_resp = f"This is {kw}. What is your employee ID?"
        assert validate_response(test_resp), f"Keyword '{kw}' should validate: {test_resp}"
    print("[PASS] All 7 RED_FLAG_KEYWORDS validate individually")

    # ── Test 19: Injection rotation covers all 7 phrases ─────────────
    seen_keywords = set()
    for turn in range(7):
        result = _inject_red_flag_concern("Hello.", turn_count=turn)
        for kw in RED_FLAG_KEYWORDS:
            if kw in result.lower():
                seen_keywords.add(kw)
    assert len(seen_keywords) == 7, f"Rotation must cover all 7 keywords, got: {seen_keywords}"
    print("[PASS] Injection rotation covers all 7 RED_FLAG_KEYWORDS")

    # ── Test 20: Followup questions all contain INV phrases ──────────
    seen_inv = set()
    for turn in range(7):
        result = _append_followup_question("Test.", turn_count=turn)
        for p in _INV_PHRASES:
            if p in result.lower():
                seen_inv.add(p)
    assert len(seen_inv) == 5, f"Followup must cover all 5 INV phrases, got: {seen_inv}"
    print("[PASS] Followup rotation covers all 5 _INV_PHRASES")

    print("\n=== ALL 20 VALIDATION TESTS PASSED ===")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
