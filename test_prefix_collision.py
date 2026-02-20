#!/usr/bin/env python3
"""
Prefix-Based Collision Resistance — Validation Test

SCENARIO (dense multi-artifact input — all 8 categories):
A single message containing phishing links, emails, UPI IDs, policy numbers,
order numbers, case IDs, bank account numbers, and phone numbers, deliberately
crafted to trigger every historical collision vector.

Validates:
 1. Ordered extraction: phishing → email → upi → policy → order → case → bank → phone
 2. Prefix-aware classification: POL- → policy, ORD- → order, SB- → case
 3. Span overlap prevention: no artifact captured twice
 4. UPI does not swallow emails (email runs BEFORE UPI)
 5. Phone numbers reject length > 12
"""

import json
import sys
sys.path.insert(0, '.')
from extractor import create_extractor

# ── SCENARIO ─────────────────────────────────────────────────────────────────
SCENARIO = (
    "Dear customer, your policy POL-8827 is expiring. "
    "Please verify at http://secure-banking-login.xyz/verify. "
    "Your order ORD-4491-AB is delayed — contact support@helpdesk.com. "
    "UPI refund sent to victim@ybl for case SB-3301. "
    "Bank account 50100012345678 debited. "
    "Call +919876543210 or email fraud@cyberpolice.gov.in. "
    "Ignore alerts from unknown@paytm and ref: SB-9922."
)

# ── EXPECTED RESULTS ─────────────────────────────────────────────────────────
EXPECTED = {
    "phishing_links":  ["http://secure-banking-login.xyz/verify"],
    "emails":          ["support@helpdesk.com", "fraud@cyberpolice.gov.in"],
    "upi_ids":         ["victim@ybl", "unknown@paytm"],
    "policy_numbers":  ["POL-8827"],
    "order_numbers":   ["ORD-4491-AB"],
    "case_ids":        ["SB-3301", "SB-9922"],
    "bank_accounts":   ["50100012345678"],
    "phone_numbers":   ["+919876543210"],
}


def run_test():
    extractor = create_extractor()
    result = extractor.extract(SCENARIO)
    
    passed = 0
    failed = 0
    
    def check(field, expected_values, actual_values):
        nonlocal passed, failed
        exp_set = set(expected_values)
        act_set = set(actual_values)
        
        missing = exp_set - act_set
        extra = act_set - exp_set
        
        if not missing and not extra:
            print(f"  ✅ {field}: {sorted(actual_values)}")
            passed += 1
        else:
            print(f"  ❌ {field}:")
            print(f"       expected: {sorted(exp_set)}")
            print(f"       actual:   {sorted(act_set)}")
            if missing:
                print(f"       missing:  {sorted(missing)}")
            if extra:
                print(f"       extra:    {sorted(extra)}")
            failed += 1
    
    print("=" * 70)
    print("PREFIX-BASED COLLISION RESISTANCE — VALIDATION TEST")
    print("=" * 70)
    print(f"\nSCENARIO:\n  {SCENARIO}\n")
    print("─" * 70)
    print("FIELD-BY-FIELD VALIDATION:\n")
    
    check("phishing_links",  EXPECTED["phishing_links"],  result.phishing_links)
    check("emails",          EXPECTED["emails"],           result.emails)
    check("upi_ids",         EXPECTED["upi_ids"],          result.upi_ids)
    check("policy_numbers",  EXPECTED["policy_numbers"],   result.policy_numbers)
    check("order_numbers",   EXPECTED["order_numbers"],    result.order_numbers)
    check("case_ids",        EXPECTED["case_ids"],         result.case_ids)
    
    # bank_accounts and phone_numbers return dicts — extract values for comparison
    actual_bank = [a.get('account_number', '') for a in result.bank_accounts]
    check("bank_accounts",   EXPECTED["bank_accounts"],    actual_bank)
    actual_phones = [p.get('number', '') for p in result.phone_numbers]
    check("phone_numbers",   EXPECTED["phone_numbers"],    actual_phones)
    
    # ── COLLISION CHECKS ─────────────────────────────────────────────────
    print("\n" + "─" * 70)
    print("COLLISION CHECKS:\n")
    
    # Email vs UPI: support@helpdesk.com must NOT appear in upi_ids
    if "support@helpdesk.com" not in result.upi_ids:
        print("  ✅ Email 'support@helpdesk.com' NOT swallowed by UPI")
        passed += 1
    else:
        print("  ❌ Email 'support@helpdesk.com' was incorrectly captured as UPI")
        failed += 1
    
    # UPI vs Email: victim@ybl must NOT appear in emails
    if "victim@ybl" not in result.emails:
        print("  ✅ UPI 'victim@ybl' NOT captured as email")
        passed += 1
    else:
        print("  ❌ UPI 'victim@ybl' was incorrectly captured as email")
        failed += 1
    
    # Bank vs Phone: 50100012345678 must NOT appear in phone_numbers
    actual_phone_nums = [p.get('number', '') for p in result.phone_numbers]
    if "50100012345678" not in actual_phone_nums:
        print("  ✅ Bank account NOT captured as phone number")
        passed += 1
    else:
        print("  ❌ Bank account '50100012345678' was incorrectly captured as phone")
        failed += 1
    
    # Prefix routing: POL-8827 ONLY in policy, NOT in case/order/generic
    pol_only_in_policy = (
        "POL-8827" in result.policy_numbers and
        "POL-8827" not in result.case_ids and
        "POL-8827" not in result.order_numbers and
        "POL-8827" not in result.generic_ids
    )
    if pol_only_in_policy:
        print("  ✅ 'POL-8827' routed exclusively to policy_numbers")
        passed += 1
    else:
        print("  ❌ 'POL-8827' leaked to wrong category")
        failed += 1
    
    # Prefix routing: ORD-4491-AB ONLY in orders
    ord_only_in_orders = (
        "ORD-4491-AB" in result.order_numbers and
        "ORD-4491-AB" not in result.case_ids and
        "ORD-4491-AB" not in result.generic_ids
    )
    if ord_only_in_orders:
        print("  ✅ 'ORD-4491-AB' routed exclusively to order_numbers")
        passed += 1
    else:
        print("  ❌ 'ORD-4491-AB' leaked to wrong category")
        failed += 1
    
    # Prefix routing: SB-3301 ONLY in case_ids
    sb_only_in_cases = (
        "SB-3301" in result.case_ids and
        "SB-3301" not in result.generic_ids
    )
    if sb_only_in_cases:
        print("  ✅ 'SB-3301' routed exclusively to case_ids")
        passed += 1
    else:
        print("  ❌ 'SB-3301' leaked to wrong category")
        failed += 1
    
    # ── PHONE LENGTH REJECT TEST ─────────────────────────────────────────
    print("\n" + "─" * 70)
    print("PHONE LENGTH VALIDATION:\n")
    
    # +919876543210 has 12 digits → should pass
    if "+919876543210" in actual_phone_nums:
        print("  ✅ +91 with 10 local digits (12 total) accepted")
        passed += 1
    else:
        print("  ❌ +91 with 10 local digits rejected incorrectly")
        failed += 1
    
    # Test: 13+ digit number should be rejected
    reject_test = extractor.extract("Call me on +9112345678901")
    reject_phone_nums = [p.get('number', '') for p in reject_test.phone_numbers]
    if "+9112345678901" not in reject_phone_nums:
        print("  ✅ 13-digit phone correctly rejected (>12)")
        passed += 1
    else:
        print("  ❌ 13-digit phone was NOT rejected")
        failed += 1
    
    # ── FINAL JSON OUTPUT ────────────────────────────────────────────────
    print("\n" + "─" * 70)
    print("FINAL JSON OUTPUT:\n")
    
    output = {
        "phishing_links":  result.phishing_links,
        "emails":          result.emails,
        "upi_ids":         result.upi_ids,
        "policy_numbers":  result.policy_numbers,
        "order_numbers":   result.order_numbers,
        "case_ids":        result.case_ids,
        "bank_accounts":   result.bank_accounts,
        "phone_numbers":   result.phone_numbers,
        "crypto_wallets":  result.crypto_wallets,
        "generic_ids":     result.generic_ids,
    }
    print(json.dumps(output, indent=2))
    
    # ── SUMMARY ──────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 70)
    
    return failed == 0


if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)
