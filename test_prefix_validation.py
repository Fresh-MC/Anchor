# Verification Test: Indian Mobile Prefix Validation
# Demonstrates fix for 10-digit phone/bank misclassification

import sys
sys.path.insert(0, '.')

from Anchor.extractor import ArtifactExtractor, IndianMobilePrefixValidator

def test_prefix_validator():
    """Test the Indian mobile prefix validator in isolation"""
    print("="*70)
    print("TEST 1: PREFIX VALIDATOR (DETERMINISTIC, OFFLINE)")
    print("="*70)
    
    test_cases = [
        ("9876543210", True, "Vodafone"),   # Vi prefix
        ("9012345678", True, "Other"),      # Other operator
        ("9400123456", True, "BSNL"),       # BSNL prefix
        ("8800123456", True, "Jio"),        # Jio prefix
        ("9999123456", True, "Airtel"),     # Airtel prefix
        ("5555555555", False, None),        # Invalid: starts with 5
        ("1234567890", False, None),        # Invalid: starts with 1
        ("9999",       False, None),        # Invalid: too short
    ]
    
    for number, expected_mobile, expected_carrier in test_cases:
        result = IndianMobilePrefixValidator.validate(number)
        carrier_str = result['carrier'] if result['carrier'] else "None"
        status = "✅" if result["is_mobile"] == expected_mobile else "❌"
        print(f"{status} {number:12} | Mobile: {str(result['is_mobile']):5} | Carrier: {carrier_str:10} | Reason: {result['reason']}")
    
    print()

def test_extraction_collision_scenario():
    """Test the original bug: phone misclassified as bank account"""
    print("="*70)
    print("TEST 2: COLLISION SCENARIO (ADVERSARIAL MESSAGE)")
    print("="*70)
    
    extractor = ArtifactExtractor()
    
    # ADVERSARIAL TEST CASE: Banking keywords + 10-digit mobile, no phone keywords
    message = "Sir urgent! Transfer amount to my account 9876543210 for verification. IFSC code HDFC0001234. Do immediately."
    
    print(f"Message: {message}\n")
    
    artifacts = extractor.extract(message)
    
    print("BEFORE FIX (Expected Behavior):")
    print("  bank_accounts: [{'account_number': '9876543210'}]")
    print("  phone_numbers: []\n")
    
    print("AFTER FIX (Actual Behavior):")
    print(f"  bank_accounts: {artifacts.bank_accounts}")
    print(f"  phone_numbers: {artifacts.phone_numbers}\n")
    
    # Verification
    has_phone = len(artifacts.phone_numbers) > 0
    has_bank = any(acc.get('account_number') == '9876543210' for acc in artifacts.bank_accounts)
    
    if has_phone and not has_bank:
        print("✅ PASS: 9876543210 correctly classified as PHONE (not bank account)")
        if artifacts.phone_numbers[0].get("carrier"):
            print(f"   Carrier: {artifacts.phone_numbers[0]['carrier']}")
            print(f"   Confidence: {artifacts.phone_numbers[0]['confidence']}")
    elif has_bank:
        print("❌ FAIL: 9876543210 misclassified as BANK ACCOUNT")
    else:
        print("⚠️  WARNING: Number not detected at all")
    
    print()

def test_whatsapp_style_evasion():
    """Test WhatsApp-style scam messages"""
    print("="*70)
    print("TEST 3: WHATSAPP-STYLE EVASION PATTERNS")
    print("="*70)
    
    extractor = ArtifactExtractor()
    
    test_messages = [
        "Bro transfer to 9988776655 account fast",
        "Send payment to 9012345678 urgently",
        "Click link and pay to 9876543210",
        "Account details: 9400123456 IFSC SBIN0001234",
    ]
    
    for msg in test_messages:
        artifacts = extractor.extract(msg)
        phones = artifacts.phone_numbers
        banks = artifacts.bank_accounts
        
        phone_nums = [p['number'] for p in phones] if phones else []
        bank_nums = [b.get('account_number', '') for b in banks]
        
        print(f"Message: {msg}")
        print(f"  Phones: {phone_nums}")
        print(f"  Banks:  {bank_nums}")
        
        # Check mutual exclusion
        all_10_digit_phones = [p['number'] for p in phones if len(p['number'].replace('+', '').replace('-', '').replace(' ', '')) == 10]
        all_10_digit_banks = [b for b in bank_nums if len(str(b)) == 10]
        
        overlap = set(all_10_digit_phones) & set(all_10_digit_banks)
        if overlap:
            print(f"  ❌ FAIL: Overlap detected: {overlap}")
        else:
            print(f"  ✅ PASS: No 10-digit overlap")
        print()

def test_legitimate_bank_accounts():
    """Ensure real bank accounts still work"""
    print("="*70)
    print("TEST 4: LEGITIMATE BANK ACCOUNT PRESERVATION")
    print("="*70)
    
    extractor = ArtifactExtractor()
    
    test_messages = [
        "Transfer to account 123456789012 IFSC HDFC0001234",  # 12-digit
        "Bank account 12345678901 IFSC code SBIN0001234",     # 11-digit
        "Wire to account 123456789 routing 021000021",        # 9-digit US
    ]
    
    for msg in test_messages:
        artifacts = extractor.extract(msg)
        banks = artifacts.bank_accounts
        
        print(f"Message: {msg}")
        print(f"  Bank accounts detected: {banks}")
        
        if banks:
            print(f"  ✅ PASS: Bank account extracted")
        else:
            print(f"  ❌ FAIL: Bank account not detected")
        print()

def test_phase1_safety():
    """Phase-1 safety check: No crashes, no silence"""
    print("="*70)
    print("TEST 5: PHASE-1 SAFETY (NO CRASHES, NO SILENCE)")
    print("="*70)
    
    extractor = ArtifactExtractor()
    
    edge_cases = [
        "",                           # Empty string
        "No numbers here",            # No artifacts
        "9" * 50,                     # Extremely long number
        "!@#$%^&*()",                 # Special characters only
        "9876543210" * 10,            # Repeated valid mobile
    ]
    
    all_passed = True
    for i, msg in enumerate(edge_cases, 1):
        try:
            artifacts = extractor.extract(msg)
            print(f"✅ Case {i}: No crash | Phones: {len(artifacts.phone_numbers)} | Banks: {len(artifacts.bank_accounts)}")
        except Exception as e:
            print(f"❌ Case {i}: CRASHED - {e}")
            all_passed = False
    
    if all_passed:
        print("\n✅ ALL EDGE CASES HANDLED SAFELY")
    else:
        print("\n❌ SOME EDGE CASES FAILED")
    
    print()

def test_forensic_metadata():
    """Test that forensic metadata is included"""
    print("="*70)
    print("TEST 6: FORENSIC METADATA (CARRIER, CONFIDENCE)")
    print("="*70)
    
    extractor = ArtifactExtractor()
    
    message = "Contact me at 9876543210 or 8800123456"
    artifacts = extractor.extract(message)
    
    print(f"Message: {message}\n")
    print("Extracted phones with metadata:")
    for phone in artifacts.phone_numbers:
        carrier_str = phone.get('carrier') if phone.get('carrier') else 'N/A'
        confidence = phone.get('confidence', 0.0)
        print(f"  Number: {phone['number']:15} | Carrier: {carrier_str:10} | Confidence: {confidence:.2f}")
    
    has_metadata = all(phone.get('carrier') is not None or phone.get('confidence') for phone in artifacts.phone_numbers)
    
    if has_metadata:
        print("\n✅ PASS: All phones include forensic metadata")
    else:
        print("\n❌ FAIL: Missing forensic metadata")
    
    print()

if __name__ == "__main__":
    print("\n" + "="*70)
    print(" INDIAN MOBILE PREFIX VALIDATION - FORENSIC PRECISION HARDENING")
    print("="*70 + "\n")
    
    test_prefix_validator()
    test_extraction_collision_scenario()
    test_whatsapp_style_evasion()
    test_legitimate_bank_accounts()
    test_phase1_safety()
    test_forensic_metadata()
    
    print("="*70)
    print(" TEST SUITE COMPLETE")
    print("="*70)
