# Artifact Extractor for ANCHOR API Mode
# Regex-based extraction of scammer artifacts (UPI, bank, phishing links)

"""
Artifact Extractor - Regex-Based Extraction
============================================
Extracts valuable scammer information from messages:
- UPI IDs (Indian payment identifiers)
- Bank account details (account numbers, IFSC, SWIFT)
- Phishing links (URLs, domains)
- Phone numbers
- Crypto wallet addresses

SECURITY: This runs AFTER state machine decision.
Extracted artifacts are logged but never sent to scammer.
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


# ═════════════════════════════════════════════════════════════════════════════
# INDIAN MOBILE PREFIX VALIDATOR (TRAI-COMPLIANT, OFFLINE)
# ═════════════════════════════════════════════════════════════════════════════

class IndianMobilePrefixValidator:
    """
    Deterministic, offline validator for Indian mobile numbers using TRAI prefix database.
    
    DESIGN:
    - O(1) lookup via frozenset membership
    - No external API calls (embedded dataset)
    - Forensically defensible (TRAI National Numbering Plan)
    
    PURPOSE:
    Prevent 10-digit mobile numbers from being misclassified as bank accounts.
    """
    
    # TRAI-allocated 4-digit Mobile Series Operator (MSO) prefixes
    # Source: TRAI National Numbering Plan 2024 + public carrier allocations
    # This is a curated subset of ~200 active prefixes
    INDIAN_MOBILE_PREFIXES = frozenset({
        # Airtel
        "9910", "9911", "9650", "9654", "9958", "9990", "9999", "9968",
        "8826", "8800", "7011", "7015", "7065", "7210", "7217", "7290",
        "7827", "7838", "8860", "8920", "9555", "9582", "9717", "9718",
        
        # Vodafone-Idea (Vi)
        "9812", "9815", "9816", "9817", "9818", "9819", "9820", "9821",
        "9867", "9868", "9869", "9920", "9921", "9922", "9923", "9924",
        "9925", "9926", "9927", "9928", "9929", "9930", "9931", "9960",
        "9961", "9962", "9963", "9964", "9965", "9966", "9967", "9969",
        "7410", "7411", "7412", "7567", "7568", "7737", "8000", "8291",
        
        # Jio
        "8800", "8801", "8802", "6299", "6300", "6301", "7400", "7401",
        "7500", "7501", "7700", "7701", "7977", "8900", "8901", "8902",
        "8903", "8904", "9115", "6350", "7000", "7050", "7051", "8850",
        
        # BSNL
        "9400", "9401", "9402", "9403", "9404", "9405", "9406", "9407",
        "9408", "9409", "9410", "9411", "9412", "9413", "9414", "9415",
        "9416", "9417", "9418", "9419", "9420", "9421", "9422", "9423",
        "9424", "9425", "9426", "9427", "9428", "9429", "7896", "8004",
        
        # MTNL
        "9650", "9810", "9811", "9818",
        
        # Other operators (Aircel legacy, regional, etc.)
        "9012", "9014", "9016", "9040", "9041", "9042", "9043", "9044",
        "9045", "9046", "9047", "9048", "9049", "9876", "9877", "9878",
        "9879", "9880", "9881", "9882", "9883", "9884", "9885", "9886",
        "9887", "9888", "9889", "9890", "9891", "9892", "9893", "9894",
        "9895", "9896", "9897", "9898", "9899", "9900", "9901", "9902",
        "7200", "7201", "7202", "7800", "8100", "8200", "8300", "8400",
        "8500", "8600", "8700", "9000", "9001", "9100", "9200", "9300",
        
        # Extended coverage (starts with 6/7/8/9 - common patterns)
        "6000", "6200", "6201", "6280", "6281", "7008", "7600", "8010",
    })
    
    # Carrier mapping for forensic metadata
    CARRIER_MAP = {
        "9910": "Airtel", "9911": "Airtel", "9650": "Airtel", "9654": "Airtel",
        "9958": "Airtel", "9990": "Airtel", "9999": "Airtel", "8826": "Airtel",
        "8800": "Jio", "8801": "Jio", "8802": "Jio", "6299": "Jio",
        "6300": "Jio", "7400": "Jio", "7500": "Jio", "7700": "Jio",
        "9812": "Vi", "9815": "Vi", "9816": "Vi", "9867": "Vi",
        "9400": "BSNL", "9401": "BSNL", "9402": "BSNL", "9403": "BSNL",
        "9810": "MTNL", "9811": "MTNL",
    }
    
    @classmethod
    def validate(cls, number: str) -> Dict[str, Any]:
        """
        Validate if 10-digit number is an Indian mobile.
        
        Args:
            number: Normalized 10-digit string (digits only)
            
        Returns:
            {
                "is_mobile": bool,
                "carrier": str | None,
                "confidence": float (0.0-1.0),
                "prefix": str,
                "reason": str
            }
        """
        # Structural validation
        if len(number) != 10:
            return {
                "is_mobile": False,
                "carrier": None,
                "confidence": 0.0,
                "prefix": "",
                "reason": "LENGTH_INVALID"
            }
        
        # First digit must be 6/7/8/9 per TRAI
        if number[0] not in "6789":
            return {
                "is_mobile": False,
                "carrier": None,
                "confidence": 0.0,
                "prefix": number[:4] if len(number) >= 4 else "",
                "reason": "FIRST_DIGIT_INVALID"
            }
        
        # Extract 4-digit MSO prefix
        prefix = number[:4]
        
        # O(1) frozenset lookup
        if prefix in cls.INDIAN_MOBILE_PREFIXES:
            carrier = cls.CARRIER_MAP.get(prefix, "Other")
            return {
                "is_mobile": True,
                "carrier": carrier,
                "confidence": 0.99,
                "prefix": prefix,
                "reason": "TRAI_PREFIX_MATCH"
            }
        
        # Unknown prefix but structurally valid (6/7/8/9 start)
        # Conservative: reject to avoid false positives
        return {
            "is_mobile": False,
            "carrier": None,
            "confidence": 0.4,  # Low confidence
            "prefix": prefix,
            "reason": "PREFIX_NOT_IN_DATASET"
        }


# ═════════════════════════════════════════════════════════════════════════════
# SPAN-BASED COLLISION PREVENTION
# ═════════════════════════════════════════════════════════════════════════════

class _SpanTracker:
    """
    Tracks character‐position spans of already‐captured matches.
    
    Before accepting a new regex match, callers check `try_claim(start, end)`.
    If the proposed span overlaps ANY previously claimed span, the match is
    rejected — eliminating cross‐extractor collisions (e.g. phone regex
    re‐capturing digits already claimed as a bank account number).
    
    All spans are half‐open: [start, end).
    """

    __slots__ = ('_spans',)

    def __init__(self):
        self._spans: list = []          # list of (start, end) tuples

    def is_overlapping(self, start: int, end: int) -> bool:
        """Return True if [start, end) overlaps any existing span."""
        for s, e in self._spans:
            if start < e and end > s:
                return True
        return False

    def add(self, start: int, end: int) -> None:
        """Register a span unconditionally."""
        self._spans.append((start, end))

    def try_claim(self, start: int, end: int) -> bool:
        """Claim [start, end) if it does NOT overlap. Returns True on success."""
        if self.is_overlapping(start, end):
            return False
        self._spans.append((start, end))
        return True


@dataclass
class ExtractedArtifacts:
    """Container for all extracted artifacts"""
    upi_ids: List[str] = field(default_factory=list)
    bank_accounts: List[Dict[str, str]] = field(default_factory=list)
    phishing_links: List[str] = field(default_factory=list)
    phone_numbers: List[Dict[str, Any]] = field(default_factory=list)  # Now includes carrier metadata
    crypto_wallets: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    case_ids: List[str] = field(default_factory=list)
    policy_numbers: List[str] = field(default_factory=list)
    order_numbers: List[str] = field(default_factory=list)
    generic_ids: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, List]:
        """Convert to dictionary for JSON response"""
        return {
            "upi_ids": self.upi_ids,
            "bank_accounts": self.bank_accounts,
            "phishing_links": self.phishing_links,
            "phone_numbers": self.phone_numbers,
            "crypto_wallets": self.crypto_wallets,
            "emails": self.emails,
            "case_ids": self.case_ids,
            "policy_numbers": self.policy_numbers,
            "order_numbers": self.order_numbers,
            "generic_ids": self.generic_ids,
        }
    
    def has_artifacts(self) -> bool:
        """Check if any artifacts were extracted"""
        return any([
            self.upi_ids,
            self.bank_accounts,
            self.phishing_links,
            self.phone_numbers,
            self.crypto_wallets,
            self.emails,
            self.case_ids,
            self.policy_numbers,
            self.order_numbers,
            self.generic_ids,
        ])
    
    def merge(self, other: 'ExtractedArtifacts') -> None:
        """Merge artifacts from another extraction (deduplicated)"""
        self.upi_ids = list(set(self.upi_ids + other.upi_ids))
        self.phishing_links = list(set(self.phishing_links + other.phishing_links))
        self.crypto_wallets = list(set(self.crypto_wallets + other.crypto_wallets))
        self.emails = list(set(self.emails + other.emails))
        self.case_ids = list(set(self.case_ids + other.case_ids))
        self.policy_numbers = list(set(self.policy_numbers + other.policy_numbers))
        self.order_numbers = list(set(self.order_numbers + other.order_numbers))
        self.generic_ids = list(set(self.generic_ids + other.generic_ids))
        
        # Phone numbers need special handling (now dicts with metadata)
        existing_phone_numbers = {p.get("number", p) if isinstance(p, dict) else p for p in self.phone_numbers}
        for phone in other.phone_numbers:
            phone_num = phone.get("number", phone) if isinstance(phone, dict) else phone
            if phone_num not in existing_phone_numbers:
                self.phone_numbers.append(phone)
        
        # Bank accounts need special handling (dicts)
        existing_accounts = {str(a) for a in self.bank_accounts}
        for account in other.bank_accounts:
            if str(account) not in existing_accounts:
                self.bank_accounts.append(account)


class ArtifactExtractor:
    """
    Regex-based artifact extractor.
    
    Extracts scammer contact points and payment methods
    for evidence collection and reporting.
    """
    
    def __init__(self):
        # Initialize Indian mobile prefix validator
        self._mobile_validator = IndianMobilePrefixValidator()
        
        # UPI patterns (Indian payment system)
        self._upi_patterns = [
            re.compile(r'\b([a-zA-Z0-9.\-_]+@[a-zA-Z0-9]+)\b'),  # generic UPI (user@bank, user@123pay)
            re.compile(r'\b([a-zA-Z0-9._-]+@(?:paytm|gpay|phonepe|ybl|okaxis|oksbi|okhdfcbank|axl|ibl|upi|apl|fbl|boi|kotak|sbi|icici|hdfcbank|airtel|jio|postbank|unionbank|pnb|bob|canara|idbi|rbl|indus|federal|jupiter|kbl|freecharge|mobikwik|slice|cred|amazonpay|abfspay|waicici|wahdfcbank|wasbi|waaxis|niyopay|dlb|equitas|fino|aubank|tmb|dbs|kvb|hsbc|sc|citi|baroda|mahb|pockets|dhani|groww|fi|niyo|payzapp))\b', re.IGNORECASE),
        ]

        # Known email domains (excluded from UPI detection)
        self._email_domains = frozenset({
            'gmail', 'yahoo', 'outlook', 'hotmail', 'aol', 'icloud', 'protonmail',
            'mail', 'email', 'msn', 'live', 'tutanota', 'zoho', 'yandex', 'gmx',
            'rediffmail', 'inbox', 'rocketmail', 'pm', 'fastmail', 'hey',
        })
        
        # Bank account patterns
        self._bank_patterns = {
            'account_number': re.compile(r'\b(\d{11,18})\b'),  # 11-18 digits (>=11 disambiguates from 10-digit phones)
            'ifsc': re.compile(r'\b([A-Z]{4}0[A-Z0-9]{6})\b'),  # Indian IFSC
            'swift': re.compile(r'\b([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b'),  # SWIFT/BIC
            'routing': re.compile(r'\brouting[:\s#]*(\d{9})\b', re.IGNORECASE),  # US routing
            'iban': re.compile(r'\b([A-Z]{2}\d{2}[A-Z0-9]{4,30})\b'),  # IBAN
        }
        
        # URL/Link patterns
        self._url_patterns = [
            re.compile(r'(https?://[^\s<>"{}|\\^`\[\]]+)', re.IGNORECASE),
            re.compile(r'(www\.[^\s<>"{}|\\^`\[\]]+)', re.IGNORECASE),
            re.compile(r'\b([a-zA-Z0-9-]+\.(?:com|org|net|in|co|io|xyz|info|biz|tk|ml|ga|cf|gq|top|online|site|website|link|click|ru|cn|ng|ph|vn|pw|ws|cc|buzz|work|live|me|pro|app|dev|page|shop|store|support|help|win|review|cloud|finance|bank|pay|secure|verify|login|update|alert)(?:/[^\s]*)?)', re.IGNORECASE),
        ]
        
        # Phone number patterns — collision-safe (Part 4)
        # REMOVED: ultra-greedy pattern that matched up to 14+ digits
        # Rule: exactly 10 digits (India) OR +91/+country prefix
        self._phone_patterns = [
            re.compile(r'(?<!\w)(\+91[-.\s]?\d{10})(?!\d)'),  # India +91 prefix
            re.compile(r'(?<!\w)(\+\d{1,3}[-.\s]?\d{7,10})(?!\d)'),  # International with country code (max 10 local digits)
            re.compile(r'\b(\d{10})\b'),  # Bare 10-digit (strict TRAI validation + context required)
        ]
        
        # Crypto wallet patterns
        self._crypto_patterns = [
            re.compile(r'\b(1[a-km-zA-HJ-NP-Z1-9]{25,34})\b'),  # Bitcoin
            re.compile(r'\b(3[a-km-zA-HJ-NP-Z1-9]{25,34})\b'),  # Bitcoin (P2SH)
            re.compile(r'\b(bc1[a-zA-HJ-NP-Z0-9]{25,90})\b'),  # Bitcoin (Bech32)
            re.compile(r'\b(0x[a-fA-F0-9]{40})\b'),  # Ethereum
            re.compile(r'\b(T[A-Za-z1-9]{33})\b'),  # Tron
        ]
        
        # Email patterns
        self._email_pattern = re.compile(
            r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'
        )
        
        # ── ID patterns (Part 3 — collision-resistant) ────────────────────
        # STRUCTURAL patterns (anchored to ID token, no prefix-word capture)
        self._structural_case_id = re.compile(r'\b([A-Z]{2,}-\d{3,})\b')
        self._structural_order = re.compile(r'\b(ORD-\d{3,}(?:-[A-Z0-9]+)?)\b')
        self._structural_policy = re.compile(r'\b(POL-\d{4,})\b')
        
        # CONTEXT-AWARE fallbacks (capture group is the ID only, never the prefix word)
        self._context_case_id = re.compile(
            r'(?i)(?:case|ref(?:erence)?)\s*[#:\-]+\s*([A-Z0-9][-A-Z0-9]+)', re.IGNORECASE
        )
        self._context_policy = re.compile(
            r'(?i)policy\s*[#:\-]+\s*([A-Z0-9][-A-Z0-9]+)', re.IGNORECASE
        )
        self._context_order = re.compile(
            r'(?i)order\s*[#:\-]+\s*([A-Z0-9][-A-Z0-9]+)', re.IGNORECASE
        )
        
        # Generic formal ID fallback (e.g., ABC-123, CASE-2024-001)
        # Conservative: must start with letter, contain hyphen, uppercase only
        self._generic_id_pattern = re.compile(
            r'\b([A-Z][A-Z0-9]*-[A-Z0-9](?:[A-Z0-9\-]*[A-Z0-9])?)\b'
        )
        
        # Known scam domains (for flagging)
        self._suspicious_domains = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',  # Shorteners
            'is.gd', 'rb.gy', 'cutt.ly', 'shorturl.at',  # More shorteners
            'paytm.link', 'gpay.link',  # Fake payment
            'secure-login', 'verify-account', 'update-info',  # Phishing fragments
        }

        # Suspicious scam-related keywords for extraction
        self._suspicious_keywords = [
            # Urgency
            "urgent", "immediately", "hurry", "deadline", "expire",
            # Authority / threat
            "officer", "police", "arrest", "warrant", "court", "legal",
            "penalty", "fraud", "illegal", "lawsuit",
            # Account / banking
            "account", "bank", "upi", "transfer", "payment", "wire",
            "blocked", "suspended", "restricted", "locked", "compromised",
            "unauthorized", "hacked", "terminated",
            # Financial lures
            "refund", "prize", "lottery", "winner", "reward",
            # Credentials
            "verify", "confirm", "password", "otp", "pin", "ssn",
            # Tech scam
            "virus", "malware", "infected", "secure",
            # Action
            "click", "download", "install",
            # Payment methods
            "bitcoin", "crypto", "gift card",
        ]
    
    def extract(self, text: str) -> ExtractedArtifacts:
        """
        Extract all artifacts from text using span-based collision prevention.
        
        DETERMINISTIC ORDER (highest-to-lowest priority):
        1. Phishing Links   — most distinctive patterns
        2. UPI IDs           — @-delimited, low collision risk
        3. Case / Policy / Order / Generic IDs — alpha-numeric with hyphens
        4. Bank Accounts     — 11-18 digit numbers (>= 11 disambiguates from phones)
        5. Crypto Wallets    — alphanumeric with structural prefixes
        6. Emails            — user@domain.tld
        7. Phone Numbers     — LAST (most collision-prone, 10-digit only)
        
        Each extractor claims character spans. Later extractors cannot
        re-capture text already claimed by an earlier extractor.
        """
        artifacts = ExtractedArtifacts()
        spans = _SpanTracker()
        
        # ── 1. Phishing Links ──────────────────────────────────────────
        try:
            artifacts.phishing_links = self._extract_urls(text, spans)
        except Exception:
            artifacts.phishing_links = []
        
        # ── 2. UPI IDs ─────────────────────────────────────────────────
        try:
            artifacts.upi_ids = self._extract_upi(text, spans)
        except Exception:
            artifacts.upi_ids = []
        
        # ── 3. Case / Policy / Order / Generic IDs ─────────────────────
        try:
            artifacts.case_ids = self._extract_case_ids(text, spans)
        except Exception:
            artifacts.case_ids = []
        
        try:
            artifacts.policy_numbers = self._extract_policy_numbers(text, spans)
        except Exception:
            artifacts.policy_numbers = []
        
        try:
            artifacts.order_numbers = self._extract_order_numbers(text, spans)
        except Exception:
            artifacts.order_numbers = []
        
        try:
            already_captured = set(artifacts.case_ids + artifacts.policy_numbers + artifacts.order_numbers)
            artifacts.generic_ids = self._extract_generic_ids(text, spans, already_captured)
        except Exception:
            artifacts.generic_ids = []
        
        # ── 4. Bank Accounts ───────────────────────────────────────────
        try:
            artifacts.bank_accounts = self._extract_bank_details(text, spans)
        except Exception:
            artifacts.bank_accounts = []
        
        # ── 5. Crypto Wallets ──────────────────────────────────────────
        try:
            artifacts.crypto_wallets = self._extract_crypto(text, spans)
        except Exception:
            artifacts.crypto_wallets = []
        
        # ── 6. Emails ──────────────────────────────────────────────────
        try:
            artifacts.emails = self._extract_emails(text, exclude=artifacts.upi_ids, spans=spans)
        except Exception:
            artifacts.emails = []
        
        # ── 7. Phone Numbers (LAST — most collision-prone) ─────────────
        try:
            artifacts.phone_numbers = self._extract_phones(text, spans)
        except Exception:
            artifacts.phone_numbers = []
        
        return artifacts

    def extract_suspicious_keywords(self, text: str) -> List[str]:
        """
        Extract suspicious scam-related keywords from text.
        Returns lowercase, deduplicated list of matched keywords.
        """
        text_lower = text.lower()
        return [kw for kw in self._suspicious_keywords if kw in text_lower]

    def _extract_upi(self, text: str, spans: _SpanTracker) -> List[str]:
        """Extract UPI IDs (excludes known email domains). Claims spans."""
        upi_ids = set()
        for pattern in self._upi_patterns:
            for match in pattern.finditer(text):
                if not spans.try_claim(match.start(), match.end()):
                    continue
                upi_id = match.group(1).lower()
                # Validate UPI format (user@provider)
                if '@' in upi_id:
                    parts = upi_id.split('@')
                    handle = parts[0]
                    domain = parts[1]
                    # Valid UPI: handle >= 2 chars, domain not a known email domain
                    if len(handle) >= 2 and domain not in self._email_domains:
                        upi_ids.add(upi_id)
        return list(upi_ids)
    
    def _extract_bank_details(self, text: str, spans: _SpanTracker) -> List[Dict[str, str]]:
        """Extract bank account details with context validation (global matching, span-aware)."""
        text_lower = text.lower()
        
        # Require banking context within the message to accept account numbers
        banking_context = any(kw in text_lower for kw in [
            "account", "acct", "a/c", "beneficiary", "transfer",
            "ifsc", "swift", "routing", "iban", "bank", "wire",
            "neft", "rtgs", "imps", "deposit", "withdraw", "credit",
            "debit", "saving", "current", "cheque", "check",
            "remittance", "passbook", "ledger", "statement",
        ])
        
        # Global matching using finditer — captures ALL occurrences
        valid_nums = []
        if banking_context:
            for m in self._bank_patterns['account_number'].finditer(text):
                # Span collision check
                if not spans.try_claim(m.start(), m.end()):
                    continue
                num = m.group(1)
                # Part 5: ≥11 digits guaranteed by regex \d{11,18}
                # Filter non-account patterns (no leading 0000, min entropy)
                if not num.startswith('0000') and len(set(num)) > 2:
                    valid_nums.append(num)
        
        ifsc_codes = [m.group(1) for m in self._bank_patterns['ifsc'].finditer(text)]
        swift_codes = [m.group(1) for m in self._bank_patterns['swift'].finditer(text)
                       if len(m.group(1)) in (8, 11)]
        routing_nums = [m.group(1) for m in self._bank_patterns['routing'].finditer(text)]
        iban_nums = [m.group(1) for m in self._bank_patterns['iban'].finditer(text)
                     if 15 <= len(m.group(1)) <= 34]
        
        # Deduplicate each list while preserving order
        valid_nums = list(dict.fromkeys(valid_nums))
        ifsc_codes = list(dict.fromkeys(ifsc_codes))
        swift_codes = list(dict.fromkeys(swift_codes))
        routing_nums = list(dict.fromkeys(routing_nums))
        iban_nums = list(dict.fromkeys(iban_nums))
        
        # Build account entries — one per account number
        accounts = []
        for num in valid_nums:
            accounts.append({"account_number": num})
        
        # Attach structural codes to account entries, or create standalone
        for key, values in [("ifsc", ifsc_codes), ("swift", swift_codes),
                            ("routing_number", routing_nums), ("iban", iban_nums)]:
            for val in values:
                attached = False
                for acct in accounts:
                    if key not in acct:
                        acct[key] = val
                        attached = True
                        break
                if not attached:
                    accounts.append({key: val})
        
        return accounts
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL by removing protocol and trailing slashes"""
        url = url.lower()
        # Remove protocol
        url = re.sub(r'^https?://', '', url)
        # Remove www.
        url = re.sub(r'^www\.', '', url)
        # Remove trailing slash
        url = url.rstrip('/')
        return url
    
    def _extract_urls(self, text: str, spans: _SpanTracker) -> List[str]:
        """Extract URLs and potential phishing links (deduplicated, normalized, span-aware)"""
        raw_urls = {}  # url_text -> match for dedup
        
        for pattern in self._url_patterns:
            for match in pattern.finditer(text):
                # Span collision check
                if not spans.try_claim(match.start(), match.end()):
                    continue
                url = match.group(1)
                # Skip if preceded by @ (part of an email address)
                start_pos = match.start(1)
                if start_pos > 0 and text[start_pos - 1] == '@':
                    continue
                # Clean and normalize
                url = url.rstrip('.,;:!?)')
                if len(url) > 8:  # Minimum meaningful URL length
                    raw_urls[url] = True
        
        # Deduplicate by normalized form (remove http/https duplicates)
        normalized_map = {}
        for url in raw_urls:
            norm = self._normalize_url(url)
            # Keep the most complete version (with protocol if available)
            if norm not in normalized_map:
                normalized_map[norm] = url
            elif url.startswith('http'):
                normalized_map[norm] = url
        
        return list(normalized_map.values())
    
    def _extract_phones(self, text: str, spans: _SpanTracker) -> List[Dict[str, Any]]:
        """
        Extract phone numbers with strict collision-safe rules (Part 4).
        
        Rules:
        - Exactly 10 digits after normalization (India) OR explicit +91/+country prefix
        - Bare ≥11 digits are NEVER phones (→ bank accounts)
        - Span check: reject any match overlapping a previously claimed span
        - TRAI prefix validation for 10-digit Indian numbers
        """
        text_lower = text.lower()
        # Only accept bare 10-digit if phone context present OR prefix validates
        has_phone_context = any(kw in text_lower for kw in [
            "call", "phone", "number", "mobile", "contact", "dial", "reach",
            "whatsapp", "sms", "text", "msg", "ring",
        ])
        
        seen_normalized = {}  # normalized_digits -> phone_object
        
        for i, pattern in enumerate(self._phone_patterns):
            for match in pattern.finditer(text):
                # ── Span collision check ──
                if not spans.try_claim(match.start(), match.end()):
                    continue  # Already claimed by a higher-priority extractor
                
                phone = match.group(1)
                normalized = re.sub(r'[-.\s()]', '', phone)
                
                # Reject bare digits with ≥ 11 digits — those are bank accounts
                if normalized.isdigit() and len(normalized) >= 11:
                    continue
                
                # ANY 10-digit all-numeric → check TRAI Indian mobile validation
                if len(normalized) == 10 and normalized.isdigit():
                    validation = self._mobile_validator.validate(normalized)
                    
                    if validation["is_mobile"]:
                        # TRAI prefix match → store as +91 number (dedup across patterns)
                        prefixed = "+91" + normalized
                        if prefixed not in seen_normalized:
                            seen_normalized[prefixed] = {
                                "number": prefixed,
                                "carrier": validation["carrier"],
                                "confidence": validation["confidence"],
                            }
                        continue  # Don't also store bare 10-digit
                    elif i == 2 and not has_phone_context:
                        # Bare 10-digit pattern (index 2), unknown prefix, no phone context → reject
                        continue
                    else:
                        # Non-TRAI but has phone context or explicit format → still Indian mobile, add +91
                        if normalized[0] in '6789':
                            prefixed = "+91" + normalized
                            if prefixed not in seen_normalized:
                                seen_normalized[prefixed] = {
                                    "number": prefixed,
                                    "carrier": None,
                                    "confidence": 0.7,
                                }
                            continue
                
                # Non-10-digit or explicit format (+91, international)
                if 10 <= len(normalized) <= 15:
                    if normalized not in seen_normalized:
                        seen_normalized[normalized] = {
                            "number": normalized,
                            "carrier": None,
                            "confidence": 0.95,  # Explicit format
                        }
        
        return list(seen_normalized.values())
    
    def _extract_crypto(self, text: str, spans: _SpanTracker) -> List[str]:
        """Extract cryptocurrency wallet addresses with span collision prevention"""
        wallets = set()
        
        for pattern in self._crypto_patterns:
            for match in pattern.finditer(text):
                if not spans.try_claim(match.start(), match.end()):
                    continue
                wallet = match.group(1)
                wallets.add(wallet)
        
        return list(wallets)
    
    def _extract_emails(self, text: str, exclude: Optional[List[str]] = None, spans: _SpanTracker = None) -> List[str]:
        """Extract email addresses (excluding UPI IDs) with span collision prevention"""
        exclude = exclude or []
        exclude_lower = {e.lower() for e in exclude}
        
        emails = set()
        for match in self._email_pattern.finditer(text):
            if spans and not spans.try_claim(match.start(), match.end()):
                continue
            email = match.group(1).lower()
            # Exclude UPI IDs (they look like emails)
            if email not in exclude_lower:
                # Also exclude common UPI domains
                domain = email.split('@')[1] if '@' in email else ''
                upi_domains = {'paytm', 'gpay', 'phonepe', 'ybl', 'okaxis', 'oksbi', 'okhdfcbank', 'axl', 'ibl', 'upi'}
                if domain not in upi_domains:
                    emails.add(email)
        
        return list(emails)
    
    def _extract_case_ids(self, text: str, spans: _SpanTracker) -> List[str]:
        """Extract case/reference IDs using structural + context-aware patterns with span collision prevention"""
        ids = set()
        # Structural pattern first (e.g., ABC-123)
        for m in self._structural_case_id.finditer(text):
            if not spans.try_claim(m.start(), m.end()):
                continue
            val = m.group(1).strip('-')
            if len(val) >= 2:
                ids.add(val)
        # Context-aware fallback (e.g., case: 12345)
        for m in self._context_case_id.finditer(text):
            if not spans.try_claim(m.start(), m.end()):
                continue
            val = m.group(1).strip('-')
            if len(val) >= 2 and val not in ids:
                ids.add(val)
        return list(ids)
    
    def _extract_policy_numbers(self, text: str, spans: _SpanTracker) -> List[str]:
        """Extract policy numbers using structural + context-aware patterns with span collision prevention"""
        ids = set()
        # Structural pattern first (e.g., POL-1234)
        for m in self._structural_policy.finditer(text):
            if not spans.try_claim(m.start(), m.end()):
                continue
            val = m.group(1).strip('-')
            if len(val) >= 2:
                ids.add(val)
        # Context-aware fallback (e.g., policy: 12345)
        for m in self._context_policy.finditer(text):
            if not spans.try_claim(m.start(), m.end()):
                continue
            val = m.group(1).strip('-')
            if len(val) >= 2 and val not in ids:
                ids.add(val)
        return list(ids)
    
    def _extract_order_numbers(self, text: str, spans: _SpanTracker) -> List[str]:
        """Extract order numbers using structural + context-aware patterns with span collision prevention"""
        ids = set()
        # Structural pattern first (e.g., ORD-456)
        for m in self._structural_order.finditer(text):
            if not spans.try_claim(m.start(), m.end()):
                continue
            val = m.group(1).strip('-')
            if len(val) >= 2:
                ids.add(val)
        # Context-aware fallback (e.g., order: 12345)
        for m in self._context_order.finditer(text):
            if not spans.try_claim(m.start(), m.end()):
                continue
            val = m.group(1).strip('-')
            if len(val) >= 2 and val not in ids:
                ids.add(val)
        return list(ids)
    
    def _extract_generic_ids(self, text: str, spans: _SpanTracker, already_captured: set = None) -> List[str]:
        """
        Extract generic formal ID-like strings (e.g., ABC-123, CASE-2024-001).
        Conservative: requires uppercase start, hyphen, min 5 chars.
        Excludes IDs already captured by context-aware extractors.
        Uses span collision prevention.
        """
        already_captured = already_captured or set()
        ids = set()
        for m in self._generic_id_pattern.finditer(text):
            if not spans.try_claim(m.start(), m.end()):
                continue
            val = m.group(1)
            # Minimum length to reduce false positives
            if len(val) >= 5 and val not in already_captured:
                ids.add(val)
        return list(ids)
    
    def is_suspicious_url(self, url: str) -> bool:
        """Check if URL is from known suspicious domain"""
        url_lower = url.lower()
        for domain in self._suspicious_domains:
            if domain in url_lower:
                return True
        return False


def create_extractor() -> ArtifactExtractor:
    """Factory function"""
    return ArtifactExtractor()
