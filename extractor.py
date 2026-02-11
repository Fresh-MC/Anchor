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


@dataclass
class ExtractedArtifacts:
    """Container for all extracted artifacts"""
    upi_ids: List[str] = field(default_factory=list)
    bank_accounts: List[Dict[str, str]] = field(default_factory=list)
    phishing_links: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    crypto_wallets: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, List]:
        """Convert to dictionary for JSON response"""
        return {
            "upi_ids": self.upi_ids,
            "bank_accounts": self.bank_accounts,
            "phishing_links": self.phishing_links,
            "phone_numbers": self.phone_numbers,
            "crypto_wallets": self.crypto_wallets,
            "emails": self.emails,
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
        ])
    
    def merge(self, other: 'ExtractedArtifacts') -> None:
        """Merge artifacts from another extraction (deduplicated)"""
        self.upi_ids = list(set(self.upi_ids + other.upi_ids))
        self.phishing_links = list(set(self.phishing_links + other.phishing_links))
        self.phone_numbers = list(set(self.phone_numbers + other.phone_numbers))
        self.crypto_wallets = list(set(self.crypto_wallets + other.crypto_wallets))
        self.emails = list(set(self.emails + other.emails))
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
        # UPI patterns (Indian payment system)
        self._upi_patterns = [
            re.compile(r'\b([a-zA-Z0-9._-]+@[a-zA-Z]{3,})\b'),  # user@bank
            re.compile(r'\b([a-zA-Z0-9._-]+@(?:paytm|gpay|phonepe|ybl|okaxis|oksbi|okhdfcbank|axl|ibl|upi))\b', re.IGNORECASE),
        ]
        
        # Bank account patterns
        self._bank_patterns = {
            'account_number': re.compile(r'\b(\d{9,18})\b'),  # 9-18 digit account numbers
            'ifsc': re.compile(r'\b([A-Z]{4}0[A-Z0-9]{6})\b'),  # Indian IFSC
            'swift': re.compile(r'\b([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b'),  # SWIFT/BIC
            'routing': re.compile(r'\brouting[:\s#]*(\d{9})\b', re.IGNORECASE),  # US routing
            'iban': re.compile(r'\b([A-Z]{2}\d{2}[A-Z0-9]{4,30})\b'),  # IBAN
        }
        
        # URL/Link patterns
        self._url_patterns = [
            re.compile(r'(https?://[^\s<>"{}|\\^`\[\]]+)', re.IGNORECASE),
            re.compile(r'(www\.[^\s<>"{}|\\^`\[\]]+)', re.IGNORECASE),
            re.compile(r'\b([a-zA-Z0-9-]+\.(?:com|org|net|in|co|io|xyz|info|biz|tk|ml|ga|cf|gq|top|online|site|website|link|click)(?:/[^\s]*)?)\b', re.IGNORECASE),
        ]
        
        # Phone number patterns (international)
        self._phone_patterns = [
            re.compile(r'\b(\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b'),  # US/Canada
            re.compile(r'\b(\+91[-.\s]?\d{10})\b'),  # India
            re.compile(r'\b(\+\d{1,3}[-.\s]?\d{6,14})\b'),  # International
            re.compile(r'\b(\d{10})\b'),  # 10-digit (contextual)
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
        
        # Known scam domains (for flagging)
        self._suspicious_domains = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',  # Shorteners
            'paytm.link', 'gpay.link',  # Fake payment
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
        Extract all artifacts from text.
        
        Args:
            text: Message text to analyze
            
        Returns:
            ExtractedArtifacts with all findings
        """
        artifacts = ExtractedArtifacts()
        
        # Extract UPI IDs
        artifacts.upi_ids = self._extract_upi(text)
        
        # Extract bank details
        artifacts.bank_accounts = self._extract_bank_details(text)
        
        # Extract URLs/links
        artifacts.phishing_links = self._extract_urls(text)
        
        # Extract phone numbers
        artifacts.phone_numbers = self._extract_phones(text)
        
        # Extract crypto wallets
        artifacts.crypto_wallets = self._extract_crypto(text)
        
        # Extract emails (excluding UPI IDs)
        artifacts.emails = self._extract_emails(text, exclude=artifacts.upi_ids)
        
        return artifacts

    def extract_suspicious_keywords(self, text: str) -> List[str]:
        """
        Extract suspicious scam-related keywords from text.
        Returns lowercase, deduplicated list of matched keywords.
        """
        text_lower = text.lower()
        return [kw for kw in self._suspicious_keywords if kw in text_lower]

    def _extract_upi(self, text: str) -> List[str]:
        """Extract UPI IDs"""
        upi_ids = set()
        for pattern in self._upi_patterns:
            for match in pattern.finditer(text):
                upi_id = match.group(1).lower()
                # Validate UPI format (user@provider)
                if '@' in upi_id and len(upi_id.split('@')[0]) >= 3:
                    upi_ids.add(upi_id)
        return list(upi_ids)
    
    def _extract_bank_details(self, text: str) -> List[Dict[str, str]]:
        """Extract bank account details"""
        accounts = []
        
        # Look for account numbers with context
        account_match = self._bank_patterns['account_number'].search(text)
        ifsc_match = self._bank_patterns['ifsc'].search(text)
        swift_match = self._bank_patterns['swift'].search(text)
        routing_match = self._bank_patterns['routing'].search(text)
        iban_match = self._bank_patterns['iban'].search(text)
        
        # Build account object if we have enough info
        account = {}
        
        if account_match:
            num = account_match.group(1)
            # Filter out likely non-account numbers
            if len(num) >= 9 and not num.startswith('0000'):
                account['account_number'] = num
        
        if ifsc_match:
            account['ifsc'] = ifsc_match.group(1)
        
        if swift_match:
            account['swift'] = swift_match.group(1)
        
        if routing_match:
            account['routing_number'] = routing_match.group(1)
        
        if iban_match:
            account['iban'] = iban_match.group(1)
        
        if account:
            accounts.append(account)
        
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
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs and potential phishing links (deduplicated and normalized)"""
        raw_urls = set()
        
        for pattern in self._url_patterns:
            for match in pattern.finditer(text):
                url = match.group(1)
                # Clean and normalize
                url = url.rstrip('.,;:!?)')
                if len(url) > 5:  # Minimum valid URL
                    raw_urls.add(url)
        
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
    
    def _extract_phones(self, text: str) -> List[str]:
        """Extract phone numbers"""
        phones = set()
        
        for pattern in self._phone_patterns:
            for match in pattern.finditer(text):
                phone = match.group(1)
                # Normalize - remove formatting
                normalized = re.sub(r'[-.\s()]', '', phone)
                # Validate length
                if 10 <= len(normalized) <= 15:
                    phones.add(phone)
        
        return list(phones)
    
    def _extract_crypto(self, text: str) -> List[str]:
        """Extract cryptocurrency wallet addresses"""
        wallets = set()
        
        for pattern in self._crypto_patterns:
            for match in pattern.finditer(text):
                wallet = match.group(1)
                wallets.add(wallet)
        
        return list(wallets)
    
    def _extract_emails(self, text: str, exclude: Optional[List[str]] = None) -> List[str]:
        """Extract email addresses (excluding UPI IDs)"""
        exclude = exclude or []
        exclude_lower = {e.lower() for e in exclude}
        
        emails = set()
        for match in self._email_pattern.finditer(text):
            email = match.group(1).lower()
            # Exclude UPI IDs (they look like emails)
            if email not in exclude_lower:
                # Also exclude common UPI domains
                domain = email.split('@')[1] if '@' in email else ''
                upi_domains = {'paytm', 'gpay', 'phonepe', 'ybl', 'okaxis', 'oksbi', 'okhdfcbank', 'axl', 'ibl', 'upi'}
                if domain not in upi_domains:
                    emails.add(email)
        
        return list(emails)
    
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
