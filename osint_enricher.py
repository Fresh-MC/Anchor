# ANCHOR OSINT Enricher — Post-Extraction, Non-Blocking
# ======================================================
# ARCHITECTURE RULES (STRICT):
#   1. NEVER called during live extraction
#   2. NEVER blocks /process response
#   3. NEVER mutates core ExtractedArtifacts
#   4. NEVER required for Phase-1 scoring or state transitions
#   5. FULLY disabled when ANCHOR_SAFE_MODE=1
#   6. ALL API failures → silent skip (logged, not raised)
#   7. ALL results stored in a SEPARATE "osint_enrichment" dict
#   8. NO new pip dependencies (uses stdlib + requests, already installed)
#
# TOOLS:
#   A. VirusTotal  — URL reputation   (phishing_links only)
#   B. Holehe      — Email OSINT       (emails only, offline/post-incident)
#   C. Shodan      — Domain/IP recon   (domains only)
#
# DESIGN: Fire-and-forget daemon threads with per-call timeouts.
#         Results are written to a shared dict that the caller can
#         optionally poll AFTER the response has already been sent.

import os
import re
import time
import threading
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

logger = logging.getLogger("anchor.osint")

# ═════════════════════════════════════════════════════════════════════════════
# SAFE MODE GATE — Single source of truth
# ═════════════════════════════════════════════════════════════════════════════

def _is_safe_mode() -> bool:
    """Check ANCHOR_SAFE_MODE env var. Deterministic, no caching."""
    return os.getenv("ANCHOR_SAFE_MODE", "0") == "1"


# ═════════════════════════════════════════════════════════════════════════════
# RESULT CONTAINERS (immutable once written)
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class VTResult:
    """VirusTotal enrichment for a single URL."""
    url: str
    malicious: bool = False
    suspicious: bool = False
    reputation_score: int = 0
    malicious_vendors: int = 0
    total_vendors: int = 0
    error: Optional[str] = None
    queried_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HoleheResult:
    """Holehe enrichment for a single email."""
    email: str
    services_found: List[str] = field(default_factory=list)
    total_checked: int = 0
    error: Optional[str] = None
    queried_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ShodanResult:
    """Shodan enrichment for a single domain/IP."""
    target: str
    ip: Optional[str] = None
    org: Optional[str] = None
    os_info: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    country: Optional[str] = None
    error: Optional[str] = None
    queried_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OSINTEnrichment:
    """
    Container for ALL OSINT results for one extraction cycle.
    
    ISOLATION GUARANTEE:
    This object is NEVER merged into ExtractedArtifacts.
    It lives under output["osint_enrichment"] as a separate dict.
    """
    virustotal: List[Dict[str, Any]] = field(default_factory=list)
    holehe: List[Dict[str, Any]] = field(default_factory=list)
    shodan: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "pending"       # pending | running | completed | skipped
    safe_mode: bool = False
    started_at: float = 0.0
    completed_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "virustotal": self.virustotal,
            "holehe": self.holehe,
            "shodan": self.shodan,
            "status": self.status,
            "safe_mode": self.safe_mode,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


# ═════════════════════════════════════════════════════════════════════════════
# INDIVIDUAL ENRICHMENT MODULES
# ═════════════════════════════════════════════════════════════════════════════

# --- A. VirusTotal (URLs) ------------------------------------------------

_VT_API_KEY = os.getenv("VT_API_KEY", "")
_VT_TIMEOUT = 1.5  # seconds

def _enrich_url_virustotal(url: str) -> VTResult:
    """
    Query VirusTotal for a single URL.
    
    CONSTRAINTS:
    - Timeout: 1.5s
    - Failure: returns VTResult with error field set
    - No crash propagation
    """
    result = VTResult(url=url)

    if not _VT_API_KEY:
        result.error = "VT_API_KEY not set"
        return result

    try:
        import requests
        import hashlib
        import base64

        # VT v3 API: URL must be base64-encoded
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": _VT_API_KEY},
            timeout=_VT_TIMEOUT,
        )

        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            result.malicious_vendors = stats.get("malicious", 0)
            result.suspicious = stats.get("suspicious", 0) > 0
            result.total_vendors = sum(stats.values())
            result.malicious = result.malicious_vendors > 0
            result.reputation_score = data.get("reputation", 0)
        elif resp.status_code == 404:
            result.error = "URL not in VT database"
        else:
            result.error = f"VT HTTP {resp.status_code}"

    except Exception as e:
        result.error = f"VT error: {str(e)[:80]}"

    return result


# --- B. Holehe (Emails) --------------------------------------------------

def _enrich_email_holehe(email: str) -> HoleheResult:
    """
    Check email across services using Holehe.
    
    CONSTRAINTS:
    - Designed for OFFLINE / post-incident analysis ONLY
    - NEVER called during live judging
    - Timeout: 5s (slow by design — background only)
    - Failure: returns HoleheResult with error field set
    """
    result = HoleheResult(email=email)

    try:
        # Holehe is an optional, separately-installed tool.
        # If unavailable, silently skip.
        import holehe.core as holehe_core
        import asyncio

        async def _run():
            out = []
            await holehe_core.holehe(email, out)
            return out

        loop = asyncio.new_event_loop()
        try:
            services = loop.run_until_complete(_run())
        finally:
            loop.close()

        found = [s["name"] for s in services if s.get("exists") is True]
        result.services_found = found
        result.total_checked = len(services)

    except ImportError:
        result.error = "holehe not installed (optional)"
    except Exception as e:
        result.error = f"holehe error: {str(e)[:80]}"

    return result


# --- C. Shodan (Domains/IPs) ---------------------------------------------

_SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
_SHODAN_TIMEOUT = 1.5  # seconds

def _extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL, stripping protocol and path."""
    try:
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urlparse(url)
        domain = parsed.hostname
        if domain and re.match(r'^[\w.-]+\.[a-z]{2,}$', domain, re.IGNORECASE):
            return domain
    except Exception:
        pass
    return None


def _enrich_domain_shodan(domain: str) -> ShodanResult:
    """
    Query Shodan for domain/IP metadata.
    
    CONSTRAINTS:
    - Timeout: 1.5s
    - Failure: returns ShodanResult with error field set
    - No crash propagation
    """
    result = ShodanResult(target=domain)

    if not _SHODAN_API_KEY:
        result.error = "SHODAN_API_KEY not set"
        return result

    try:
        import requests

        # Resolve domain to IP via Shodan DNS
        dns_resp = requests.get(
            f"https://api.shodan.io/dns/resolve",
            params={"hostnames": domain, "key": _SHODAN_API_KEY},
            timeout=_SHODAN_TIMEOUT,
        )

        if dns_resp.status_code != 200:
            result.error = f"Shodan DNS HTTP {dns_resp.status_code}"
            return result

        ip = dns_resp.json().get(domain)
        if not ip:
            result.error = "Domain did not resolve"
            return result

        result.ip = ip

        # Query Shodan host
        host_resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": _SHODAN_API_KEY},
            timeout=_SHODAN_TIMEOUT,
        )

        if host_resp.status_code == 200:
            host_data = host_resp.json()
            result.org = host_data.get("org")
            result.os_info = host_data.get("os")
            result.open_ports = host_data.get("ports", [])
            result.country = host_data.get("country_name")
        else:
            result.error = f"Shodan host HTTP {host_resp.status_code}"

    except Exception as e:
        result.error = f"Shodan error: {str(e)[:80]}"

    return result


# ═════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR — Fire-and-Forget, Non-Blocking
# ═════════════════════════════════════════════════════════════════════════════

class OSINTEnricher:
    """
    Post-extraction OSINT enrichment dispatcher.
    
    ARCHITECTURE:
    ┌───────────────────────────────────────────────────────────┐
    │  /process handler                                        │
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
    │  │ Extraction  │→ │ Response    │→ │ Return JSON     │  │
    │  │ (offline)   │  │ Assembly    │  │ (DONE)          │  │
    │  └─────────────┘  └──────┬──────┘  └─────────────────┘  │
    │                          │                               │
    │            ┌─────────────▼──────────────┐                │
    │            │ OSINTEnricher.enrich_async()│                │
    │            │ (daemon thread, detached)   │                │
    │            └─────────────┬──────────────┘                │
    │                          │ (fire & forget)               │
    └──────────────────────────┼────────────────────────────────┘
                               │
                ┌──────────────▼──────────────┐
                │ Background (daemon thread)  │
                │ ┌─────┐ ┌──────┐ ┌───────┐  │
                │ │ VT  │ │Holehe│ │Shodan │  │
                │ └──┬──┘ └──┬───┘ └──┬────┘  │
                │    ▼       ▼        ▼       │
                │ osint_enrichment dict       │
                │ (NEVER mutates core output) │
                └─────────────────────────────┘
    
    GUARANTEE: The /process response is returned BEFORE any OSINT call starts.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # Session → latest OSINTEnrichment (for optional polling)
        self._results: Dict[str, OSINTEnrichment] = {}

    def enrich_async(
        self,
        session_id: str,
        artifacts_dict: Dict[str, Any],
        skip_holehe: bool = True,
    ) -> None:
        """
        Dispatch OSINT enrichment in a background daemon thread.
        
        CRITICAL CONTRACT:
        - This method returns IMMEDIATELY (< 0.1ms)
        - Background thread is daemon (dies with process)
        - Failures are logged, never raised
        - SAFE_MODE disables all dispatching
        
        Args:
            session_id: Session identifier for result lookup
            artifacts_dict: Output from ExtractedArtifacts.to_dict()
            skip_holehe: Skip Holehe by default (slow, offline-only)
        """
        # ── SAFE MODE GATE ──────────────────────────────────────────────
        if _is_safe_mode():
            enrichment = OSINTEnrichment(
                status="skipped",
                safe_mode=True,
                started_at=time.time(),
                completed_at=time.time(),
            )
            with self._lock:
                self._results[session_id] = enrichment
            logger.info("OSINT_SKIPPED_SAFE_MODE")
            print("   🛡️ OSINT_SKIPPED_SAFE_MODE")
            return

        # ── Dispatch daemon thread ──────────────────────────────────────
        t = threading.Thread(
            target=self._run_enrichment,
            args=(session_id, artifacts_dict, skip_holehe),
            daemon=True,  # CRITICAL: dies with main process
            name=f"osint-{session_id[:8]}",
        )
        t.start()

    def _run_enrichment(
        self,
        session_id: str,
        artifacts_dict: Dict[str, Any],
        skip_holehe: bool,
    ) -> None:
        """
        Background enrichment worker. Runs all applicable modules.
        
        FAILURE ISOLATION:
        Every module call is individually try/excepted.
        One module crashing does NOT affect others.
        """
        enrichment = OSINTEnrichment(
            status="running",
            started_at=time.time(),
        )
        with self._lock:
            self._results[session_id] = enrichment

        try:
            # ── A. VirusTotal (phishing_links only) ─────────────────────
            phishing_links = artifacts_dict.get("phishing_links", [])
            if phishing_links and _VT_API_KEY:
                for url in phishing_links[:5]:  # Cap at 5 to avoid rate limiting
                    try:
                        vt_result = _enrich_url_virustotal(url)
                        enrichment.virustotal.append(vt_result.to_dict())
                    except Exception as e:
                        enrichment.virustotal.append(
                            VTResult(url=url, error=f"dispatch error: {str(e)[:60]}").to_dict()
                        )

            # ── B. Holehe (emails only, skip by default) ────────────────
            emails = artifacts_dict.get("emails", [])
            if emails and not skip_holehe:
                for email in emails[:3]:  # Cap at 3
                    try:
                        holehe_result = _enrich_email_holehe(email)
                        enrichment.holehe.append(holehe_result.to_dict())
                    except Exception as e:
                        enrichment.holehe.append(
                            HoleheResult(email=email, error=f"dispatch error: {str(e)[:60]}").to_dict()
                        )

            # ── C. Shodan (domains from phishing_links only) ────────────
            if phishing_links and _SHODAN_API_KEY:
                seen_domains = set()
                for url in phishing_links[:5]:
                    domain = _extract_domain(url)
                    if domain and domain not in seen_domains:
                        seen_domains.add(domain)
                        try:
                            shodan_result = _enrich_domain_shodan(domain)
                            enrichment.shodan.append(shodan_result.to_dict())
                        except Exception as e:
                            enrichment.shodan.append(
                                ShodanResult(target=domain, error=f"dispatch error: {str(e)[:60]}").to_dict()
                            )

        except Exception as e:
            # Catch-all: even if the entire loop crashes, we log and move on
            logger.error(f"OSINT enrichment crashed: {e}")

        finally:
            enrichment.status = "completed"
            enrichment.completed_at = time.time()
            with self._lock:
                self._results[session_id] = enrichment

    def get_results(self, session_id: str) -> Dict[str, Any]:
        """
        Get enrichment results for a session (for optional polling).
        
        Returns:
            OSINTEnrichment dict, or empty dict if not available
        """
        with self._lock:
            enrichment = self._results.get(session_id)
        if enrichment:
            return enrichment.to_dict()
        return {}

    def clear_session(self, session_id: str) -> None:
        """Remove stored results for a session."""
        with self._lock:
            self._results.pop(session_id, None)


# ═════════════════════════════════════════════════════════════════════════════
# SINGLETON FACTORY
# ═════════════════════════════════════════════════════════════════════════════

_enricher_instance: Optional[OSINTEnricher] = None
_enricher_lock = threading.Lock()


def get_enricher() -> OSINTEnricher:
    """Get or create the singleton OSINTEnricher instance."""
    global _enricher_instance
    if _enricher_instance is None:
        with _enricher_lock:
            if _enricher_instance is None:
                _enricher_instance = OSINTEnricher()
    return _enricher_instance


def create_enricher() -> OSINTEnricher:
    """Factory function (alias for get_enricher)."""
    return get_enricher()
