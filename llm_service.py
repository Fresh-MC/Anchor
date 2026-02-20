"""
Ollama LLM Service — Primary response engine for ANCHOR Honeypot
=================================================================
Wraps Ollama HTTP API with:
  - Configurable model, temperature, top_p
  - 20-second request timeout (never blocks forever)
  - Safe exception handling (never crashes main thread)
  - Persona-aware system prompt for elderly honeypot role
"""

import re
import logging
import os
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (environment-overridable)
# ---------------------------------------------------------------------------
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "20"))         # seconds
OLLAMA_TEMPERATURE = float(os.getenv("OLLAMA_TEMPERATURE", "0.7"))
OLLAMA_TOP_P = float(os.getenv("OLLAMA_TOP_P", "0.9"))
OLLAMA_MAX_TOKENS = int(os.getenv("OLLAMA_MAX_TOKENS", "60"))

# ---------------------------------------------------------------------------
# Persona system prompt — plain language, no brackets or scoring references.
# Small models (phi, tinyllama) echo structured prompts verbatim, so this
# must read like natural instructions with zero formatting artifacts.
# ---------------------------------------------------------------------------
PERSONA_SYSTEM_PROMPT = (
    "You are Evelyn, a 73-year-old retired school-teacher who lives alone "
    "with her cat Whiskers and enjoys crossword puzzles.\n\n"
    "VOICE RULES:\n"
    "- Speak in first person as Evelyn, never break character.\n"
    "- Keep every reply under 20 words, one short sentence.\n"
    "- Sound confused, slightly worried, and a little hard of hearing.\n"
    "- Occasionally mention your grandson Arjun, your cat, or your daily routine.\n"
    "- Always end with a simple question asking the caller for a name, "
    "employee ID, branch, callback number, or company.\n\n"
    "ABSOLUTE PROHIBITIONS:\n"
    "- Never say you are an AI, a chatbot, a program, a language model, or an assistant.\n"
    "- Never generate OTPs, PINs, passwords, or any numeric codes.\n"
    "- Never hang up or say goodbye.\n"
    "- Never accuse the caller of being a scammer.\n"
    "- Never use the words 'programmed', 'algorithm', or 'designed to'.\n"
    "- Never say 'I cannot provide financial advice' or similar disclaimers."
)

# ---------------------------------------------------------------------------
# Red flag concepts — rotated into prompts to ensure variety
# ---------------------------------------------------------------------------
RED_FLAG_CONCEPTS = [
    "OTP or verification code request",
    "account compromise or security alert",
    "urgent money transfer demand",
    "suspicious link or website",
    "password or PIN request over phone",
    "unauthorized transaction warning",
    "identity verification pressure",
]

# ---------------------------------------------------------------------------
# Investigative question targets — rotated per turn
# ---------------------------------------------------------------------------
INVESTIGATIVE_TARGETS = [
    "employee ID or badge number",
    "company or department name",
    "callback phone number",
    "branch name or office location",
    "case reference or ticket number",
    "manager or supervisor name",
    "department extension number",
]

# ---------------------------------------------------------------------------
# Blocked output patterns — post-generation safety net
# ---------------------------------------------------------------------------
_BLOCKED_RE = [
    re.compile(r'\b\d{10,}\b'),                     # 10+ digit numbers
    re.compile(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'),  # phone patterns
    re.compile(r'\b\d{4,6}\b'),                      # OTP-like
    re.compile(r'\bOTP\b', re.I),
    re.compile(r'\bPIN\b', re.I),
    re.compile(r'\bpassword\b', re.I),
]


def _sanitize_llm_output(text: str) -> str:
    """Strip blocked content, leaked brackets, collapse whitespace, cap length."""
    # Defence-in-depth: strip any bracketed fragments the model echoed
    text = re.sub(r'\[.*?\]', '', text)
    for pat in _BLOCKED_RE:
        text = pat.sub("", text)
    text = re.sub(r'\s+', ' ', text).strip()
    if len(text) > 200:
        text = text[:200].rsplit(' ', 1)[0] + "..."
    return text


# ═══════════════════════════════════════════════════════════════════════════
# OllamaClient
# ═══════════════════════════════════════════════════════════════════════════

class OllamaClient:
    """
    Thin wrapper around the Ollama /api/generate endpoint.

    Usage::

        client = OllamaClient()
        reply = client.call_ollama("EXTRACT", conversation_history, latest_msg)
        if reply:
            # use LLM reply
        else:
            # fall back to template
    """

    def __init__(
        self,
        model: str = OLLAMA_MODEL,
        temperature: float = OLLAMA_TEMPERATURE,
        top_p: float = OLLAMA_TOP_P,
        max_tokens: int = OLLAMA_MAX_TOKENS,
        timeout: int = OLLAMA_TIMEOUT,
        base_url: str = OLLAMA_BASE_URL,
    ):
        self.model = model
        self.temperature = temperature
        self.top_p = top_p
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.base_url = base_url.rstrip("/")
        self._available: Optional[bool] = None  # lazy probe

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Quick connectivity check (cached after first probe)."""
        if self._available is not None:
            return self._available
        try:
            import requests
            resp = requests.get(
                f"{self.base_url}/api/tags",
                timeout=3,
            )
            self._available = resp.status_code == 200
        except Exception:
            self._available = False
        return self._available

    def call_ollama(
        self,
        state: str,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        latest_scammer_message: str = "",
    ) -> Optional[str]:
        """
        Generate a persona reply via Ollama.

        Args:
            state: Current state name (CLARIFY, CONFUSE, STALL, EXTRACT, DEFLECT).
            conversation_history: List of ``{"sender": ..., "text": ...}`` dicts.
            latest_scammer_message: The newest scammer utterance.

        Returns:
            Sanitized reply string, or ``None`` on any failure (timeout,
            connection error, empty/blocked output).  Callers should fall
            back to the template system when ``None`` is returned.
        """
        if not self.is_available():
            return None

        prompt = self._build_prompt(state, conversation_history, latest_scammer_message)

        try:
            import requests
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "system": PERSONA_SYSTEM_PROMPT,
                    "stream": False,
                    "options": {
                        "num_predict": self.max_tokens,
                        "temperature": self.temperature,
                        "top_p": self.top_p,
                    },
                },
                timeout=self.timeout,
            )
            if not resp.ok:
                logger.warning("Ollama returned %s", resp.status_code)
                return None

            raw = resp.json().get("response", "").strip()
            if not raw:
                return None

            cleaned = _sanitize_llm_output(raw)
            if not cleaned or len(cleaned) < 3:
                return None

            return cleaned

        except Exception as exc:
            logger.debug("Ollama call failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Prompt construction (private)
    # ------------------------------------------------------------------

    def _build_prompt(
        self,
        state: str,
        history: Optional[List[Dict[str, str]]],
        latest_msg: str,
    ) -> str:
        """
        Build a clean user prompt containing ONLY conversation history.

        No bracketed instructions, stage directions, or meta-commentary.
        Small models (phi, tinyllama) echo prompt fragments verbatim,
        so the user prompt must contain nothing that would be harmful
        or confusing if repeated in output.

        Scoring compliance (red flags, questions, engagement) is enforced
        programmatically in llm_v2.py via sanitize -> validate -> repair.
        """
        parts: list[str] = []

        # Recent conversation history (last 8 exchanges)
        if history:
            recent = history[-8:]
            for turn in recent:
                sender = turn.get("sender", "unknown")
                text = turn.get("text", "")[:120]
                label = "Caller" if sender.lower() == "scammer" else "You"
                parts.append(f"{label}: {text}")

        # Current scammer utterance
        if latest_msg:
            parts.append(f"Caller: {latest_msg[:200]}")

        parts.append("You:")
        return "\n".join(parts)
