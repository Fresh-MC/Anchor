# Behavioral Intelligence Scorer for ANCHOR
# Deterministic, explainable, no-ML signal accumulator

"""
BehaviorScorer – Weighted Temporal Intent Analysis
====================================================
Accumulates signals ACROSS turns to detect scammer intent shift.

PER-TURN FORMULA:
  Score_t = 0.35·ΔUrgency + 0.25·PressureLex + 0.20·CredentialRepeat
          + 0.10·(1 − DelayTolerance) + 0.10·PolitenessShift
  Each component ∈ [0.0, 1.0] ⇒ composite ∈ [0.0, 1.0]

CUMULATIVE SCORE = mean(Score_1 … Score_t)  ∈ [0.0, 1.0]

SESSION BEHAVIOR SCORE (monotonically non-decreasing):
  SBS_t = max(SBS_{t-1}, composite_t, cumulative_t)
  Bounded [0.0, 1.0]. Represents the peak threat signal
  observed at any point in the session.  Once risk is
  detected it can never decrease — scammer cannot "un-scare".

ESCALATION MULTIPLIER (multi-vector detection):
  Counts how many DISTINCT signal dimensions fired across
  the entire session (5 dimensions total).  A dimension
  "fires" when its contribution > 0 in ANY scored turn.

  fired = |{d ∈ {urgency, pressure, credential, delay, politeness}
            : ∃ t where d_t > 0}|

  escalation_multiplier = fired / 5.0
  Range: [0.0, 1.0], granularity 0.2.

  Interpretation:
    0.0  — no signal dimensions fired (benign conversation)
    0.2  — single-vector attack (e.g., pressure only)
    0.6+ — multi-vector attack (e.g., urgency + credential + pressure)
    1.0  — all 5 dimensions fired at some point (sophisticated attack)

  This captures attack breadth.  A scammer who combines
  urgency + credential + impoliteness is more dangerous than
  one who repeats only pressure words.

THRESHOLDS:
  cumulative >= 0.60  →  force EXTRACT  (high confidence scammer)
  cumulative >= 0.40  →  prefer EXTRACT / CLARIFY
  cumulative <  0.40  →  normal state rotation

DESIGN:
  • Deterministic – no randomness anywhere
  • Explainable – every signal is a named float
  • Fast – pure arithmetic, <0.1 ms per turn
  • Stateful – accumulates across conversation turns
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import re


# ═══════════════════════════════════════════════════════════════════════════
# SIGNAL LEXICONS (keyword sets for each signal dimension)
# ═══════════════════════════════════════════════════════════════════════════

URGENCY_LEXICON = {
    "immediately", "urgent", "now", "quickly", "hurry", "fast",
    "limited time", "expire", "deadline", "act fast", "right now",
    "as soon as possible", "asap", "time is running out", "last chance",
    "today only", "don't delay", "within the hour",
}

PRESSURE_LEXICON = {
    "must", "have to", "required", "mandatory", "compulsory",
    "arrest", "warrant", "police", "court", "jail", "legal action",
    "suspend", "terminate", "cancel", "block", "freeze",
    "penalty", "fine", "consequences", "action will be taken",
    "failure to comply", "non-compliance",
}

CREDENTIAL_LEXICON = {
    "otp", "pin", "password", "ssn", "social security",
    "date of birth", "dob", "mother's maiden", "cvv", "card number",
    "expiry", "security code", "verify", "confirm your",
    "your account", "your number", "your details", "your information",
    "aadhaar", "pan card", "pan number",
}

POLITENESS_MARKERS = {
    "sir", "ma'am", "madam", "please", "kindly", "dear",
    "respected", "thank you", "sorry to bother",
}

IMPATIENCE_MARKERS = {
    "listen", "look", "pay attention", "i said", "i told you",
    "are you deaf", "don't waste", "stop wasting", "enough",
    "just do it", "just send", "just give", "why aren't you",
    "what's wrong with you", "how many times",
}

DELAY_ACCEPTANCE = {
    "okay", "sure", "take your time", "no problem", "no rush",
    "i'll wait", "go ahead", "alright", "that's fine",
}


@dataclass
class TurnSignals:
    """Raw signals extracted from a single scammer turn."""
    urgency_count: int = 0
    pressure_count: int = 0
    credential_hits: int = 0
    politeness_count: int = 0
    impatience_count: int = 0
    delay_accepted: bool = False
    word_count: int = 0

    def to_dict(self) -> Dict:
        return {
            "urgency": self.urgency_count,
            "pressure": self.pressure_count,
            "credential": self.credential_hits,
            "politeness": self.politeness_count,
            "impatience": self.impatience_count,
            "delay_accepted": self.delay_accepted,
            "words": self.word_count,
        }


@dataclass
class TurnScore:
    """Computed score for a single turn."""
    delta_urgency: float = 0.0
    pressure_lex: float = 0.0
    credential_repeat: float = 0.0
    delay_tolerance: float = 0.0
    politeness_shift: float = 0.0
    composite: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "delta_urgency": round(self.delta_urgency, 3),
            "pressure_lex": round(self.pressure_lex, 3),
            "credential_repeat": round(self.credential_repeat, 3),
            "delay_tolerance": round(self.delay_tolerance, 3),
            "politeness_shift": round(self.politeness_shift, 3),
            "composite": round(self.composite, 3),
        }


# Weights for composite score
W_URGENCY = 0.35
W_PRESSURE = 0.25
W_CREDENTIAL = 0.20
W_DELAY = 0.10
W_POLITENESS = 0.10


class BehaviorScorer:
    """
    Deterministic behavioral intelligence engine.

    Tracks scammer behaviour across turns and produces
    an explainable composite score that drives state selection.
    """

    def __init__(self):
        self._history: List[TurnSignals] = []
        self._scores: List[TurnScore] = []
        self._credential_seen: set = set()   # credentials seen so far
        self._cumulative_score: float = 0.0
        # ── Session-level escalation tracking ───────────────────────────
        self._session_behavior_score: float = 0.0  # monotonically non-decreasing peak
        self._dimensions_fired: set = set()         # which signal dimensions fired (max 5)

    # ── public API ──────────────────────────────────────────────────────

    def score_turn(self, text: str) -> TurnScore:
        """
        Analyse one scammer message, accumulate, return turn score.
        Fast: pure string matching + arithmetic, <0.1 ms.
        """
        signals = self._extract_signals(text)
        self._history.append(signals)

        ts = TurnScore()

        # 1. ΔUrgency  (change vs previous turn, normalised 0-1)
        if len(self._history) >= 2:
            prev = self._history[-2].urgency_count
            curr = signals.urgency_count
            delta = max(curr - prev, 0)
            ts.delta_urgency = min(delta / 3.0, 1.0)
        else:
            ts.delta_urgency = min(signals.urgency_count / 3.0, 1.0)

        # 2. PressureLex  (normalised count)
        ts.pressure_lex = min(signals.pressure_count / 4.0, 1.0)

        # 3. CredentialRepeat  (1.0 if a credential keyword recurs)
        current_creds = self._extract_credential_tokens(text)
        repeated = current_creds & self._credential_seen
        ts.credential_repeat = 1.0 if repeated else 0.0
        self._credential_seen |= current_creds

        # 4. DelayTolerance  (0 = impatient, 1 = tolerant)
        ts.delay_tolerance = 1.0 if signals.delay_accepted else 0.0

        # 5. PolitenessShift  (-1 → 1 mapped to 0 → 1)
        pol_ratio = 0.5  # neutral default
        if signals.politeness_count + signals.impatience_count > 0:
            pol_ratio = signals.impatience_count / (
                signals.politeness_count + signals.impatience_count
            )
        ts.politeness_shift = pol_ratio  # higher = more aggressive

        # Composite
        ts.composite = (
            W_URGENCY    * ts.delta_urgency
            + W_PRESSURE   * ts.pressure_lex
            + W_CREDENTIAL * ts.credential_repeat
            + W_DELAY      * (1.0 - ts.delay_tolerance)  # impatient → higher
            + W_POLITENESS * ts.politeness_shift
        )
        ts.composite = round(min(ts.composite, 1.0), 3)

        self._scores.append(ts)
        self._cumulative_score = sum(s.composite for s in self._scores) / len(self._scores)

        # ── Session behavior score: monotonically non-decreasing ────────
        # SBS_t = max(SBS_{t-1}, composite_t, cumulative_t)
        self._session_behavior_score = max(
            self._session_behavior_score,
            ts.composite,
            self._cumulative_score,
        )

        # ── Escalation multiplier: track which dimensions fired ─────────
        # A dimension "fires" when its per-turn contribution > 0.
        if ts.delta_urgency > 0:
            self._dimensions_fired.add("urgency")
        if ts.pressure_lex > 0:
            self._dimensions_fired.add("pressure")
        if ts.credential_repeat > 0:
            self._dimensions_fired.add("credential")
        if (1.0 - ts.delay_tolerance) > 0:       # impatient → fires delay dim
            self._dimensions_fired.add("delay")
        if ts.politeness_shift > 0.5:             # above neutral → fires politeness dim
            self._dimensions_fired.add("politeness")

        return ts

    @property
    def cumulative_score(self) -> float:
        """Rolling average composite across all turns."""
        return round(self._cumulative_score, 3)

    @property
    def session_behavior_score(self) -> float:
        """
        Monotonically non-decreasing peak risk signal.
        SBS_t = max(SBS_{t-1}, composite_t, cumulative_t)
        Bounded [0.0, 1.0].
        """
        return round(self._session_behavior_score, 3)

    @property
    def escalation_multiplier(self) -> float:
        """
        Multi-vector attack breadth.
        escalation_multiplier = |dimensions_fired| / 5.0
        Range [0.0, 1.0], granularity 0.2.
        """
        return round(len(self._dimensions_fired) / 5.0, 3)

    @property
    def latest_score(self) -> float:
        """Most recent turn's composite."""
        if self._scores:
            return self._scores[-1].composite
        return 0.0

    @property
    def turn_count(self) -> int:
        return len(self._history)

    def should_force_extract(self) -> bool:
        """High-confidence scammer → force EXTRACT state."""
        return self.cumulative_score >= 0.60 or self.latest_score >= 0.70

    def prefer_extract(self) -> bool:
        """Medium confidence → prefer EXTRACT / CLARIFY."""
        return self.cumulative_score >= 0.40

    def get_summary(self) -> Dict:
        """Explainable summary for logs / evaluator dashboard."""
        return {
            "turns_scored": self.turn_count,
            "cumulative_score": self.cumulative_score,
            "session_behavior_score": self.session_behavior_score,
            "escalation_multiplier": self.escalation_multiplier,
            "dimensions_fired": sorted(self._dimensions_fired),
            "latest_score": self.latest_score,
            "force_extract": self.should_force_extract(),
            "prefer_extract": self.prefer_extract(),
            "credentials_seen": sorted(self._credential_seen),
            "per_turn": [s.to_dict() for s in self._scores],
        }

    def reset(self):
        self._history.clear()
        self._scores.clear()
        self._credential_seen.clear()
        self._cumulative_score = 0.0
        self._session_behavior_score = 0.0
        self._dimensions_fired.clear()

    # ── internal helpers ────────────────────────────────────────────────

    def _extract_signals(self, text: str) -> TurnSignals:
        text_lower = text.lower()
        words = text_lower.split()

        return TurnSignals(
            urgency_count=sum(1 for kw in URGENCY_LEXICON if kw in text_lower),
            pressure_count=sum(1 for kw in PRESSURE_LEXICON if kw in text_lower),
            credential_hits=sum(1 for kw in CREDENTIAL_LEXICON if kw in text_lower),
            politeness_count=sum(1 for kw in POLITENESS_MARKERS if kw in text_lower),
            impatience_count=sum(1 for kw in IMPATIENCE_MARKERS if kw in text_lower),
            delay_accepted=any(kw in text_lower for kw in DELAY_ACCEPTANCE),
            word_count=len(words),
        )

    def _extract_credential_tokens(self, text: str) -> set:
        text_lower = text.lower()
        return {kw for kw in CREDENTIAL_LEXICON if kw in text_lower}


def create_scorer() -> BehaviorScorer:
    """Factory function."""
    return BehaviorScorer()
