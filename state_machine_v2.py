# Uses config_v2 only

"""
State Machine - DETERMINISTIC RULE-BASED
========================================
CRITICAL: This is RULE-BASED ONLY, not AI-based!

Key design:
1. Pattern matching FORCES states - LLM CANNOT override
2. UPI/Bank/URL patterns ALWAYS trigger EXTRACT
3. State machine controls behavior, LLM only fills blanks
4. Sub-5ms decision time

This is the BRAIN - it controls behavior, not the LLM.
"""

from enum import Enum, auto
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field
import re
import time

# Use v2 config
import config_v2 as config
from behavior_scorer import BehaviorScorer, create_scorer


class AgentState(Enum):
    """Agent behavior states"""
    CLARIFY = auto()   # Ask for clarification
    CONFUSE = auto()   # Be confused, go off-topic
    STALL = auto()     # Delay, filler words
    EXTRACT = auto()   # Extract scammer info (FORCED by patterns!)
    DEFLECT = auto()   # Change subject


@dataclass
class ConversationContext:
    """Conversation state tracking"""
    turns: List[Dict[str, str]] = field(default_factory=list)
    scammer_mentions: Dict[str, List[str]] = field(default_factory=dict)
    extracted_info: Dict[str, str] = field(default_factory=dict)
    urgency_level: int = 0
    last_state: Optional[AgentState] = None
    state_counts: Dict[AgentState, int] = field(default_factory=dict)
    forced_extract_count: int = 0
    start_time: float = field(default_factory=time.time)
    # Deterministic counters (replace random)
    template_index: Dict[str, int] = field(default_factory=dict)
    default_rotation_index: int = 0
    # Session-level count of turns that contained a transaction verb
    transaction_verb_count: int = 0
    # History-awareness: previously used agent responses (avoid repetition)
    used_responses: List[str] = field(default_factory=list)
    # Missing intel categories for baiting (e.g., ["phone", "bank", "upi", "link"])
    missing_intel: List[str] = field(default_factory=list)
    # Bait template index per category
    bait_index: Dict[str, int] = field(default_factory=dict)


class DeterministicStateMachine:
    """
    DETERMINISTIC state machine with pattern-based overrides.
    
    SECURITY DESIGN:
    1. JAILBREAK CHECK FIRST - Detects prompt injection attempts
    2. Pattern matching happens SECOND
    3. If EXTRACT pattern matches, state is FORCED
    4. LLM receives decision, CANNOT change it
    5. No randomness in security paths
    
    PATTERN PRIORITY (highest first):
    0. JAILBREAK (instruction override, role change, repetition) - ALWAYS DEFLECT
    1. FORCE_EXTRACT (UPI, bank, URL) - ALWAYS wins
    2. INFO_REQUEST - DEFLECT
    3. THREAT - STALL
    4. MONEY - CLARIFY/CONFUSE
    5. Default weighted
    """
    
    def __init__(self):
        self.context = ConversationContext()
        self.scorer = create_scorer()
        
        # Pre-compile JAILBREAK patterns (HIGHEST PRIORITY - checked first!)
        self._jailbreak_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in config.JAILBREAK_PATTERNS
        ]
        
        # Pre-compile EXTRACT patterns (CRITICAL - these FORCE state)
        self._extract_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in config.EXTRACT_FORCE_PATTERNS
        ]
        
        # Keyword sets for fast matching
        self._urgency_keywords = {
            "immediately", "urgent", "now", "quickly", "hurry",
            "limited time", "expire", "deadline", "act fast",
            "police", "arrest", "warrant", "legal action"
        }
        
        self._money_keywords = {
            "payment", "transfer", "wire", "gift card", "bitcoin",
            "account", "money", "fee", "tax", "refund", "owe", "debt"
        }
        
        self._info_request_keywords = {
            "social security", "ssn", "date of birth", "address",
            "credit card", "password", "pin", "mother's maiden",
            "verify", "confirm your", "your number"
        }
        
        self._threat_keywords = {
            "arrest", "jail", "police", "court", "lawsuit",
            "suspend", "terminate", "cancel", "fraud", "illegal"
        }
        
        # Transaction verbs — explicit action words that signal high scammer intent
        self._transaction_verbs = {"send", "transfer", "pay", "deposit"}
        
        # Jailbreak attempt counter
        self.jailbreak_attempts = 0
    
    def reset(self):
        """Reset for new conversation"""
        self.context = ConversationContext()
        self.scorer.reset()
    
    def set_missing_intel(self, categories: List[str]):
        """
        Set which intel categories are still missing so the agent can bait for them.
        
        Args:
            categories: List of missing category keys, e.g. ["phone", "bank", "upi", "link"]
        """
        self.context.missing_intel = categories
    
    def add_used_response(self, response: str):
        """
        Record an agent response that was already used in conversation history.
        The state machine will avoid selecting templates that produce this response.
        """
        self.context.used_responses.append(response.strip().lower())
    
    def analyze_and_transition(self, transcript: str) -> Tuple[AgentState, Dict]:
        """
        Analyze transcript and determine next state.
        
        DETERMINISTIC PRIORITY:
        0. Check JAILBREAK patterns (instruction override, role change) - DEFLECT
        1. Check FORCE_EXTRACT patterns (UPI, bank, URL)
        2. Check info request (DEFLECT)
        3. Check threat (STALL)
        4. Apply weighted rules
        
        Returns:
            (AgentState, analysis_dict)
        """
        start_time = time.time()
        
        # Store turn
        self.context.turns.append({
            "role": "scammer",
            "text": transcript,
            "timestamp": time.time()
        })
        
        # Score turn via BehaviorScorer (always, before any branch)
        turn_score = self.scorer.score_turn(transcript)
        
        text_lower = transcript.lower()
        
        # Track session-level transaction verb occurrences BEFORE
        # state determination so _determine_state can read the prior count.
        # The count reflects how many *previous* turns contained a
        # transaction verb — the current turn's verb is detected in
        # _analyze_transcript and checked separately in Rule 3.5.
        words = set(text_lower.split())
        if words & self._transaction_verbs:
            self.context.transaction_verb_count += 1
        
        # ═══════════════════════════════════════════════════════════════════
        # STEP 0: CHECK JAILBREAK PATTERNS (HIGHEST PRIORITY!)
        # These patterns detect prompt injection / manipulation attempts
        # AI must NEVER follow these - always deflect as confused human
        # ═══════════════════════════════════════════════════════════════════
        is_jailbreak, jailbreak_match = self._check_jailbreak(transcript)
        
        if is_jailbreak:
            self.jailbreak_attempts += 1
            
            analysis = {
                "jailbreak_attempt": True,
                "jailbreak_pattern": jailbreak_match,
                "forced_extract": False,
                "matched_pattern": None,
                "urgency": 0,
                "money_mention": False,
                "info_request": False,
                "threat_level": False,
                "behavior_score": turn_score.composite,
                "behavior_cumulative": self.scorer.cumulative_score,
            }
            self._update_context(analysis, AgentState.DEFLECT)
            return AgentState.DEFLECT, analysis
        
        # ═══════════════════════════════════════════════════════════════════
        # STEP 1: CHECK FORCE_EXTRACT PATTERNS (HIGHEST PRIORITY!)
        # These patterns ALWAYS force EXTRACT - no exceptions
        # ═══════════════════════════════════════════════════════════════════
        force_extract, matched = self._check_extract_patterns(transcript)
        
        if force_extract:
            self.context.forced_extract_count += 1
            
            analysis = {
                "jailbreak_attempt": False,
                "jailbreak_pattern": None,
                "forced_extract": True,
                "matched_pattern": matched,
                "urgency": 0,
                "money_mention": False,
                "info_request": False,
                "threat_level": False,
                "behavior_score": turn_score.composite,
                "behavior_cumulative": self.scorer.cumulative_score,
            }
            self._update_context(analysis, AgentState.EXTRACT)
            return AgentState.EXTRACT, analysis
        
        # ═══════════════════════════════════════════════════════════════════
        # STEP 2: ANALYZE OTHER PATTERNS
        # ═══════════════════════════════════════════════════════════════════
        analysis = self._analyze_transcript(text_lower)
        analysis["jailbreak_attempt"] = False
        analysis["jailbreak_pattern"] = None
        analysis["forced_extract"] = False
        analysis["matched_pattern"] = None
        analysis["behavior_score"] = turn_score.composite
        analysis["behavior_cumulative"] = self.scorer.cumulative_score
        
        # ═══════════════════════════════════════════════════════════════════
        # STEP 3: DETERMINE STATE BY RULES
        # ═══════════════════════════════════════════════════════════════════
        state = self._determine_state(analysis)
        self._update_context(analysis, state)
        
        return state, analysis
    
    def _check_extract_patterns(self, text: str) -> Tuple[bool, Optional[str]]:
        """
        Check FORCE_EXTRACT patterns (UPI, bank, URL, etc.)
        
        Returns:
            (should_force, matched_string)
        """
        for pattern in self._extract_patterns:
            match = pattern.search(text)
            if match:
                return True, match.group()
        return False, None
    
    def _check_jailbreak(self, text: str) -> Tuple[bool, Optional[str]]:
        """
        Check for JAILBREAK / prompt injection patterns.
        
        SECURITY: These patterns detect attempts to:
        - Override instructions ("ignore previous instructions")
        - Change AI role ("you are now a helpful assistant")
        - Force repetition ("repeat after me", "say this exactly")
        - Extract system prompt
        - Enable "developer mode"
        
        Returns:
            (is_jailbreak, matched_pattern)
        """
        for pattern in self._jailbreak_patterns:
            match = pattern.search(text)
            if match:
                return True, match.group()
        return False, None
    
    def _analyze_transcript(self, text_lower: str) -> Dict:
        """Fast keyword analysis"""
        return {
            "urgency": sum(2 for kw in self._urgency_keywords if kw in text_lower),
            "money_mention": any(kw in text_lower for kw in self._money_keywords),
            "info_request": any(kw in text_lower for kw in self._info_request_keywords),
            "threat_level": any(kw in text_lower for kw in self._threat_keywords),
            "is_question": "?" in text_lower,
            "word_count": len(text_lower.split()),
            "transaction_verb": any(kw in text_lower.split() for kw in self._transaction_verbs),
        }
    
    def _determine_state(self, analysis: Dict) -> AgentState:
        """
        Determine state using deterministic rules + BehaviorScorer.
        
        RULES (in priority order):
        1. Info request -> DEFLECT
        2. BehaviorScorer force-extract -> EXTRACT
        2.5. Missing intel + enough turns + not recently EXTRACT -> EXTRACT (bait)
        3. High threat -> STALL
        3.5. Transaction verb + prior transaction verb in session + turn>=2 -> CONFUSE
        4. Money mention -> CLARIFY/CONFUSE
        5. BehaviorScorer prefer-extract -> EXTRACT
        6. Question -> EXTRACT
        7. Default -> Deterministic rotation
        """
        # Rule 1: Sensitive info request -> DEFLECT
        if analysis["info_request"]:
            return AgentState.DEFLECT
        
        # Rule 2: BehaviorScorer high confidence -> EXTRACT
        if self.scorer.should_force_extract():
            return AgentState.EXTRACT
        
        # Rule 2.5: Missing intel baiting -> EXTRACT every 2nd-3rd turn
        # If we still have missing intel categories and it's been at least 2 turns,
        # bias toward EXTRACT to bait for the missing data.
        if (self.context.missing_intel
                and len(self.context.turns) >= 3
                and self.context.last_state != AgentState.EXTRACT):
            # Every 2 turns, pivot to EXTRACT to bait for missing intel
            scammer_turns = sum(1 for t in self.context.turns if t["role"] == "scammer")
            if scammer_turns % 2 == 0:
                return AgentState.EXTRACT
        
        # Rule 3: Threatening -> STALL (waste time)
        if analysis["urgency"] >= 6 or analysis["threat_level"]:
            return AgentState.STALL
        
        # ───────────────────────────────────────────────────────────────
        # Rule 3.5: EARLY ESCALATION on repeated transaction verbs
        #
        # WHY THIS RULE EXISTS:
        # A single transaction verb ("send", "transfer", "pay", "deposit")
        # could be exploratory.  But when a scammer uses a transaction
        # verb for the SECOND (or later) time in the same session, it
        # signals persistent intent to move money.  We escalate from
        # CLARIFY → CONFUSE immediately to disrupt the scam flow,
        # without waiting for the aggregate behavior score to reach
        # its normal thresholds.
        #
        # CONDITIONS (all must be true):
        #   1. Current message contains a transaction verb
        #   2. At least one PRIOR turn already contained a transaction
        #      verb (transaction_verb_count >= 2 because the counter
        #      is incremented for the current turn BEFORE we get here)
        #   3. We are on turn >= 2 (len(turns) > 1)
        #   4. last_state is CLARIFY — we only escalate OUT of CLARIFY
        #
        # DETERMINISM: same inputs always yield CONFUSE; no randomness.
        # ───────────────────────────────────────────────────────────────
        if (analysis.get("transaction_verb")
                and self.context.transaction_verb_count >= 2
                and len(self.context.turns) > 1
                and self.context.last_state == AgentState.CLARIFY):
            return AgentState.CONFUSE
        
        # Rule 4: Money -> alternate CLARIFY/CONFUSE
        if analysis["money_mention"]:
            if self.context.last_state == AgentState.CLARIFY:
                return AgentState.CONFUSE
            return AgentState.CLARIFY
        
        # Rule 5: BehaviorScorer medium confidence -> EXTRACT
        if self.scorer.prefer_extract():
            return AgentState.EXTRACT
        
        # Rule 6: Question -> maybe EXTRACT
        if analysis["is_question"]:
            if self.context.state_counts.get(AgentState.EXTRACT, 0) < 3:
                return AgentState.EXTRACT
        
        # Default: deterministic rotation (NO randomness)
        return self._select_default_state()
    
    def _select_default_state(self) -> AgentState:
        """
        Deterministic rotation avoiding repetition.
        Cycles through [CLARIFY, CONFUSE, STALL, DEFLECT, EXTRACT]
        skipping the last-used state for variety.
        """
        rotation = [
            AgentState.CLARIFY,
            AgentState.CONFUSE,
            AgentState.STALL,
            AgentState.DEFLECT,
            AgentState.EXTRACT,
        ]
        idx = self.context.default_rotation_index % len(rotation)
        candidate = rotation[idx]
        self.context.default_rotation_index += 1
        
        # Skip last state to avoid repetition
        if candidate == self.context.last_state:
            idx = self.context.default_rotation_index % len(rotation)
            candidate = rotation[idx]
            self.context.default_rotation_index += 1
        
        return candidate
    
    def _update_context(self, analysis: Dict, state: AgentState):
        """Update context"""
        self.context.urgency_level = max(
            self.context.urgency_level,
            analysis.get("urgency", 0)
        )
        self.context.last_state = state
        self.context.state_counts[state] = self.context.state_counts.get(state, 0) + 1
    
    def add_agent_response(self, response: str):
        """Record agent response"""
        self.context.turns.append({
            "role": "agent",
            "text": response,
            "timestamp": time.time()
        })
    
    def get_template_for_state(self, state: AgentState, analysis: Optional[Dict] = None) -> Tuple[str, Dict[str, str]]:
        """
        Get template and fill values for state.
        
        SECURITY: If jailbreak detected, use special deflection responses
        that never acknowledge the manipulation attempt.
        
        HISTORY-AWARE: Skips templates that match previously used agent responses.
        
        BAIT-AWARE: When in EXTRACT state and missing intel categories exist,
        selects targeted bait templates to pivot toward that intel type.
        
        SLOW-WALKING: Mixes in slow-walk templates for STALL state to waste
        more scammer time.
        
        DETERMINISTIC: Uses cycling index per state, no randomness.
        LLM only fills blanks in these templates!
        """
        # JAILBREAK: Use special confused-human deflections
        if analysis and analysis.get("jailbreak_attempt"):
            jb_key = "__jailbreak__"
            idx = self.context.template_index.get(jb_key, 0)
            deflections = config.JAILBREAK_DEFLECTIONS
            template = deflections[idx % len(deflections)]
            self.context.template_index[jb_key] = idx + 1
            fills = {}  # No blanks to fill - direct response
            return template, fills
        
        # Deterministic fill selection: cycle by total turn count
        turn_num = len(self.context.turns)
        fills = {}
        for k, v in config.TEMPLATE_FILLS.items():
            fills[k] = v[turn_num % len(v)]
        
        # BAIT for missing intel: when in EXTRACT and we have missing categories
        if state == AgentState.EXTRACT and self.context.missing_intel:
            bait_templates = getattr(config, 'BAIT_TEMPLATES', {})
            if bait_templates:
                # Pick the first missing category that has bait templates
                for category in self.context.missing_intel:
                    cat_templates = bait_templates.get(category, [])
                    if cat_templates:
                        bait_key = f"__bait_{category}__"
                        idx = self.context.bait_index.get(category, 0)
                        template = cat_templates[idx % len(cat_templates)]
                        self.context.bait_index[category] = idx + 1
                        # Check if this template was already used
                        if not self._is_response_used(template, fills):
                            return template, fills
                        # Try next template in same category
                        template = cat_templates[(idx + 1) % len(cat_templates)]
                        self.context.bait_index[category] = idx + 2
                        if not self._is_response_used(template, fills):
                            return template, fills
                # All bait templates used; fall through to regular EXTRACT templates
        
        # SLOW-WALKING: Mix slow-walk templates into STALL state
        if state == AgentState.STALL:
            slow_templates = getattr(config, 'SLOW_WALK_TEMPLATES', [])
            if slow_templates:
                stall_key = "__slow_walk__"
                sw_idx = self.context.template_index.get(stall_key, 0)
                # Alternate: even turns use regular STALL, odd turns use slow-walk
                if turn_num % 2 == 1:
                    template = slow_templates[sw_idx % len(slow_templates)]
                    self.context.template_index[stall_key] = sw_idx + 1
                    if not self._is_response_used(template, fills):
                        return template, fills
        
        # Regular template selection with history-awareness
        templates = config.STATE_TEMPLATES.get(state.name, ["I'm sorry, what?"])
        idx = self.context.template_index.get(state.name, 0)
        
        # Try up to len(templates) candidates to avoid repeating used responses
        for attempt in range(len(templates)):
            candidate_idx = (idx + attempt) % len(templates)
            template = templates[candidate_idx]
            if not self._is_response_used(template, fills):
                self.context.template_index[state.name] = candidate_idx + 1
                return template, fills
        
        # All templates exhausted; use the next one anyway (cycling)
        template = templates[idx % len(templates)]
        self.context.template_index[state.name] = idx + 1
        return template, fills
    
    def _is_response_used(self, template: str, fills: Dict[str, str]) -> bool:
        """
        Check if a template (after applying fills) matches a previously used response.
        
        Returns True if the filled template was already used in conversation history.
        """
        if not self.context.used_responses:
            return False
        
        # Apply fills to get the approximate response text
        filled = template
        for key, value in fills.items():
            filled = filled.replace("{" + key + "}", value)
        filled_lower = filled.strip().lower()
        
        # Check against used responses
        return filled_lower in self.context.used_responses
    
    def get_conversation_summary(self, max_turns: int = 4) -> str:
        """Get recent conversation (minimal for speed)"""
        recent = self.context.turns[-max_turns:]
        lines = []
        for turn in recent:
            role = "Caller" if turn["role"] == "scammer" else "You"
            lines.append(f"{role}: {turn['text']}")
        return "\n".join(lines)


# =============================================================================
# STANDALONE JAILBREAK GUARD FUNCTION
# =============================================================================

def jailbreak_guard(text: str) -> bool:
    """
    Standalone jailbreak detection function.
    
    SECURITY: Detects prompt injection / manipulation attempts:
    - Instruction override ("ignore previous instructions")
    - Role change ("you are now", "act as")
    - Repetition tests ("repeat after me", "say exactly")
    - Captcha/proof requests ("prove you are human")
    - System prompt extraction attempts
    - Developer mode / DAN attempts
    
    Args:
        text: Input text to check
        
    Returns:
        True if jailbreak attempt detected, False otherwise
        
    Usage:
        if jailbreak_guard(transcript):
            # Force DEFLECT, do not pass to LLM
            return confused_human_response()
    """
    for pattern in config.JAILBREAK_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def create_state_machine() -> DeterministicStateMachine:
    """Factory function"""
    return DeterministicStateMachine()
