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
import random
import time

# Use v2 config
import config_v2 as config


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
        
        # Jailbreak attempt counter
        self.jailbreak_attempts = 0
    
    def reset(self):
        """Reset for new conversation"""
        self.context = ConversationContext()
    
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
        
        text_lower = transcript.lower()
        
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
        }
    
    def _determine_state(self, analysis: Dict) -> AgentState:
        """
        Determine state using deterministic rules.
        
        RULES (in priority order):
        1. Info request -> DEFLECT
        2. High threat -> STALL
        3. Money mention -> CLARIFY/CONFUSE
        4. Default -> Weighted
        """
        # Rule 1: Sensitive info request -> DEFLECT
        if analysis["info_request"]:
            return AgentState.DEFLECT
        
        # Rule 2: Threatening -> STALL (waste time)
        if analysis["urgency"] >= 6 or analysis["threat_level"]:
            return AgentState.STALL
        
        # Rule 3: Money -> alternate CLARIFY/CONFUSE
        if analysis["money_mention"]:
            if self.context.last_state == AgentState.CLARIFY:
                return AgentState.CONFUSE
            return AgentState.CLARIFY
        
        # Rule 4: Question -> maybe EXTRACT
        if analysis["is_question"]:
            if self.context.state_counts.get(AgentState.EXTRACT, 0) < 3:
                return AgentState.EXTRACT
        
        # Default: weighted selection
        return self._select_default_state()
    
    def _select_default_state(self) -> AgentState:
        """Weighted random selection avoiding repetition"""
        weights = {
            AgentState.CLARIFY: 1.0,
            AgentState.CONFUSE: 1.0,
            AgentState.STALL: 0.8,
            AgentState.EXTRACT: 0.5,
            AgentState.DEFLECT: 0.8,
        }
        
        # Reduce last state weight
        if self.context.last_state:
            weights[self.context.last_state] *= 0.3
        
        # Weighted selection
        states = list(weights.keys())
        total = sum(weights.values())
        r = random.random() * total
        
        cumsum = 0
        for state in states:
            cumsum += weights[state]
            if r <= cumsum:
                return state
        
        return AgentState.CLARIFY
    
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
        
        LLM only fills blanks in these templates!
        """
        # JAILBREAK: Use special confused-human deflections
        if analysis and analysis.get("jailbreak_attempt"):
            template = random.choice(config.JAILBREAK_DEFLECTIONS)
            fills = {}  # No blanks to fill - direct response
            return template, fills
        
        templates = config.STATE_TEMPLATES.get(state.name, ["I'm sorry, what?"])
        template = random.choice(templates)
        
        fills = {k: random.choice(v) for k, v in config.TEMPLATE_FILLS.items()}
        return template, fills
    
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
