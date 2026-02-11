"""
State Machine for controlling agent behavior
Analyzes transcripts and determines response strategy
"""

from enum import Enum, auto
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field
import re
import random
import time


class AgentState(Enum):
    """Possible states for the agent"""
    CLARIFY = auto()   # Ask for clarification
    CONFUSE = auto()   # Act confused, give nonsensical response
    STALL = auto()     # Delay, use filler words
    EXTRACT = auto()   # Try to extract scammer information
    DEFLECT = auto()   # Change subject, avoid giving info


@dataclass
class ConversationContext:
    """Tracks conversation history and context"""
    turns: List[Dict[str, str]] = field(default_factory=list)
    scammer_requests: List[str] = field(default_factory=list)
    extracted_info: Dict[str, str] = field(default_factory=dict)
    current_topic: Optional[str] = None
    urgency_level: int = 0  # 0-10 scale
    last_state: Optional[AgentState] = None
    state_counts: Dict[AgentState, int] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)


class StateMachine:
    """
    State machine that controls agent behavior based on conversation analysis
    """
    
    # Keywords that indicate scammer tactics
    URGENCY_KEYWORDS = [
        "immediately", "urgent", "now", "quickly", "hurry",
        "limited time", "expire", "deadline", "act fast",
        "police", "arrest", "warrant", "legal action"
    ]
    
    MONEY_KEYWORDS = [
        "payment", "transfer", "wire", "gift card", "bitcoin",
        "account", "bank", "money", "fee", "tax", "refund",
        "owe", "debt", "charge"
    ]
    
    INFO_REQUEST_KEYWORDS = [
        "social security", "ssn", "date of birth", "address",
        "credit card", "bank account", "password", "pin",
        "mother's maiden", "verify", "confirm your"
    ]
    
    THREAT_KEYWORDS = [
        "arrest", "jail", "police", "court", "lawsuit",
        "suspend", "terminate", "cancel", "fraud", "illegal"
    ]
    
    def __init__(self):
        self.context = ConversationContext()
        self._state_weights = {
            AgentState.CLARIFY: 1.0,
            AgentState.CONFUSE: 1.0,
            AgentState.STALL: 1.0,
            AgentState.EXTRACT: 0.8,
            AgentState.DEFLECT: 1.0,
        }
    
    def reset(self):
        """Reset state machine for new conversation"""
        self.context = ConversationContext()
    
    def analyze_and_transition(self, transcript: str) -> AgentState:
        """
        Analyze transcript and determine next state
        
        Args:
            transcript: The transcribed text from the scammer
            
        Returns:
            The next AgentState
        """
        # Store turn in history
        self.context.turns.append({
            "role": "scammer",
            "text": transcript,
            "timestamp": time.time()
        })
        
        # Analyze the transcript
        analysis = self._analyze_transcript(transcript)
        
        # Determine next state based on analysis
        next_state = self._determine_state(analysis)
        
        # Update context
        self._update_context(analysis, next_state)
        
        print(f"[STATE] Transition: {self.context.last_state} -> {next_state}")
        print(f"[STATE] Analysis: urgency={analysis['urgency']}, "
              f"money_mention={analysis['money_mention']}, "
              f"info_request={analysis['info_request']}")
        
        return next_state
    
    def _analyze_transcript(self, transcript: str) -> Dict:
        """Analyze transcript for key indicators"""
        text_lower = transcript.lower()
        
        analysis = {
            "urgency": self._calculate_urgency(text_lower),
            "money_mention": self._detect_keywords(text_lower, self.MONEY_KEYWORDS),
            "info_request": self._detect_keywords(text_lower, self.INFO_REQUEST_KEYWORDS),
            "threat_level": self._detect_keywords(text_lower, self.THREAT_KEYWORDS),
            "is_question": "?" in transcript,
            "word_count": len(transcript.split()),
            "contains_number": bool(re.search(r'\d+', transcript)),
        }
        
        return analysis
    
    def _calculate_urgency(self, text: str) -> int:
        """Calculate urgency level (0-10)"""
        urgency = 0
        for keyword in self.URGENCY_KEYWORDS:
            if keyword in text:
                urgency += 2
        return min(10, urgency)
    
    def _detect_keywords(self, text: str, keywords: List[str]) -> bool:
        """Check if any keywords are present"""
        return any(kw in text for kw in keywords)
    
    def _determine_state(self, analysis: Dict) -> AgentState:
        """Determine the next state based on analysis"""
        
        # Rule-based state selection
        
        # If they're asking for sensitive info, DEFLECT
        if analysis["info_request"]:
            return AgentState.DEFLECT
        
        # If high urgency/threats, STALL to waste their time
        if analysis["urgency"] >= 6 or analysis["threat_level"]:
            return AgentState.STALL
        
        # If they mention money, alternate between CLARIFY and CONFUSE
        if analysis["money_mention"]:
            if self.context.last_state == AgentState.CLARIFY:
                return AgentState.CONFUSE
            return AgentState.CLARIFY
        
        # If it's a question, sometimes EXTRACT info from them
        if analysis["is_question"] and random.random() < 0.3:
            return AgentState.EXTRACT
        
        # Default: weighted random selection with variety
        return self._weighted_random_state()
    
    def _weighted_random_state(self) -> AgentState:
        """Select state with weighted randomness, avoiding repetition"""
        weights = self._state_weights.copy()
        
        # Reduce weight of last state to encourage variety
        if self.context.last_state:
            weights[self.context.last_state] *= 0.3
        
        # Reduce weight of frequently used states
        total_turns = sum(self.context.state_counts.values()) or 1
        for state, count in self.context.state_counts.items():
            if count / total_turns > 0.3:  # Used more than 30%
                weights[state] *= 0.5
        
        # Weighted random selection
        states = list(weights.keys())
        state_weights = list(weights.values())
        total = sum(state_weights)
        r = random.random() * total
        
        cumsum = 0
        for state, weight in zip(states, state_weights):
            cumsum += weight
            if r <= cumsum:
                return state
        
        return AgentState.CLARIFY  # Fallback
    
    def _update_context(self, analysis: Dict, state: AgentState):
        """Update conversation context"""
        self.context.urgency_level = max(
            self.context.urgency_level,
            analysis["urgency"]
        )
        self.context.last_state = state
        self.context.state_counts[state] = self.context.state_counts.get(state, 0) + 1
        
        # Track if they requested info
        if analysis["info_request"]:
            self.context.scammer_requests.append("personal_info")
        if analysis["money_mention"]:
            self.context.scammer_requests.append("money")
    
    def add_agent_response(self, response: str):
        """Record agent's response in history"""
        self.context.turns.append({
            "role": "agent",
            "text": response,
            "timestamp": time.time()
        })
    
    def get_conversation_summary(self) -> str:
        """Get a summary of the conversation for context"""
        recent_turns = self.context.turns[-6:]  # Last 3 exchanges
        summary = []
        for turn in recent_turns:
            role = "Caller" if turn["role"] == "scammer" else "You"
            summary.append(f"{role}: {turn['text']}")
        return "\n".join(summary)
    
    def get_state_info(self, state: AgentState) -> Dict:
        """Get information about a state for LLM prompting"""
        return {
            "state": state.name,
            "description": self._get_state_description(state),
            "example_phrases": self._get_example_phrases(state),
        }
    
    def _get_state_description(self, state: AgentState) -> str:
        """Get description of what the state means"""
        descriptions = {
            AgentState.CLARIFY: "Ask them to repeat or explain. Act hard of hearing.",
            AgentState.CONFUSE: "Be confused. Misunderstand on purpose. Go off-topic.",
            AgentState.STALL: "Delay and waste time. Pretend to look for things.",
            AgentState.EXTRACT: "Subtly ask about their operation or location.",
            AgentState.DEFLECT: "Change subject. Avoid giving any information.",
        }
        return descriptions.get(state, "")
    
    def _get_example_phrases(self, state: AgentState) -> List[str]:
        """Get example phrases for each state"""
        phrases = {
            AgentState.CLARIFY: [
                "I'm sorry, could you repeat that?",
                "What was that about the... what did you say?",
                "My hearing isn't so good, speak up please.",
            ],
            AgentState.CONFUSE: [
                "Oh, is this about my library books?",
                "I thought you were calling about my cat.",
                "Wait, I already paid my cable bill.",
            ],
            AgentState.STALL: [
                "Hold on, let me find my glasses...",
                "One moment, someone's at the door.",
                "Let me get a pen to write this down...",
            ],
            AgentState.EXTRACT: [
                "And where are you calling from exactly?",
                "What company did you say this was?",
                "Can I have your supervisor's name?",
            ],
            AgentState.DEFLECT: [
                "Oh my, did I tell you about my grandson?",
                "Speaking of which, do you know a good recipe for pie?",
                "That reminds me of this show I was watching...",
            ],
        }
        return phrases.get(state, [])


def create_state_machine() -> StateMachine:
    """Factory function to create state machine instance"""
    return StateMachine()
