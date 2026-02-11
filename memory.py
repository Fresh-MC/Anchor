# Conversation Memory for ANCHOR API Mode
# Stores conversation history and engagement metrics

"""
Conversation Memory - Session State Management
==============================================
Maintains conversation state for API-driven interactions:
- Full conversation history
- Engagement turn counter
- Cumulative extracted artifacts
- Session metadata

DESIGN:
- In-memory storage (no persistence for hackathon)
- Thread-safe for concurrent sessions
- Automatic summarization after N turns
"""

import time
import threading
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import uuid

from extractor import ExtractedArtifacts


@dataclass
class ConversationTurn:
    """Single turn in conversation"""
    role: str  # "scammer" or "agent"
    message: str
    timestamp: float
    state: Optional[str] = None
    artifacts: Optional[Dict] = None
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "role": self.role,
            "message": self.message,
            "timestamp": self.timestamp,
            "state": self.state,
            "artifacts": self.artifacts,
            "metadata": self.metadata,
        }


@dataclass
class SessionMetrics:
    """Engagement and security metrics for session"""
    total_turns: int = 0
    scammer_turns: int = 0
    agent_turns: int = 0
    jailbreak_attempts: int = 0
    extract_triggers: int = 0
    state_distribution: Dict[str, int] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "total_turns": self.total_turns,
            "scammer_turns": self.scammer_turns,
            "agent_turns": self.agent_turns,
            "jailbreak_attempts": self.jailbreak_attempts,
            "extract_triggers": self.extract_triggers,
            "state_distribution": self.state_distribution,
            "session_duration_seconds": time.time() - self.start_time,
            "start_time": self.start_time,
            "last_activity": self.last_activity,
        }


class ConversationMemory:
    """
    In-memory conversation storage for a single session.
    
    Features:
    - Full conversation history
    - Cumulative artifact extraction
    - Engagement metrics
    - State tracking
    """
    
    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.history: List[ConversationTurn] = []
        self.cumulative_artifacts = ExtractedArtifacts()
        self.metrics = SessionMetrics()
        self._lock = threading.Lock()
    
    @property
    def engagement_turn(self) -> int:
        """Get current engagement turn (1-indexed, counts scammer messages only)"""
        return self.metrics.scammer_turns
    
    def add_scammer_message(
        self,
        message: str,
        state: Optional[str] = None,
        artifacts: Optional[ExtractedArtifacts] = None,
        is_jailbreak: bool = False,
        is_extract_trigger: bool = False,
    ) -> None:
        """
        Add scammer message to history.
        
        Args:
            message: Scammer's message text
            state: State triggered by this message
            artifacts: Extracted artifacts (if any)
            is_jailbreak: Whether this was a jailbreak attempt
            is_extract_trigger: Whether this triggered EXTRACT state
        """
        with self._lock:
            turn = ConversationTurn(
                role="scammer",
                message=message,
                timestamp=time.time(),
                state=state,
                artifacts=artifacts.to_dict() if artifacts else None,
                metadata={
                    "is_jailbreak": is_jailbreak,
                    "is_extract_trigger": is_extract_trigger,
                }
            )
            self.history.append(turn)
            
            # Update metrics
            self.metrics.total_turns += 1
            self.metrics.scammer_turns += 1
            self.metrics.last_activity = time.time()
            
            if state:
                self.metrics.state_distribution[state] = \
                    self.metrics.state_distribution.get(state, 0) + 1
            
            if is_jailbreak:
                self.metrics.jailbreak_attempts += 1
            
            if is_extract_trigger:
                self.metrics.extract_triggers += 1
            
            # Merge artifacts
            if artifacts:
                self.cumulative_artifacts.merge(artifacts)
    
    def add_agent_response(
        self,
        message: str,
        state: str,
    ) -> None:
        """
        Add agent response to history.
        
        Args:
            message: Agent's response text
            state: State that generated this response
        """
        with self._lock:
            turn = ConversationTurn(
                role="agent",
                message=message,
                timestamp=time.time(),
                state=state,
            )
            self.history.append(turn)
            
            # Update metrics
            self.metrics.total_turns += 1
            self.metrics.agent_turns += 1
            self.metrics.last_activity = time.time()
    
    def get_conversation_log(self, max_turns: Optional[int] = None) -> List[Dict]:
        """
        Get conversation history as list of dicts.
        
        Args:
            max_turns: Limit to last N turns (None = all)
            
        Returns:
            List of turn dictionaries
        """
        with self._lock:
            history = self.history[-max_turns:] if max_turns else self.history
            return [turn.to_dict() for turn in history]
    
    def get_recent_context(self, max_turns: int = 4) -> str:
        """
        Get recent conversation as formatted string.
        For display/debugging purposes.
        
        Args:
            max_turns: Number of recent turns to include
            
        Returns:
            Formatted conversation string
        """
        with self._lock:
            recent = self.history[-max_turns:]
            lines = []
            for turn in recent:
                role = "Scammer" if turn.role == "scammer" else "Agent"
                lines.append(f"{role}: {turn.message}")
            return "\n".join(lines)
    
    def get_all_artifacts(self) -> Dict[str, List]:
        """Get all extracted artifacts across session"""
        with self._lock:
            return self.cumulative_artifacts.to_dict()
    
    def get_metrics(self) -> Dict:
        """Get session metrics"""
        with self._lock:
            return self.metrics.to_dict()
    
    def reset(self) -> None:
        """Reset session (new conversation)"""
        with self._lock:
            self.history.clear()
            self.cumulative_artifacts = ExtractedArtifacts()
            self.metrics = SessionMetrics()


class MemoryManager:
    """
    Manages multiple conversation sessions.
    
    For multi-session scenarios (multiple concurrent scammers).
    """
    
    def __init__(self):
        self._sessions: Dict[str, ConversationMemory] = {}
        self._lock = threading.Lock()
    
    def get_or_create_session(self, session_id: Optional[str] = None) -> ConversationMemory:
        """
        Get existing session or create new one.
        
        Args:
            session_id: Session ID (auto-generated if None)
            
        Returns:
            ConversationMemory for the session
        """
        with self._lock:
            if session_id and session_id in self._sessions:
                return self._sessions[session_id]
            
            # Create new session
            memory = ConversationMemory(session_id)
            self._sessions[memory.session_id] = memory
            return memory
    
    def get_session(self, session_id: str) -> Optional[ConversationMemory]:
        """Get session by ID"""
        with self._lock:
            return self._sessions.get(session_id)
    
    def delete_session(self, session_id: str) -> bool:
        """Delete session"""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False
    
    def list_sessions(self) -> List[str]:
        """List all session IDs"""
        with self._lock:
            return list(self._sessions.keys())
    
    def cleanup_stale_sessions(self, max_idle_seconds: float = 3600) -> int:
        """
        Remove sessions that have been idle too long.
        
        Args:
            max_idle_seconds: Maximum idle time before cleanup
            
        Returns:
            Number of sessions cleaned up
        """
        now = time.time()
        stale = []
        
        with self._lock:
            for session_id, memory in self._sessions.items():
                if now - memory.metrics.last_activity > max_idle_seconds:
                    stale.append(session_id)
            
            for session_id in stale:
                del self._sessions[session_id]
        
        return len(stale)


# Global memory manager instance
_memory_manager = MemoryManager()


def get_memory_manager() -> MemoryManager:
    """Get global memory manager"""
    return _memory_manager


def create_memory(session_id: Optional[str] = None) -> ConversationMemory:
    """Create new conversation memory"""
    return ConversationMemory(session_id)
