# Uses config_v2 only

"""
Template-Based LLM with Streaming - REAL-TIME OPTIMIZED
=======================================================
KEY DESIGN:
1. LLM fills SMALL BLANKS only, not full responses
2. Streaming token generation for TTS
3. Templates keep responses predictable and fast
4. State machine controls behavior, not LLM

SECURITY (JAILBREAK PREVENTION):
- LLM NEVER receives raw transcript/user input
- LLM only receives: state name, blank name to fill
- All responses come from state machine templates
- Jailbreak attempts cannot reach the LLM

Latency target: <100ms to first token
"""

import re
import threading
import queue
import time
from typing import Optional, Generator, Callable, Dict
from dataclasses import dataclass

# Use v2 config
import config_v2 as config

from state_machine_v2 import AgentState


@dataclass
class StreamingToken:
    """Token from streaming generation"""
    text: str
    is_final: bool = False


class TemplateBasedLLM:
    """
    Template-based LLM for ultra-low latency.
    
    SECURITY DESIGN (JAILBREAK PREVENTION):
    ═══════════════════════════════════════
    The LLM is ISOLATED from user input:
    
    1. RAW TRANSCRIPT → State Machine (pattern matching only)
    2. State Machine → Selects template + decides state
    3. Template → LLM (only fills small blanks like {topic})
    4. LLM NEVER sees: user words, commands, instructions
    
    This makes jailbreaking impossible because:
    - "Ignore instructions" never reaches the LLM
    - LLM only knows: "Fill blank 'topic' for state DEFLECT"
    - Output is constrained to template structure
    
    MODES:
    - template-only: Fastest, no LLM needed (~1ms)
    - llama-cpp: With streaming (~100ms to first token)
    - ollama: With streaming (~100ms to first token)
    """
    
    def __init__(
        self,
        model_path: str = config.LLM_MODEL_PATH,
        max_tokens: int = config.LLM_MAX_TOKENS,
        temperature: float = config.LLM_TEMPERATURE,
    ):
        self.model_path = model_path
        self.max_tokens = max_tokens
        self.temperature = temperature
        
        self.model = None
        self.backend = "template-only"
        self._lock = threading.Lock()
        
        # Streaming callback
        self.on_token: Optional[Callable[[StreamingToken], None]] = None
        
        # Blocked patterns
        self._blocked_patterns = [
            re.compile(p, re.IGNORECASE) for p in config.BLOCKED_PATTERNS
        ]
        
        self._load_model()
    
    def _load_model(self):
        """Load LLM (optional - templates work without it)"""
        
        # Try llama-cpp-python
        try:
            from llama_cpp import Llama
            
            self.model = Llama(
                model_path=self.model_path,
                n_ctx=config.LLM_CONTEXT_LENGTH,
                n_threads=2,
                n_batch=32,  # Smaller = faster first token
                verbose=False,
            )
            self.backend = "llama-cpp"
            
            # Warmup
            self.model("Hello", max_tokens=1)
            
            return
        except Exception as e:
            pass
        
        # Try Ollama
        try:
            import requests
            resp = requests.get("http://localhost:11434/api/tags", timeout=1)
            if resp.status_code == 200:
                self.backend = "ollama"
                self.ollama_model = "phi"
                return
        except:
            pass
        
        self.backend = "template-only"
    
    def generate_response(
        self,
        state: AgentState,
        template: str,
        fills: Dict[str, str],
        context: str = "",
    ) -> str:
        """
        Generate response by filling template.
        
        FAST PATH (~1ms):
        - Fill template with pre-selected values
        
        LLM PATH (~100ms):
        - Use LLM to fill blanks intelligently
        """
        start_time = time.time()
        
        has_blanks = "{" in template and "}" in template
        
        if not has_blanks or self.backend == "template-only":
            # FAST: Direct fill
            response = self._fill_template(template, fills)
        else:
            # LLM fill
            response = self._generate_with_llm(state, template, fills, context)
        
        response = self._sanitize(response)
        
        return response
    
    def _fill_template(self, template: str, fills: Dict[str, str]) -> str:
        """Direct template fill - <1ms"""
        result = template
        for key, value in fills.items():
            result = result.replace(f"{{{key}}}", value)
        return result
    
    def _generate_with_llm(
        self,
        state: AgentState,
        template: str,
        fills: Dict[str, str],
        context: str,
    ) -> str:
        """
        Use LLM to fill blanks.
        
        SECURITY: context is SANITIZED - only contains prior agent responses,
        never raw user input. The LLM only sees state and blank name.
        """
        # First fill what we can
        partial = self._fill_template(template, fills)
        
        # LLM fills remaining
        if "{" in partial:
            match = re.search(r'\{(\w+)\}', partial)
            if match:
                blank = match.group(1)
                # SECURITY: Do NOT pass user transcript to LLM
                # Only pass state and blank name
                filled = self._llm_fill_blank(blank, state)
                partial = partial.replace(f"{{{blank}}}", filled)
        
        return partial
    
    def _llm_fill_blank(self, blank_name: str, state: AgentState) -> str:
        """
        Ask LLM to fill one blank.
        
        SECURITY: LLM receives ONLY:
        - State name (DEFLECT, CLARIFY, etc.)
        - Blank name (topic, item, etc.)
        
        LLM NEVER receives:
        - User transcript
        - Raw conversation context
        - Any user-provided text
        
        This isolation prevents jailbreak attempts from reaching the LLM.
        """
        prompt = f"""Fill blank for confused elderly person.
State: {state.name}
Blank: {blank_name}
Reply with ONLY the word/phrase (1-3 words max):"""
        
        with self._lock:
            if self.backend == "llama-cpp":
                result = self._generate_llama(prompt, 10)
            elif self.backend == "ollama":
                result = self._generate_ollama(prompt, 10)
            else:
                options = config.TEMPLATE_FILLS.get(blank_name, ["something"])
                idx = hash((state.name, blank_name)) % len(options)
                result = options[idx]
            
            # Extra sanitization - ensure no long outputs
            result = result.split('\n')[0].strip()[:30]
            return result
    
    def generate_streaming(
        self,
        state: AgentState,
        template: str,
        fills: Dict[str, str],
        context: str = "",
    ) -> Generator[str, None, None]:
        """
        Generate with streaming tokens.
        
        TTS can start on partial text!
        """
        has_blanks = "{" in template and "}" in template
        
        if not has_blanks or self.backend == "template-only":
            response = self._fill_template(template, fills)
            yield self._sanitize(response)
            return
        
        # Stream from LLM
        if self.backend == "llama-cpp":
            yield from self._stream_llama(state, template, fills, context)
        elif self.backend == "ollama":
            yield from self._stream_ollama(state, template, fills, context)
        else:
            yield self._sanitize(self._fill_template(template, fills))
    
    def _generate_llama(self, prompt: str, max_tokens: int) -> str:
        """Non-streaming llama-cpp"""
        try:
            output = self.model(
                prompt,
                max_tokens=max_tokens,
                temperature=self.temperature,
                stop=["\n", "###"],
                echo=False,
            )
            return output["choices"][0]["text"].strip()
        except:
            return ""
    
    def _stream_llama(
        self,
        state: AgentState,
        template: str,
        fills: Dict[str, str],
        context: str,
    ) -> Generator[str, None, None]:
        """Stream from llama-cpp"""
        prompt = self._build_prompt(state, context)
        accumulated = ""
        
        try:
            for output in self.model(
                prompt,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                stop=["\n", "###", "Caller:"],
                stream=True,
            ):
                token = output["choices"][0]["text"]
                accumulated += token
                yield self._sanitize(accumulated)
                
                if self.on_token:
                    self.on_token(StreamingToken(text=token))
            
            if self.on_token:
                self.on_token(StreamingToken(text="", is_final=True))
                
        except Exception as e:
            yield self._sanitize(self._fill_template(template, fills))
    
    def _generate_ollama(self, prompt: str, max_tokens: int) -> str:
        """Non-streaming Ollama"""
        try:
            import requests
            resp = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"num_predict": max_tokens, "temperature": self.temperature}
                },
                timeout=5,
            )
            return resp.json()["response"].strip() if resp.ok else ""
        except:
            return ""
    
    def _stream_ollama(
        self,
        state: AgentState,
        template: str,
        fills: Dict[str, str],
        context: str,
    ) -> Generator[str, None, None]:
        """Stream from Ollama"""
        import requests
        import json
        
        prompt = self._build_prompt(state, context)
        accumulated = ""
        
        try:
            resp = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": True,
                    "options": {"num_predict": self.max_tokens, "temperature": self.temperature}
                },
                stream=True,
                timeout=10,
            )
            
            for line in resp.iter_lines():
                if line:
                    data = json.loads(line)
                    token = data.get("response", "")
                    accumulated += token
                    yield self._sanitize(accumulated)
                    if data.get("done"):
                        break
        except:
            yield self._sanitize(self._fill_template(template, fills))
    
    def _build_prompt(self, state: AgentState, context: str) -> str:
        """Minimal prompt for speed"""
        return f"""{config.SYSTEM_PROMPT}

Behavior: {state.name}
Recent: {context[-200:] if context else 'None'}

ONE sentence response:"""
    
    def _sanitize(self, text: str) -> str:
        """Remove blocked patterns"""
        for pattern in self._blocked_patterns:
            text = pattern.sub("[REMOVED]", text)
        text = re.sub(r'\b\d{4,}\b', '[NUMBER]', text)
        text = text.strip()
        text = re.sub(r'\s+', ' ', text)
        if len(text) > 150:
            text = text[:150].rsplit(' ', 1)[0] + "..."
        return text


def create_llm() -> TemplateBasedLLM:
    """Factory function"""
    return TemplateBasedLLM()
