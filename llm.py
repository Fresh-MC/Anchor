"""
Local LLM for response generation
Uses Llama.cpp or similar for fast inference
"""

import re
from typing import Optional, List
import threading
import time

import config
from state_machine import AgentState


class LocalLLM:
    """
    Local LLM wrapper for response generation
    Supports llama.cpp, Ollama, or other local inference
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
        self._lock = threading.Lock()
        
        # Try to load model
        self._load_model()
        
        # Compiled regex for blocked patterns
        self.blocked_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in config.BLOCKED_PATTERNS
        ]
    
    def _load_model(self):
        """Load the local LLM model"""
        # Try llama-cpp-python first
        try:
            from llama_cpp import Llama
            self.model = Llama(
                model_path=self.model_path,
                n_ctx=2048,
                n_threads=4,
                verbose=False,
            )
            self.backend = "llama-cpp"
            print(f"[LLM] Loaded model with llama-cpp-python")
            return
        except (ImportError, Exception) as e:
            print(f"[LLM] llama-cpp-python not available: {e}")
        
        # Try Ollama
        try:
            import requests
            response = requests.get("http://localhost:11434/api/tags", timeout=2)
            if response.status_code == 200:
                self.backend = "ollama"
                self.ollama_model = "phi"  # or "llama2", "mistral", etc.
                print(f"[LLM] Using Ollama backend with {self.ollama_model}")
                return
        except Exception as e:
            print(f"[LLM] Ollama not available: {e}")
        
        # Fallback to placeholder
        print("[LLM] No LLM backend available, using placeholder mode")
        self.backend = "placeholder"
    
    def generate_response(
        self,
        state: AgentState,
        conversation_context: str,
        state_info: dict,
    ) -> str:
        """
        Generate a response based on state and context
        
        Args:
            state: Current agent state
            conversation_context: Recent conversation history
            state_info: Information about the current state
            
        Returns:
            Generated response text
        """
        with self._lock:
            start_time = time.time()
            
            # Build prompt
            prompt = self._build_prompt(state, conversation_context, state_info)
            
            # Generate response
            if self.backend == "llama-cpp":
                response = self._generate_llama_cpp(prompt)
            elif self.backend == "ollama":
                response = self._generate_ollama(prompt)
            else:
                response = self._generate_placeholder(state, state_info)
            
            # Sanitize response
            response = self._sanitize_response(response)
            
            elapsed_ms = (time.time() - start_time) * 1000
            print(f"[LLM] Generation took {elapsed_ms:.0f}ms")
            
            return response
    
    def _build_prompt(
        self,
        state: AgentState,
        conversation_context: str,
        state_info: dict,
    ) -> str:
        """Build the prompt for the LLM"""
        system_prompt = config.SYSTEM_PROMPT
        state_prompt = config.STATE_PROMPTS.get(state.name, "")
        
        prompt = f"""### System:
{system_prompt}

### Current Behavior:
{state_prompt}
{state_info.get('description', '')}

### Recent Conversation:
{conversation_context}

### Instructions:
Generate a short response (1-2 sentences) that matches the behavior above.
Do NOT include any phone numbers, codes, PINs, or passwords.
Stay in character as a confused elderly person.

### Response:"""
        
        return prompt
    
    def _generate_llama_cpp(self, prompt: str) -> str:
        """Generate using llama-cpp-python"""
        try:
            output = self.model(
                prompt,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                stop=["###", "\n\n", "Caller:", "You:"],
                echo=False,
            )
            return output["choices"][0]["text"].strip()
        except Exception as e:
            print(f"[LLM] Generation error: {e}")
            return ""
    
    def _generate_ollama(self, prompt: str) -> str:
        """Generate using Ollama API"""
        try:
            import requests
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "num_predict": self.max_tokens,
                        "temperature": self.temperature,
                    }
                },
                timeout=10,
            )
            if response.status_code == 200:
                return response.json()["response"].strip()
        except Exception as e:
            print(f"[LLM] Ollama error: {e}")
        return ""
    
    def _generate_placeholder(self, state: AgentState, state_info: dict) -> str:
        """Generate placeholder response for testing"""
        import random
        
        example_phrases = state_info.get("example_phrases", [])
        if example_phrases:
            return random.choice(example_phrases)
        
        # Default responses by state
        defaults = {
            AgentState.CLARIFY: "I'm sorry dear, could you say that again? My hearing isn't what it used to be.",
            AgentState.CONFUSE: "Oh my, I thought this was about my doctor's appointment. What were we talking about?",
            AgentState.STALL: "Hold on just a moment, let me find my reading glasses...",
            AgentState.EXTRACT: "And where did you say you were calling from again?",
            AgentState.DEFLECT: "That reminds me, have I told you about my cat? She's such a sweet thing.",
        }
        return defaults.get(state, "I'm sorry, what was that?")
    
    def _sanitize_response(self, response: str) -> str:
        """Remove any blocked patterns from response"""
        # Remove blocked patterns
        for pattern in self.blocked_patterns:
            response = pattern.sub("[REMOVED]", response)
        
        # Remove any remaining digit sequences that look like codes
        response = re.sub(r'\b\d{4,}\b', '[NUMBER]', response)
        
        # Clean up artifacts
        response = response.strip()
        response = re.sub(r'\s+', ' ', response)
        
        # Truncate if too long
        if len(response) > 200:
            response = response[:200].rsplit(' ', 1)[0] + "..."
        
        return response


def create_llm() -> LocalLLM:
    """Factory function to create LLM instance"""
    return LocalLLM()


# Async wrapper for non-blocking generation
class AsyncLLM:
    """Async wrapper for LLM to avoid blocking main loop"""
    
    def __init__(self, llm: LocalLLM):
        self.llm = llm
        self._result = None
        self._thread = None
        self._done = threading.Event()
    
    def generate_async(
        self,
        state: AgentState,
        conversation_context: str,
        state_info: dict,
    ):
        """Start async generation"""
        self._done.clear()
        self._result = None
        self._thread = threading.Thread(
            target=self._generate_worker,
            args=(state, conversation_context, state_info)
        )
        self._thread.start()
    
    def _generate_worker(self, state, context, state_info):
        """Worker thread for generation"""
        self._result = self.llm.generate_response(state, context, state_info)
        self._done.set()
    
    def get_result(self, timeout: float = 5.0) -> Optional[str]:
        """Get generation result (blocking)"""
        if self._done.wait(timeout=timeout):
            return self._result
        return None
    
    def is_done(self) -> bool:
        """Check if generation is complete"""
        return self._done.is_set()
