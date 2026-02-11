# Uses config_v2 only

"""
Streaming TTS - REAL-TIME OPTIMIZED
===================================
KEY FEATURES:
1. Streaming synthesis (start before full text)
2. Background thread for non-blocking
3. Audio queue for smooth playback

Latency target: <150ms from text to first audio
"""

import numpy as np
import threading
import queue
import time
from typing import Optional, Generator, Callable, List
import os

# Use v2 config
import config_v2 as config


class StreamingTTS:
    """
    TTS with streaming for real-time voice loop.
    
    STREAMING PIPELINE:
    1. Receive text chunks from LLM
    2. Buffer until phrase complete (~20 chars)
    3. Synthesize in background
    4. Queue audio for playback
    
    Enables: LLM generate -> TTS synthesize -> Play (concurrent)
    """
    
    def __init__(
        self,
        model_name: str = config.TTS_MODEL_NAME,
        sample_rate: int = config.SAMPLE_RATE,
    ):
        self.model_name = model_name
        self.sample_rate = sample_rate
        
        self.tts = None
        self.backend = "placeholder"
        self._lock = threading.Lock()
        
        # Audio queue for non-blocking playback
        self.audio_queue: queue.Queue[Optional[np.ndarray]] = queue.Queue()
        
        # Callback when audio ready
        self.on_audio_ready: Optional[Callable[[np.ndarray], None]] = None
        
        self._load_model()
    
    def _load_model(self):
        """Load TTS model"""
        
        # Try Coqui TTS
        try:
            from TTS.api import TTS
            
            self.tts = TTS(model_name=self.model_name, progress_bar=False)
            self.backend = "coqui"
            
            # Warmup
            _ = self.tts.tts("Hello")
            
            print(f"[TTS] Coqui loaded: {self.model_name}")
            return
        except ImportError:
            print("[TTS] Coqui not installed")
        except Exception as e:
            print(f"[TTS] Coqui error: {e}")
        
        # Try pyttsx3
        try:
            import pyttsx3
            self.pyttsx_engine = pyttsx3.init()
            self.pyttsx_engine.setProperty('rate', 150)
            self.backend = "pyttsx3"
            print("[TTS] pyttsx3 loaded")
            return
        except Exception as e:
            print(f"[TTS] pyttsx3 error: {e}")
        
        print("[TTS] Placeholder mode")
        self.backend = "placeholder"
    
    def synthesize(self, text: str) -> Optional[np.ndarray]:
        """
        Synthesize text to audio (blocking).
        
        Returns:
            Audio as int16 numpy array
        """
        if not text or not text.strip():
            return None
        
        with self._lock:
            start_time = time.time()
            
            if self.backend == "coqui":
                audio = self._synthesize_coqui(text)
            elif self.backend == "pyttsx3":
                audio = self._synthesize_pyttsx3(text)
            else:
                audio = self._synthesize_placeholder(text)
            
            elapsed_ms = (time.time() - start_time) * 1000
            duration_ms = len(audio) / self.sample_rate * 1000 if audio is not None else 0
            print(f"[TTS] {elapsed_ms:.0f}ms for {duration_ms:.0f}ms audio")
            
            return audio
    
    def _synthesize_coqui(self, text: str) -> Optional[np.ndarray]:
        """Coqui TTS synthesis"""
        try:
            wav = self.tts.tts(text=text)
            
            if isinstance(wav, list):
                wav = np.array(wav, dtype=np.float32)
            
            # Resample if needed
            if hasattr(self.tts, 'synthesizer') and self.tts.synthesizer:
                tts_sr = self.tts.synthesizer.output_sample_rate
                if tts_sr != self.sample_rate:
                    wav = self._resample(wav, tts_sr, self.sample_rate)
            
            return (wav * 32767).astype(np.int16)
        except Exception as e:
            print(f"[TTS] Error: {e}")
            return None
    
    def _synthesize_pyttsx3(self, text: str) -> Optional[np.ndarray]:
        """pyttsx3 synthesis"""
        try:
            import tempfile
            import wave
            
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
                temp_path = f.name
            
            self.pyttsx_engine.save_to_file(text, temp_path)
            self.pyttsx_engine.runAndWait()
            
            with wave.open(temp_path, 'r') as wf:
                audio = np.frombuffer(wf.readframes(wf.getnframes()), dtype=np.int16)
            
            os.unlink(temp_path)
            return audio
        except Exception as e:
            print(f"[TTS] Error: {e}")
            return None
    
    def _synthesize_placeholder(self, text: str) -> np.ndarray:
        """Placeholder silence"""
        duration_sec = len(text.split()) * 0.25
        return np.zeros(int(self.sample_rate * duration_sec), dtype=np.int16)
    
    def _resample(self, audio: np.ndarray, orig_sr: int, target_sr: int) -> np.ndarray:
        """Resample audio"""
        try:
            import scipy.signal
            num_samples = int(len(audio) * target_sr / orig_sr)
            return scipy.signal.resample(audio, num_samples)
        except ImportError:
            ratio = target_sr / orig_sr
            new_len = int(len(audio) * ratio)
            indices = np.linspace(0, len(audio) - 1, new_len)
            return np.interp(indices, np.arange(len(audio)), audio)
    
    def synthesize_streaming(
        self, text_generator: Generator[str, None, None]
    ) -> Generator[np.ndarray, None, None]:
        """
        Synthesize from streaming text.
        
        STRATEGY:
        1. Accumulate until phrase complete (punctuation or min chars)
        2. Synthesize phrase
        3. Yield audio
        4. Continue
        
        Allows TTS to start before full text received!
        """
        buffer = ""
        last_text = ""
        
        for text in text_generator:
            # Get new text
            new_text = text[len(last_text):] if len(text) > len(last_text) else ""
            last_text = text
            buffer += new_text
            
            # Check for complete phrases
            phrases = self._split_phrases(buffer)
            
            for phrase in phrases[:-1]:
                if phrase.strip():
                    audio = self.synthesize(phrase)
                    if audio is not None:
                        yield audio
            
            buffer = phrases[-1] if phrases else ""
        
        # Final buffer
        if buffer.strip():
            audio = self.synthesize(buffer)
            if audio is not None:
                yield audio
    
    def _split_phrases(self, text: str) -> List[str]:
        """Split into phrases for incremental synthesis"""
        import re
        
        parts = re.split(r'([.!?]+\s*)', text)
        
        phrases = []
        current = ""
        
        for part in parts:
            current += part
            if len(current) >= config.TTS_MIN_CHUNK_CHARS:
                if re.search(r'[.!?,;]\s*$', current):
                    phrases.append(current)
                    current = ""
        
        phrases.append(current)
        return phrases


def create_tts() -> StreamingTTS:
    """Factory function"""
    return StreamingTTS()
