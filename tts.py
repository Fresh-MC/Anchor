"""
Text-to-Speech using Coqui TTS
Converts response text to audio for playback
"""

import numpy as np
import threading
import time
from typing import Optional
import os

import config


class CoquiTTS:
    """
    Coqui TTS wrapper for text-to-speech
    """
    
    def __init__(
        self,
        model_name: str = config.TTS_MODEL_NAME,
        sample_rate: int = config.SAMPLE_RATE,
    ):
        self.model_name = model_name
        self.sample_rate = sample_rate
        
        self.tts = None
        self._lock = threading.Lock()
        
        # Load model
        self._load_model()
    
    def _load_model(self):
        """Load Coqui TTS model"""
        try:
            from TTS.api import TTS
            
            # Use a fast model for low latency
            self.tts = TTS(model_name=self.model_name, progress_bar=False)
            print(f"[TTS] Loaded Coqui TTS model: {self.model_name}")
            
        except ImportError:
            print("[TTS] Coqui TTS not installed, trying pyttsx3...")
            self._try_pyttsx3()
        except Exception as e:
            print(f"[TTS] Error loading Coqui TTS: {e}")
            self._try_pyttsx3()
    
    def _try_pyttsx3(self):
        """Fallback to pyttsx3 for TTS"""
        try:
            import pyttsx3
            self.pyttsx_engine = pyttsx3.init()
            self.pyttsx_engine.setProperty('rate', 150)
            self.backend = "pyttsx3"
            print("[TTS] Using pyttsx3 backend")
        except Exception as e:
            print(f"[TTS] pyttsx3 not available: {e}")
            print("[TTS] Running in placeholder mode")
            self.backend = "placeholder"
    
    def synthesize(self, text: str) -> Optional[np.ndarray]:
        """
        Synthesize speech from text
        
        Args:
            text: Text to convert to speech
            
        Returns:
            Audio samples as numpy array (int16) or None
        """
        if not text:
            return None
            
        with self._lock:
            start_time = time.time()
            
            if self.tts is not None:
                audio = self._synthesize_coqui(text)
            elif hasattr(self, 'backend') and self.backend == "pyttsx3":
                audio = self._synthesize_pyttsx3(text)
            else:
                audio = self._synthesize_placeholder(text)
            
            elapsed_ms = (time.time() - start_time) * 1000
            if audio is not None:
                duration_ms = len(audio) / self.sample_rate * 1000
                print(f"[TTS] Synthesis took {elapsed_ms:.0f}ms for {duration_ms:.0f}ms audio")
            
            return audio
    
    def _synthesize_coqui(self, text: str) -> Optional[np.ndarray]:
        """Synthesize using Coqui TTS"""
        try:
            # Generate to numpy array
            wav = self.tts.tts(text=text)
            
            # Convert to numpy array
            if isinstance(wav, list):
                wav = np.array(wav, dtype=np.float32)
            
            # Resample if needed
            if hasattr(self.tts, 'synthesizer') and self.tts.synthesizer:
                tts_sr = self.tts.synthesizer.output_sample_rate
                if tts_sr != self.sample_rate:
                    wav = self._resample(wav, tts_sr, self.sample_rate)
            
            # Convert to int16
            wav_int16 = (wav * 32767).astype(np.int16)
            return wav_int16
            
        except Exception as e:
            print(f"[TTS] Coqui synthesis error: {e}")
            return None
    
    def _synthesize_pyttsx3(self, text: str) -> Optional[np.ndarray]:
        """Synthesize using pyttsx3 (writes to file, then reads)"""
        try:
            import tempfile
            import wave
            
            # pyttsx3 can only save to file
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
                temp_path = f.name
            
            self.pyttsx_engine.save_to_file(text, temp_path)
            self.pyttsx_engine.runAndWait()
            
            # Read the file
            with wave.open(temp_path, 'r') as wf:
                audio = np.frombuffer(wf.readframes(wf.getnframes()), dtype=np.int16)
            
            os.unlink(temp_path)
            return audio
            
        except Exception as e:
            print(f"[TTS] pyttsx3 synthesis error: {e}")
            return None
    
    def _synthesize_placeholder(self, text: str) -> Optional[np.ndarray]:
        """Generate placeholder silence for testing"""
        # Generate silence with length based on text
        duration_sec = len(text.split()) * 0.3  # ~300ms per word
        num_samples = int(self.sample_rate * duration_sec)
        return np.zeros(num_samples, dtype=np.int16)
    
    def _resample(self, audio: np.ndarray, orig_sr: int, target_sr: int) -> np.ndarray:
        """Resample audio to target sample rate"""
        try:
            import scipy.signal
            num_samples = int(len(audio) * target_sr / orig_sr)
            return scipy.signal.resample(audio, num_samples)
        except ImportError:
            # Simple linear interpolation fallback
            ratio = target_sr / orig_sr
            new_length = int(len(audio) * ratio)
            indices = np.linspace(0, len(audio) - 1, new_length)
            return np.interp(indices, np.arange(len(audio)), audio)


def create_tts() -> CoquiTTS:
    """Factory function to create TTS instance"""
    return CoquiTTS()


# Async wrapper for non-blocking synthesis
class AsyncTTS:
    """Async wrapper for TTS to avoid blocking main loop"""
    
    def __init__(self, tts: CoquiTTS):
        self.tts = tts
        self._result = None
        self._thread = None
        self._done = threading.Event()
    
    def synthesize_async(self, text: str):
        """Start async synthesis"""
        self._done.clear()
        self._result = None
        self._thread = threading.Thread(
            target=self._synthesize_worker,
            args=(text,)
        )
        self._thread.start()
    
    def _synthesize_worker(self, text: str):
        """Worker thread for synthesis"""
        self._result = self.tts.synthesize(text)
        self._done.set()
    
    def get_result(self, timeout: float = 10.0) -> Optional[np.ndarray]:
        """Get synthesis result (blocking)"""
        if self._done.wait(timeout=timeout):
            return self._result
        return None
    
    def is_done(self) -> bool:
        """Check if synthesis is complete"""
        return self._done.is_set()
