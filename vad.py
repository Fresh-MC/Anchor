"""
Voice Activity Detection using Silero VAD
Detects speech start/end from audio stream
"""

import numpy as np
import torch
import threading
from collections import deque
from typing import Callable, Optional
import time

import config


class SileroVAD:
    """
    Silero VAD wrapper for real-time speech detection
    """
    
    def __init__(
        self,
        threshold: float = config.VAD_THRESHOLD,
        min_speech_duration_ms: int = config.VAD_MIN_SPEECH_DURATION_MS,
        min_silence_duration_ms: int = config.VAD_MIN_SILENCE_DURATION_MS,
        sample_rate: int = config.SAMPLE_RATE,
    ):
        self.threshold = threshold
        self.min_speech_duration_ms = min_speech_duration_ms
        self.min_silence_duration_ms = min_silence_duration_ms
        self.sample_rate = sample_rate
        
        # Load Silero VAD model
        self.model = None
        self._load_model()
        
        # State tracking
        self.is_speaking = False
        self.speech_start_time: Optional[float] = None
        self.silence_start_time: Optional[float] = None
        self.audio_buffer = deque(maxlen=int(sample_rate * 30))  # 30 sec buffer
        self.speech_buffer = []
        
        # Callbacks
        self.on_speech_start: Optional[Callable] = None
        self.on_speech_end: Optional[Callable[[np.ndarray], None]] = None
        
        self._lock = threading.Lock()
    
    def _load_model(self):
        """Load Silero VAD model from torch hub"""
        try:
            self.model, utils = torch.hub.load(
                repo_or_dir='snakers4/silero-vad',
                model='silero_vad',
                force_reload=False,
                trust_repo=True
            )
            self.model.eval()
            print("[VAD] Silero VAD model loaded successfully")
        except Exception as e:
            print(f"[VAD] Error loading Silero VAD: {e}")
            print("[VAD] Running in placeholder mode")
            self.model = None
    
    def reset_states(self):
        """Reset VAD state for new conversation"""
        if self.model is not None:
            self.model.reset_states()
        self.is_speaking = False
        self.speech_start_time = None
        self.silence_start_time = None
        self.speech_buffer.clear()
    
    def process_chunk(self, audio_chunk: np.ndarray) -> bool:
        """
        Process an audio chunk and detect speech activity
        
        Args:
            audio_chunk: Audio samples as numpy array (int16 or float32)
            
        Returns:
            True if speech is currently detected, False otherwise
        """
        with self._lock:
            # Convert to float32 if needed
            if audio_chunk.dtype == np.int16:
                audio_float = audio_chunk.astype(np.float32) / 32768.0
            else:
                audio_float = audio_chunk.astype(np.float32)
            
            # Get speech probability
            speech_prob = self._get_speech_probability(audio_float)
            current_time = time.time()
            
            # State machine for speech detection
            if speech_prob >= self.threshold:
                # Speech detected
                self.silence_start_time = None
                
                if not self.is_speaking:
                    # Speech just started
                    if self.speech_start_time is None:
                        self.speech_start_time = current_time
                    
                    # Check minimum speech duration
                    speech_duration_ms = (current_time - self.speech_start_time) * 1000
                    if speech_duration_ms >= self.min_speech_duration_ms:
                        self.is_speaking = True
                        self.speech_buffer.clear()
                        if self.on_speech_start:
                            self.on_speech_start()
                
                # Buffer audio during speech
                if self.is_speaking:
                    self.speech_buffer.append(audio_chunk.copy())
                    
            else:
                # Silence detected
                self.speech_start_time = None
                
                if self.is_speaking:
                    # Still buffer during potential pause
                    self.speech_buffer.append(audio_chunk.copy())
                    
                    if self.silence_start_time is None:
                        self.silence_start_time = current_time
                    
                    # Check minimum silence duration
                    silence_duration_ms = (current_time - self.silence_start_time) * 1000
                    if silence_duration_ms >= self.min_silence_duration_ms:
                        # Speech ended - trigger callback
                        self.is_speaking = False
                        self.silence_start_time = None
                        
                        if self.speech_buffer and self.on_speech_end:
                            speech_audio = np.concatenate(self.speech_buffer)
                            self.speech_buffer.clear()
                            self.on_speech_end(speech_audio)
            
            return self.is_speaking
    
    def _get_speech_probability(self, audio_float: np.ndarray) -> float:
        """Get speech probability from Silero model"""
        if self.model is None:
            # Placeholder: simple energy-based detection
            energy = np.sqrt(np.mean(audio_float ** 2))
            return min(1.0, energy * 10)
        
        try:
            # Silero expects tensor input
            audio_tensor = torch.from_numpy(audio_float)
            speech_prob = self.model(audio_tensor, self.sample_rate).item()
            return speech_prob
        except Exception as e:
            print(f"[VAD] Error in speech detection: {e}")
            return 0.0
    
    def get_current_speech_audio(self) -> Optional[np.ndarray]:
        """Get currently buffered speech audio"""
        with self._lock:
            if self.speech_buffer:
                return np.concatenate(self.speech_buffer)
            return None


def create_vad() -> SileroVAD:
    """Factory function to create VAD instance"""
    return SileroVAD()


# Placeholder for testing without actual VAD
class PlaceholderVAD:
    """Simple placeholder VAD for testing"""
    
    def __init__(self):
        self.is_speaking = False
        self.on_speech_start = None
        self.on_speech_end = None
        self.speech_buffer = []
        self.silence_counter = 0
    
    def reset_states(self):
        self.is_speaking = False
        self.speech_buffer.clear()
        self.silence_counter = 0
    
    def process_chunk(self, audio_chunk: np.ndarray) -> bool:
        # Simple energy-based detection for testing
        if audio_chunk.dtype == np.int16:
            audio_float = audio_chunk.astype(np.float32) / 32768.0
        else:
            audio_float = audio_chunk
        
        energy = np.sqrt(np.mean(audio_float ** 2))
        is_speech = energy > 0.01
        
        if is_speech:
            self.silence_counter = 0
            if not self.is_speaking:
                self.is_speaking = True
                if self.on_speech_start:
                    self.on_speech_start()
            self.speech_buffer.append(audio_chunk.copy())
        else:
            if self.is_speaking:
                self.silence_counter += 1
                self.speech_buffer.append(audio_chunk.copy())
                
                if self.silence_counter > 15:  # ~500ms of silence
                    self.is_speaking = False
                    if self.speech_buffer and self.on_speech_end:
                        speech_audio = np.concatenate(self.speech_buffer)
                        self.speech_buffer.clear()
                        self.on_speech_end(speech_audio)
                    self.silence_counter = 0
        
        return self.is_speaking
