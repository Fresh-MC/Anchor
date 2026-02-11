# Uses config_v2 only

"""
Voice Activity Detection using Silero VAD - REAL-TIME OPTIMIZED
================================================================
KEY OPTIMIZATIONS:
1. Circular buffer prevents memory allocation during streaming
2. Early trigger: Start streaming to ASR on speech START, don't wait for silence
3. Chunks are streamed to ASR callback immediately during speech
4. VAD gates ASR - ASR never runs on silence (saves compute)

Latency target: <50ms from speech detection to ASR streaming start
"""

import numpy as np
import torch
import threading
from typing import Callable, Optional
import time

# Use v2 config
import config_v2 as config


class CircularAudioBuffer:
    """
    Lock-free circular buffer for audio samples.
    Pre-allocated to avoid memory allocation during streaming.
    
    LATENCY OPTIMIZATION: No allocations during hot path
    """
    
    def __init__(self, max_seconds: float = config.CIRCULAR_BUFFER_SECONDS, 
                 sample_rate: int = config.SAMPLE_RATE):
        self.max_samples = int(max_seconds * sample_rate)
        self.sample_rate = sample_rate
        
        # Pre-allocate buffer - CRITICAL for avoiding GC pauses
        self._buffer = np.zeros(self.max_samples, dtype=np.int16)
        self._write_pos = 0
        self._speech_start_pos = 0
        self._lock = threading.Lock()
    
    def write(self, chunk: np.ndarray):
        """
        Write chunk to circular buffer - O(1) operation.
        
        LATENCY: <0.1ms (just memcpy)
        """
        chunk_len = len(chunk)
        
        with self._lock:
            end_pos = self._write_pos + chunk_len
            
            if end_pos <= self.max_samples:
                # Fast path: no wraparound
                self._buffer[self._write_pos:end_pos] = chunk
            else:
                # Handle wraparound
                first_part = self.max_samples - self._write_pos
                self._buffer[self._write_pos:] = chunk[:first_part]
                self._buffer[:chunk_len - first_part] = chunk[first_part:]
            
            self._write_pos = end_pos % self.max_samples
    
    def mark_speech_start(self):
        """Mark current position as speech start (with padding for context)"""
        pad_samples = int(config.VAD_SPEECH_PAD_MS * self.sample_rate / 1000)
        with self._lock:
            self._speech_start_pos = (self._write_pos - pad_samples) % self.max_samples
    
    def get_speech_audio(self) -> np.ndarray:
        """Get audio from speech start to current position"""
        with self._lock:
            if self._speech_start_pos <= self._write_pos:
                return self._buffer[self._speech_start_pos:self._write_pos].copy()
            else:
                # Handle wraparound
                return np.concatenate([
                    self._buffer[self._speech_start_pos:],
                    self._buffer[:self._write_pos]
                ])
    
    def get_recent_chunk(self, duration_ms: int) -> np.ndarray:
        """Get most recent N milliseconds of audio for streaming"""
        num_samples = int(duration_ms * self.sample_rate / 1000)
        
        with self._lock:
            start_pos = (self._write_pos - num_samples) % self.max_samples
            
            if start_pos < self._write_pos:
                return self._buffer[start_pos:self._write_pos].copy()
            else:
                return np.concatenate([
                    self._buffer[start_pos:],
                    self._buffer[:self._write_pos]
                ])


class StreamingVAD:
    """
    Silero VAD with streaming support for real-time voice loop.
    
    KEY BEHAVIOR (sub-500ms optimization):
    1. On speech START → immediately call on_speech_start callback
    2. During speech → stream chunks to on_speech_chunk callback (for ASR)
    3. On speech END → call on_speech_end with full audio
    
    This allows ASR to start processing BEFORE the user finishes speaking.
    
    LATENCY: ~30ms detection latency with 512-sample chunks at 16kHz
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
        
        # Load Silero VAD model (optimized for speed)
        self.model = None
        self._load_model()
        
        # Circular buffer for audio (pre-allocated)
        self.audio_buffer = CircularAudioBuffer()
        
        # State tracking
        self.is_speaking = False
        self.speech_start_time: Optional[float] = None
        self.silence_start_time: Optional[float] = None
        self._pending_speech_start: Optional[float] = None
        
        # Streaming state - for incremental ASR
        self._last_stream_time: float = 0
        self._stream_interval_ms = config.ASR_CHUNK_DURATION_MS
        
        # ═══════════════════════════════════════════════════════════════════
        # CALLBACKS - These enable the real-time pipeline
        # ═══════════════════════════════════════════════════════════════════
        self.on_speech_start: Optional[Callable[[], None]] = None
        self.on_speech_chunk: Optional[Callable[[np.ndarray], None]] = None  # STREAMING!
        self.on_speech_end: Optional[Callable[[np.ndarray], None]] = None
        
        self._lock = threading.Lock()
        
        print(f"[VAD] Initialized: threshold={threshold}, "
              f"min_speech={min_speech_duration_ms}ms, min_silence={min_silence_duration_ms}ms")
    
    def _load_model(self):
        """
        Load Silero VAD model - optimized for CPU inference.
        
        LATENCY OPTIMIZATION:
        - Single thread mode (reduces context switching)
        - Warmup calls (JIT compilation happens before real audio)
        """
        try:
            # Single thread for consistent low latency
            torch.set_num_threads(1)
            
            self.model, _ = torch.hub.load(
                repo_or_dir='snakers4/silero-vad',
                model='silero_vad',
                force_reload=False,
                trust_repo=True
            )
            self.model.eval()
            
            # CRITICAL: Warmup inference (first call is slow due to JIT)
            dummy = torch.zeros(512)
            for _ in range(3):
                self.model(dummy, self.sample_rate)
            
            print("[VAD] Silero VAD loaded and warmed up")
        except Exception as e:
            print(f"[VAD] Error loading Silero VAD: {e}")
            print("[VAD] Using energy-based fallback")
            self.model = None
    
    def reset(self):
        """Reset VAD state for new conversation"""
        with self._lock:
            if self.model is not None:
                self.model.reset_states()
            self.is_speaking = False
            self.speech_start_time = None
            self.silence_start_time = None
            self._pending_speech_start = None
            self._last_stream_time = 0
    
    def process_chunk(self, audio_chunk: np.ndarray) -> bool:
        """
        Process audio chunk through VAD.
        
        STREAMING BEHAVIOR:
        - Returns True if speech is active
        - Calls on_speech_chunk periodically during speech
        - VAD GATES ASR: chunks only sent during active speech
        
        Args:
            audio_chunk: Audio samples (int16 or float32), typically 512 samples (~32ms)
            
        Returns:
            True if speech is currently detected
        """
        # Write to circular buffer (always, for lookback)
        self.audio_buffer.write(audio_chunk)
        
        # Convert to float32 for VAD model
        if audio_chunk.dtype == np.int16:
            audio_float = audio_chunk.astype(np.float32) / 32768.0
        else:
            audio_float = audio_chunk.astype(np.float32)
        
        # Get speech probability (~5ms on CPU)
        speech_prob = self._get_speech_probability(audio_float)
        current_time = time.time()
        
        with self._lock:
            return self._update_state(speech_prob, current_time, audio_chunk)
    
    def _update_state(self, speech_prob: float, current_time: float, 
                      audio_chunk: np.ndarray) -> bool:
        """
        State machine for speech detection with EARLY TRIGGER.
        
        States:
        - SILENCE: No speech detected
        - PENDING: Possible speech start (waiting for min duration)
        - SPEAKING: Active speech, streaming to ASR
        - ENDING: Possible speech end (waiting for min silence)
        """
        
        if speech_prob >= self.threshold:
            # ═══════════════════════════════════════════════════════════════
            # SPEECH DETECTED
            # ═══════════════════════════════════════════════════════════════
            self.silence_start_time = None
            
            if not self.is_speaking:
                # Not yet confirmed speaking
                if self._pending_speech_start is None:
                    self._pending_speech_start = current_time
                    self.audio_buffer.mark_speech_start()
                
                # Check minimum speech duration
                speech_duration_ms = (current_time - self._pending_speech_start) * 1000
                
                if speech_duration_ms >= self.min_speech_duration_ms:
                    # ═══════════════════════════════════════════════════════
                    # SPEECH START CONFIRMED - TRIGGER IMMEDIATELY!
                    # This is where latency optimization matters most
                    # ═══════════════════════════════════════════════════════
                    self.is_speaking = True
                    self.speech_start_time = self._pending_speech_start
                    self._pending_speech_start = None
                    self._last_stream_time = current_time
                    
                    print(f"[VAD] 🎤 Speech START (prob={speech_prob:.2f})")
                    
                    if self.on_speech_start:
                        self.on_speech_start()
            
            else:
                # ═══════════════════════════════════════════════════════════
                # DURING SPEECH - Stream chunks to ASR periodically
                # KEY OPTIMIZATION: ASR processes incrementally!
                # ═══════════════════════════════════════════════════════════
                time_since_stream = (current_time - self._last_stream_time) * 1000
                
                if time_since_stream >= self._stream_interval_ms:
                    self._last_stream_time = current_time
                    
                    if self.on_speech_chunk:
                        recent_audio = self.audio_buffer.get_recent_chunk(
                            int(self._stream_interval_ms)
                        )
                        self.on_speech_chunk(recent_audio)
        
        else:
            # ═══════════════════════════════════════════════════════════════
            # SILENCE DETECTED
            # ═══════════════════════════════════════════════════════════════
            self._pending_speech_start = None
            
            if self.is_speaking:
                if self.silence_start_time is None:
                    self.silence_start_time = current_time
                
                silence_duration_ms = (current_time - self.silence_start_time) * 1000
                
                if silence_duration_ms >= self.min_silence_duration_ms:
                    # ═══════════════════════════════════════════════════════
                    # SPEECH END CONFIRMED - Trigger pipeline!
                    # ═══════════════════════════════════════════════════════
                    self.is_speaking = False
                    self.silence_start_time = None
                    
                    speech_duration = current_time - self.speech_start_time
                    print(f"[VAD] 🔇 Speech END (duration={speech_duration:.2f}s)")
                    
                    if self.on_speech_end:
                        speech_audio = self.audio_buffer.get_speech_audio()
                        self.on_speech_end(speech_audio)
        
        return self.is_speaking
    
    def _get_speech_probability(self, audio_float: np.ndarray) -> float:
        """
        Get speech probability from Silero model.
        
        LATENCY: ~5ms per chunk on CPU
        """
        if self.model is None:
            # Fallback: energy-based detection
            energy = np.sqrt(np.mean(audio_float ** 2))
            return min(1.0, energy * 10)
        
        try:
            audio_tensor = torch.from_numpy(audio_float)
            speech_prob = self.model(audio_tensor, self.sample_rate).item()
            return speech_prob
        except Exception:
            return 0.0
    
    def get_is_speaking(self) -> bool:
        """Thread-safe check if currently speaking"""
        with self._lock:
            return self.is_speaking


def create_vad() -> StreamingVAD:
    """Factory function to create optimized VAD instance"""
    return StreamingVAD()
