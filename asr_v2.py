# Uses config_v2 only

"""
Automatic Speech Recognition - STREAMING OPTIMIZED
==================================================
KEY OPTIMIZATIONS:
1. Accepts audio chunks from VAD in near real-time
2. Supports incremental transcription (don't wait for full audio)
3. Uses faster-whisper with int8 quantization for speed
4. Thread-safe streaming accumulator

Latency target: <150ms for transcription
"""

import numpy as np
import threading
import queue
import time
from typing import Optional, Generator, Callable
import os

# Use v2 config
import config_v2 as config


class StreamingASR:
    """
    Streaming ASR that processes audio incrementally.
    
    KEY BEHAVIOR for sub-500ms latency:
    1. Accumulates audio chunks from VAD during speech
    2. Can transcribe incrementally (partial results)
    3. Uses faster-whisper with int8 for speed
    
    VAD GATING: ASR only receives audio during confirmed speech
    """
    
    def __init__(
        self,
        model_path: str = config.WHISPER_MODEL_PATH,
        language: str = config.WHISPER_LANGUAGE,
        sample_rate: int = config.SAMPLE_RATE,
    ):
        self.model_path = model_path
        self.language = language
        self.sample_rate = sample_rate
        
        # Streaming buffer (thread-safe)
        self._audio_buffer = []
        self._buffer_lock = threading.Lock()
        self._total_samples = 0
        
        # Model
        self.model = None
        self.backend = "placeholder"
        self._model_lock = threading.Lock()
        
        # Callbacks for streaming results
        self.on_partial_transcript: Optional[Callable[[str], None]] = None
        self.on_final_transcript: Optional[Callable[[str], None]] = None
        
        self._load_model()
    
    def _load_model(self):
        """
        Load ASR model - prioritize faster-whisper for speed.
        
        LATENCY PRIORITY:
        1. faster-whisper (fastest, int8 quantization)
        2. OpenAI whisper (slower but compatible)
        3. Placeholder (testing)
        """
        # Try faster-whisper (RECOMMENDED for real-time)
        try:
            from faster_whisper import WhisperModel
            
            # int8 quantization is FASTER than float16 on CPU
            self.model = WhisperModel(
                "base.en",  # Use "tiny.en" for even faster
                device="cpu",
                compute_type="int8",
                cpu_threads=2,  # Limit threads for consistent latency
            )
            self.backend = "faster-whisper"
            
            # CRITICAL: Warmup (first inference is slow)
            dummy = np.zeros(self.sample_rate, dtype=np.float32)
            list(self.model.transcribe(dummy, language="en"))
            
            print("[ASR] faster-whisper loaded (int8, optimized)")
            return
            
        except ImportError:
            print("[ASR] faster-whisper not available")
        except Exception as e:
            print(f"[ASR] faster-whisper error: {e}")
        
        # Try OpenAI whisper
        try:
            import whisper
            self.model = whisper.load_model("base.en")
            self.backend = "openai-whisper"
            print("[ASR] OpenAI Whisper loaded")
            return
        except ImportError:
            pass
        
        print("[ASR] Using placeholder mode")
        self.backend = "placeholder"
    
    def add_audio_chunk(self, chunk: np.ndarray):
        """
        Add audio chunk to streaming buffer.
        Called by VAD during speech - thread-safe.
        """
        with self._buffer_lock:
            self._audio_buffer.append(chunk.copy())
            self._total_samples += len(chunk)
    
    def get_buffer_duration_ms(self) -> float:
        """Get current buffer duration"""
        with self._buffer_lock:
            return (self._total_samples / self.sample_rate) * 1000
    
    def transcribe_buffer(self, clear_after: bool = True) -> str:
        """Transcribe accumulated buffer"""
        with self._buffer_lock:
            if not self._audio_buffer:
                return ""
            
            audio = np.concatenate(self._audio_buffer)
            
            if clear_after:
                self._audio_buffer.clear()
                self._total_samples = 0
        
        return self.transcribe(audio)
    
    def transcribe(self, audio: np.ndarray) -> str:
        """
        Transcribe audio to text.
        
        LATENCY OPTIMIZATIONS:
        - beam_size=1 (greedy decoding)
        - VAD filter to skip silence
        - Early return on short audio
        """
        if len(audio) == 0:
            return ""
        
        duration_ms = len(audio) / self.sample_rate * 1000
        if duration_ms < config.ASR_MIN_AUDIO_LENGTH_MS:
            return ""
        
        with self._model_lock:
            start_time = time.time()
            
            # Convert to float32
            if audio.dtype == np.int16:
                audio_float = audio.astype(np.float32) / 32768.0
            else:
                audio_float = audio.astype(np.float32)
            
            # Transcribe
            if self.backend == "faster-whisper":
                result = self._transcribe_faster_whisper(audio_float)
            elif self.backend == "openai-whisper":
                result = self._transcribe_openai_whisper(audio_float)
            else:
                result = f"[Placeholder - {duration_ms:.0f}ms audio]"
            
            elapsed_ms = (time.time() - start_time) * 1000
            print(f"[ASR] {elapsed_ms:.0f}ms for {duration_ms:.0f}ms audio -> '{result}'")
            
            return result
    
    def _transcribe_faster_whisper(self, audio: np.ndarray) -> str:
        """
        Transcribe using faster-whisper.
        
        SPEED SETTINGS:
        - beam_size=1: Greedy (fastest)
        - vad_filter=True: Skip silence
        - No word timestamps
        """
        try:
            segments, _ = self.model.transcribe(
                audio,
                language=self.language,
                beam_size=1,
                best_of=1,
                temperature=0.0,
                vad_filter=True,
                vad_parameters=dict(min_silence_duration_ms=200),
                word_timestamps=False,
                condition_on_previous_text=False,
            )
            return " ".join(seg.text for seg in segments).strip()
        except Exception as e:
            print(f"[ASR] Error: {e}")
            return ""
    
    def _transcribe_openai_whisper(self, audio: np.ndarray) -> str:
        """Transcribe using OpenAI whisper"""
        try:
            result = self.model.transcribe(
                audio,
                language=self.language,
                fp16=False,
                temperature=0.0,
            )
            return result["text"].strip()
        except Exception as e:
            print(f"[ASR] Error: {e}")
            return ""
    
    def clear_buffer(self):
        """Clear the audio buffer"""
        with self._buffer_lock:
            self._audio_buffer.clear()
            self._total_samples = 0


class ASRStreamProcessor:
    """
    Background processor for non-blocking ASR.
    Runs transcription in separate thread.
    """
    
    def __init__(self, asr: StreamingASR):
        self.asr = asr
        self._result_queue = queue.Queue()
        self._thread: Optional[threading.Thread] = None
    
    def start_transcription(self, audio: np.ndarray):
        """Start async transcription"""
        self._thread = threading.Thread(
            target=self._worker,
            args=(audio,),
            daemon=True
        )
        self._thread.start()
    
    def _worker(self, audio: np.ndarray):
        result = self.asr.transcribe(audio)
        self._result_queue.put(result)
    
    def get_result(self, timeout: float = 5.0) -> Optional[str]:
        try:
            return self._result_queue.get(timeout=timeout)
        except queue.Empty:
            return None


def create_asr() -> StreamingASR:
    """Factory function"""
    return StreamingASR()
