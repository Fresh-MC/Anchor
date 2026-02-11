"""
Automatic Speech Recognition using whisper.cpp
Transcribes audio chunks to text with low latency
"""

import numpy as np
import subprocess
import tempfile
import wave
import os
from typing import Optional
import threading
import time

import config


class WhisperASR:
    """
    Whisper.cpp wrapper for fast speech-to-text
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
        
        # Check for whisper.cpp binary
        self.whisper_cpp_path = self._find_whisper_cpp()
        self._lock = threading.Lock()
        
        # Optional: Use Python bindings if available
        self.use_python_bindings = False
        self._try_load_python_bindings()
    
    def _find_whisper_cpp(self) -> Optional[str]:
        """Find whisper.cpp executable"""
        possible_paths = [
            "./whisper.cpp/main",
            "./whisper.cpp/build/bin/main",
            "whisper-cpp",
            "whisper",
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                print(f"[ASR] Found whisper.cpp at: {path}")
                return path
        
        print("[ASR] whisper.cpp not found, using placeholder mode")
        return None
    
    def _try_load_python_bindings(self):
        """Try to load faster Python bindings for whisper"""
        try:
            import whisper
            self.whisper_model = whisper.load_model("base.en")
            self.use_python_bindings = True
            print("[ASR] Using OpenAI Whisper Python bindings")
        except ImportError:
            try:
                from faster_whisper import WhisperModel
                self.whisper_model = WhisperModel("base.en", device="cpu", compute_type="int8")
                self.use_python_bindings = True
                self.use_faster_whisper = True
                print("[ASR] Using faster-whisper Python bindings")
            except ImportError:
                print("[ASR] No Python bindings available, using CLI mode")
    
    def transcribe(self, audio: np.ndarray) -> str:
        """
        Transcribe audio to text
        
        Args:
            audio: Audio samples as numpy array (int16)
            
        Returns:
            Transcribed text string
        """
        with self._lock:
            start_time = time.time()
            
            # Try Python bindings first for lower latency
            if self.use_python_bindings:
                result = self._transcribe_python(audio)
            elif self.whisper_cpp_path:
                result = self._transcribe_cpp(audio)
            else:
                result = self._transcribe_placeholder(audio)
            
            elapsed_ms = (time.time() - start_time) * 1000
            print(f"[ASR] Transcription took {elapsed_ms:.0f}ms: '{result}'")
            
            return result
    
    def _transcribe_python(self, audio: np.ndarray) -> str:
        """Transcribe using Python bindings"""
        try:
            # Convert to float32 if needed
            if audio.dtype == np.int16:
                audio_float = audio.astype(np.float32) / 32768.0
            else:
                audio_float = audio
            
            if hasattr(self, 'use_faster_whisper') and self.use_faster_whisper:
                # faster-whisper
                segments, _ = self.whisper_model.transcribe(
                    audio_float,
                    language=self.language,
                    beam_size=1,
                    best_of=1,
                )
                return " ".join([seg.text for seg in segments]).strip()
            else:
                # OpenAI whisper
                result = self.whisper_model.transcribe(
                    audio_float,
                    language=self.language,
                    fp16=False,
                )
                return result["text"].strip()
                
        except Exception as e:
            print(f"[ASR] Python transcription error: {e}")
            return ""
    
    def _transcribe_cpp(self, audio: np.ndarray) -> str:
        """Transcribe using whisper.cpp CLI"""
        try:
            # Write audio to temp WAV file
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
                temp_path = f.name
                self._write_wav(f.name, audio)
            
            # Run whisper.cpp
            cmd = [
                self.whisper_cpp_path,
                "-m", self.model_path,
                "-f", temp_path,
                "-l", self.language,
                "-nt",  # No timestamps
                "--no-prints",
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            
            # Clean up
            os.unlink(temp_path)
            
            return result.stdout.strip()
            
        except subprocess.TimeoutExpired:
            print("[ASR] whisper.cpp timed out")
            return ""
        except Exception as e:
            print(f"[ASR] whisper.cpp error: {e}")
            return ""
    
    def _transcribe_placeholder(self, audio: np.ndarray) -> str:
        """Placeholder transcription for testing"""
        # Return dummy text based on audio length
        duration_sec = len(audio) / self.sample_rate
        return f"[Placeholder transcription - {duration_sec:.1f}s audio]"
    
    def _write_wav(self, filepath: str, audio: np.ndarray):
        """Write audio to WAV file"""
        if audio.dtype != np.int16:
            audio = (audio * 32768).astype(np.int16)
        
        with wave.open(filepath, 'w') as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(self.sample_rate)
            wf.writeframes(audio.tobytes())


def create_asr() -> WhisperASR:
    """Factory function to create ASR instance"""
    return WhisperASR()


# Async wrapper for non-blocking transcription
class AsyncASR:
    """Async wrapper for ASR to avoid blocking main loop"""
    
    def __init__(self, asr: WhisperASR):
        self.asr = asr
        self._result = None
        self._thread = None
        self._done = threading.Event()
    
    def transcribe_async(self, audio: np.ndarray):
        """Start async transcription"""
        self._done.clear()
        self._result = None
        self._thread = threading.Thread(
            target=self._transcribe_worker,
            args=(audio,)
        )
        self._thread.start()
    
    def _transcribe_worker(self, audio: np.ndarray):
        """Worker thread for transcription"""
        self._result = self.asr.transcribe(audio)
        self._done.set()
    
    def get_result(self, timeout: float = 5.0) -> Optional[str]:
        """Get transcription result (blocking)"""
        if self._done.wait(timeout=timeout):
            return self._result
        return None
    
    def is_done(self) -> bool:
        """Check if transcription is complete"""
        return self._done.is_set()
