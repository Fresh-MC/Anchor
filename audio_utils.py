"""
Audio utilities for recording and playback
Handles microphone input and speaker output
"""

import numpy as np
import threading
import queue
import time
from typing import Optional, Callable
import os

import config


class AudioRecorder:
    """
    Real-time audio recorder from microphone
    """
    
    def __init__(
        self,
        sample_rate: int = config.SAMPLE_RATE,
        channels: int = config.CHANNELS,
        chunk_size: int = config.CHUNK_SIZE,
    ):
        self.sample_rate = sample_rate
        self.channels = channels
        self.chunk_size = chunk_size
        
        self.audio_queue = queue.Queue()
        self._stream = None
        self._pa = None
        self._running = False
        self._thread = None
        
        # Callback for audio chunks
        self.on_audio_chunk: Optional[Callable[[np.ndarray], None]] = None
        
        self._init_audio()
    
    def _init_audio(self):
        """Initialize audio backend"""
        try:
            import pyaudio
            self._pa = pyaudio.PyAudio()
            self.backend = "pyaudio"
            print("[AUDIO] Using PyAudio backend")
        except ImportError:
            try:
                import sounddevice as sd
                self.backend = "sounddevice"
                print("[AUDIO] Using sounddevice backend")
            except ImportError:
                print("[AUDIO] No audio backend available!")
                self.backend = None
    
    def start(self):
        """Start recording"""
        if self._running:
            return
        
        self._running = True
        
        if self.backend == "pyaudio":
            self._start_pyaudio()
        elif self.backend == "sounddevice":
            self._start_sounddevice()
        else:
            print("[AUDIO] Cannot start recording - no backend")
    
    def _start_pyaudio(self):
        """Start recording with PyAudio"""
        import pyaudio
        
        def callback(in_data, frame_count, time_info, status):
            if self._running:
                audio_chunk = np.frombuffer(in_data, dtype=np.int16)
                self.audio_queue.put(audio_chunk)
                if self.on_audio_chunk:
                    self.on_audio_chunk(audio_chunk)
            return (None, pyaudio.paContinue)
        
        self._stream = self._pa.open(
            format=pyaudio.paInt16,
            channels=self.channels,
            rate=self.sample_rate,
            input=True,
            frames_per_buffer=self.chunk_size,
            stream_callback=callback,
        )
        self._stream.start_stream()
        print("[AUDIO] Recording started (PyAudio)")
    
    def _start_sounddevice(self):
        """Start recording with sounddevice"""
        import sounddevice as sd
        
        def callback(indata, frames, time, status):
            if self._running:
                audio_chunk = (indata[:, 0] * 32768).astype(np.int16)
                self.audio_queue.put(audio_chunk)
                if self.on_audio_chunk:
                    self.on_audio_chunk(audio_chunk)
        
        self._stream = sd.InputStream(
            samplerate=self.sample_rate,
            channels=self.channels,
            blocksize=self.chunk_size,
            dtype=np.float32,
            callback=callback,
        )
        self._stream.start()
        print("[AUDIO] Recording started (sounddevice)")
    
    def stop(self):
        """Stop recording"""
        self._running = False
        
        if self._stream:
            if self.backend == "pyaudio":
                self._stream.stop_stream()
                self._stream.close()
            elif self.backend == "sounddevice":
                self._stream.stop()
                self._stream.close()
            self._stream = None
        
        print("[AUDIO] Recording stopped")
    
    def get_chunk(self, timeout: float = 0.1) -> Optional[np.ndarray]:
        """Get next audio chunk from queue"""
        try:
            return self.audio_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def clear_queue(self):
        """Clear audio queue"""
        while not self.audio_queue.empty():
            try:
                self.audio_queue.get_nowait()
            except queue.Empty:
                break
    
    def __del__(self):
        self.stop()
        if self._pa:
            self._pa.terminate()


class AudioPlayer:
    """
    Audio player for speaker output
    """
    
    def __init__(
        self,
        sample_rate: int = config.SAMPLE_RATE,
        channels: int = config.CHANNELS,
    ):
        self.sample_rate = sample_rate
        self.channels = channels
        
        self._pa = None
        self._stream = None
        self._playing = False
        self._lock = threading.Lock()
        
        self._init_audio()
    
    def _init_audio(self):
        """Initialize audio backend"""
        try:
            import pyaudio
            self._pa = pyaudio.PyAudio()
            self.backend = "pyaudio"
        except ImportError:
            try:
                import sounddevice as sd
                self.backend = "sounddevice"
            except ImportError:
                self.backend = None
    
    def play(self, audio: np.ndarray, blocking: bool = True):
        """
        Play audio through speakers
        
        Args:
            audio: Audio samples as numpy array (int16)
            blocking: If True, wait for playback to complete
        """
        if audio is None or len(audio) == 0:
            return
        
        with self._lock:
            self._playing = True
            
            if self.backend == "pyaudio":
                self._play_pyaudio(audio, blocking)
            elif self.backend == "sounddevice":
                self._play_sounddevice(audio, blocking)
            else:
                # Placeholder: just wait for duration
                duration = len(audio) / self.sample_rate
                if blocking:
                    time.sleep(duration)
            
            self._playing = False
    
    def _play_pyaudio(self, audio: np.ndarray, blocking: bool):
        """Play with PyAudio"""
        import pyaudio
        
        stream = self._pa.open(
            format=pyaudio.paInt16,
            channels=self.channels,
            rate=self.sample_rate,
            output=True,
        )
        
        stream.write(audio.tobytes())
        
        if blocking:
            stream.stop_stream()
        stream.close()
    
    def _play_sounddevice(self, audio: np.ndarray, blocking: bool):
        """Play with sounddevice"""
        import sounddevice as sd
        
        # Convert to float32
        audio_float = audio.astype(np.float32) / 32768.0
        
        sd.play(audio_float, self.sample_rate)
        if blocking:
            sd.wait()
    
    def stop(self):
        """Stop playback"""
        if self.backend == "sounddevice":
            import sounddevice as sd
            sd.stop()
        self._playing = False
    
    def is_playing(self) -> bool:
        """Check if currently playing"""
        return self._playing
    
    def __del__(self):
        if self._pa:
            self._pa.terminate()


class FillerAudioPlayer:
    """
    Preloaded filler audio for instant playback
    """
    
    def __init__(self, sample_rate: int = config.SAMPLE_RATE):
        self.sample_rate = sample_rate
        self.filler_audio = {}
        self.player = AudioPlayer(sample_rate=sample_rate)
        
        self._load_filler_audio()
    
    def _load_filler_audio(self):
        """Preload all filler audio files"""
        filler_dir = config.FILLER_AUDIO_DIR
        
        for category, files in config.FILLER_FILES.items():
            self.filler_audio[category] = []
            
            for filename in files:
                filepath = os.path.join(filler_dir, filename)
                audio = self._load_wav(filepath)
                
                if audio is not None:
                    self.filler_audio[category].append(audio)
                    print(f"[FILLER] Loaded: {filename}")
                else:
                    # Create placeholder
                    placeholder = self._create_placeholder_filler()
                    self.filler_audio[category].append(placeholder)
                    print(f"[FILLER] Created placeholder for: {filename}")
    
    def _load_wav(self, filepath: str) -> Optional[np.ndarray]:
        """Load WAV file"""
        try:
            import wave
            with wave.open(filepath, 'r') as wf:
                audio = np.frombuffer(wf.readframes(wf.getnframes()), dtype=np.int16)
                
                # Resample if needed
                file_sr = wf.getframerate()
                if file_sr != self.sample_rate:
                    ratio = self.sample_rate / file_sr
                    new_length = int(len(audio) * ratio)
                    indices = np.linspace(0, len(audio) - 1, new_length)
                    audio = np.interp(indices, np.arange(len(audio)), audio).astype(np.int16)
                
                return audio
        except Exception as e:
            print(f"[FILLER] Error loading {filepath}: {e}")
            return None
    
    def _create_placeholder_filler(self) -> np.ndarray:
        """Create a placeholder filler (silence)"""
        duration_sec = 1.0
        return np.zeros(int(self.sample_rate * duration_sec), dtype=np.int16)
    
    def play_filler(self, category: str = "stall", blocking: bool = False):
        """Play a random filler from category"""
        import random
        
        if category in self.filler_audio and self.filler_audio[category]:
            audio = random.choice(self.filler_audio[category])
            
            if blocking:
                self.player.play(audio, blocking=True)
            else:
                # Non-blocking playback in thread
                thread = threading.Thread(
                    target=self.player.play,
                    args=(audio, True)
                )
                thread.start()


def create_recorder() -> AudioRecorder:
    """Factory function to create audio recorder"""
    return AudioRecorder()


def create_player() -> AudioPlayer:
    """Factory function to create audio player"""
    return AudioPlayer()


def create_filler_player() -> FillerAudioPlayer:
    """Factory function to create filler audio player"""
    return FillerAudioPlayer()
