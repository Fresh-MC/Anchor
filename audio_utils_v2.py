# Uses config_v2 only

"""
Audio Utilities - ECHO PREVENTION + NON-BLOCKING
================================================
KEY FEATURES:
1. Non-blocking playback (separate thread)
2. Echo suppression (mute mic during playback)
3. Preloaded filler audio (instant playback)
4. No feedback loop (AI won't hear itself)

This is CRITICAL for real-time voice loop!
"""

import numpy as np
import threading
import queue
import time
from typing import Optional, Callable, List
import os

# Use v2 config
import config_v2 as config


class EchoAwareRecorder:
    """
    Audio recorder with echo prevention.
    
    ECHO PREVENTION:
    When playing audio:
    1. Mute mic processing
    2. Continue recording but discard
    3. Resume after playback + tail time
    
    Prevents AI hearing itself (feedback loop).
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
        
        self._stream = None
        self._pa = None
        self._running = False
        
        # Echo suppression
        self._muted = False
        self._mute_until: float = 0
        self._mute_lock = threading.Lock()
        
        # Callback
        self.on_audio_chunk: Optional[Callable[[np.ndarray], None]] = None
        
        self._init_backend()
    
    def _init_backend(self):
        """Initialize audio backend"""
        try:
            import pyaudio
            self._pa = pyaudio.PyAudio()
            self.backend = "pyaudio"
            print("[AUDIO] Recorder: PyAudio")
        except ImportError:
            try:
                import sounddevice as sd
                self.backend = "sounddevice"
                print("[AUDIO] Recorder: sounddevice")
            except ImportError:
                self.backend = None
                print("[AUDIO] No audio backend!")
    
    def start(self):
        """Start recording"""
        if self._running:
            return
        
        self._running = True
        
        if self.backend == "pyaudio":
            self._start_pyaudio()
        elif self.backend == "sounddevice":
            self._start_sounddevice()
    
    def _start_pyaudio(self):
        """PyAudio recording"""
        import pyaudio
        
        def callback(in_data, frame_count, time_info, status):
            if self._running:
                audio = np.frombuffer(in_data, dtype=np.int16)
                self._process_chunk(audio)
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
        print("[AUDIO] Recording started")
    
    def _start_sounddevice(self):
        """sounddevice recording"""
        import sounddevice as sd
        
        def callback(indata, frames, time, status):
            if self._running:
                audio = (indata[:, 0] * 32768).astype(np.int16)
                self._process_chunk(audio)
        
        self._stream = sd.InputStream(
            samplerate=self.sample_rate,
            channels=self.channels,
            blocksize=self.chunk_size,
            dtype=np.float32,
            callback=callback,
        )
        self._stream.start()
        print("[AUDIO] Recording started")
    
    def _process_chunk(self, audio: np.ndarray):
        """
        Process chunk with echo suppression.
        
        DISCARD during playback to prevent feedback!
        """
        with self._mute_lock:
            if self._muted or time.time() < self._mute_until:
                return  # DISCARD - echo suppression
        
        if self.on_audio_chunk:
            self.on_audio_chunk(audio)
    
    def mute_for_playback(self, duration_sec: float):
        """
        Mute mic for playback duration.
        
        Called BEFORE playing audio.
        """
        if not config.ECHO_SUPPRESSION_ENABLED:
            return
        
        with self._mute_lock:
            tail_sec = config.ECHO_SUPPRESSION_TAIL_MS / 1000
            self._mute_until = time.time() + duration_sec + tail_sec
            self._muted = True
            print(f"[AUDIO] Mic muted for {duration_sec + tail_sec:.2f}s")
    
    def unmute(self):
        """Unmute mic"""
        with self._mute_lock:
            self._muted = False
            self._mute_until = 0
    
    def is_muted(self) -> bool:
        """Check if muted"""
        with self._mute_lock:
            return self._muted or time.time() < self._mute_until
    
    def stop(self):
        """Stop recording"""
        self._running = False
        if self._stream:
            if self.backend == "pyaudio":
                self._stream.stop_stream()
                self._stream.close()
            else:
                self._stream.stop()
                self._stream.close()
            self._stream = None
        print("[AUDIO] Recording stopped")
    
    def __del__(self):
        self.stop()
        if self._pa:
            self._pa.terminate()


class NonBlockingPlayer:
    """
    Non-blocking audio player.
    
    DESIGN:
    1. Audio queued for playback
    2. Separate thread handles actual playback
    3. Main thread NEVER blocks
    4. Reports duration for echo suppression
    """
    
    def __init__(
        self,
        sample_rate: int = config.SAMPLE_RATE,
        channels: int = config.CHANNELS,
    ):
        self.sample_rate = sample_rate
        self.channels = channels
        
        self._pa = None
        self._running = False
        
        # Playback queue
        self._audio_queue: queue.Queue[Optional[np.ndarray]] = queue.Queue()
        self._playback_thread: Optional[threading.Thread] = None
        
        # Callbacks
        self.on_playback_start: Optional[Callable[[float], None]] = None
        self.on_playback_end: Optional[Callable[[], None]] = None
        
        self._is_playing = False
        self._lock = threading.Lock()
        
        self._init_backend()
    
    def _init_backend(self):
        """Initialize backend"""
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
    
    def start(self):
        """Start playback thread"""
        if self._running:
            return
        
        self._running = True
        self._playback_thread = threading.Thread(
            target=self._worker,
            daemon=True
        )
        self._playback_thread.start()
        print("[AUDIO] Playback thread started")
    
    def stop(self):
        """Stop playback thread"""
        self._running = False
        self._audio_queue.put(None)
        if self._playback_thread:
            self._playback_thread.join(timeout=2)
        print("[AUDIO] Playback stopped")
    
    def queue_audio(self, audio: np.ndarray):
        """Queue audio (non-blocking)"""
        self._audio_queue.put(audio)
    
    def play_immediate(self, audio: np.ndarray):
        """Play immediately, clear queue first"""
        # Clear queue
        while not self._audio_queue.empty():
            try:
                self._audio_queue.get_nowait()
            except queue.Empty:
                break
        
        self._audio_queue.put(audio)
    
    def _worker(self):
        """Playback worker thread"""
        while self._running:
            try:
                audio = self._audio_queue.get(timeout=0.1)
                if audio is None:
                    break
                self._play(audio)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[AUDIO] Playback error: {e}")
    
    def _play(self, audio: np.ndarray):
        """Play audio (blocking in worker)"""
        if audio is None or len(audio) == 0:
            return
        
        duration_sec = len(audio) / self.sample_rate
        
        with self._lock:
            self._is_playing = True
        
        # Notify for echo suppression
        if self.on_playback_start:
            self.on_playback_start(duration_sec)
        
        if self.backend == "pyaudio":
            self._play_pyaudio(audio)
        elif self.backend == "sounddevice":
            self._play_sounddevice(audio)
        else:
            time.sleep(duration_sec)
        
        with self._lock:
            self._is_playing = False
        
        if self.on_playback_end:
            self.on_playback_end()
    
    def _play_pyaudio(self, audio: np.ndarray):
        """PyAudio playback"""
        import pyaudio
        
        stream = self._pa.open(
            format=pyaudio.paInt16,
            channels=self.channels,
            rate=self.sample_rate,
            output=True,
        )
        stream.write(audio.tobytes())
        stream.stop_stream()
        stream.close()
    
    def _play_sounddevice(self, audio: np.ndarray):
        """sounddevice playback"""
        import sounddevice as sd
        audio_float = audio.astype(np.float32) / 32768.0
        sd.play(audio_float, self.sample_rate)
        sd.wait()
    
    def is_playing(self) -> bool:
        """Check if playing"""
        with self._lock:
            return self._is_playing
    
    def __del__(self):
        self.stop()
        if self._pa:
            self._pa.terminate()


class FillerAudioPlayer:
    """
    Preloaded filler audio for INSTANT playback.
    
    Filler loaded at startup, played with ~0ms latency!
    """
    
    def __init__(self, player: NonBlockingPlayer, sample_rate: int = config.SAMPLE_RATE):
        self.player = player
        self.sample_rate = sample_rate
        self.filler_audio: dict[str, List[np.ndarray]] = {}
        
        self._load_fillers()
    
    def _load_fillers(self):
        """Preload all filler audio"""
        filler_dir = config.FILLER_AUDIO_DIR
        
        for category, files in config.FILLER_FILES.items():
            self.filler_audio[category] = []
            
            for filename in files:
                filepath = os.path.join(filler_dir, filename)
                audio = self._load_wav(filepath)
                
                if audio is not None:
                    self.filler_audio[category].append(audio)
                    print(f"[FILLER] Preloaded: {filename}")
                else:
                    audio = self._create_synthetic()
                    self.filler_audio[category].append(audio)
                    print(f"[FILLER] Synthetic: {filename}")
    
    def _load_wav(self, filepath: str) -> Optional[np.ndarray]:
        """Load WAV file"""
        try:
            import wave
            with wave.open(filepath, 'r') as wf:
                audio = np.frombuffer(wf.readframes(wf.getnframes()), dtype=np.int16)
                
                file_sr = wf.getframerate()
                if file_sr != self.sample_rate:
                    ratio = self.sample_rate / file_sr
                    new_len = int(len(audio) * ratio)
                    indices = np.linspace(0, len(audio) - 1, new_len)
                    audio = np.interp(indices, np.arange(len(audio)), audio).astype(np.int16)
                
                return audio
        except:
            return None
    
    def _create_synthetic(self) -> np.ndarray:
        """Create synthetic filler (quiet noise)"""
        duration_sec = 0.5
        samples = int(self.sample_rate * duration_sec)
        return np.random.normal(0, 100, samples).astype(np.int16)
    
    def play_filler(self, category: str = "stall"):
        """
        Play random filler - INSTANT!
        
        Non-blocking, preloaded audio.
        """
        import random
        
        if category in self.filler_audio and self.filler_audio[category]:
            audio = random.choice(self.filler_audio[category])
            self.player.play_immediate(audio)
            print(f"[FILLER] Playing {category}")


# Factory functions
def create_recorder() -> EchoAwareRecorder:
    return EchoAwareRecorder()

def create_player() -> NonBlockingPlayer:
    player = NonBlockingPlayer()
    player.start()
    return player

def create_filler_player(player: NonBlockingPlayer) -> FillerAudioPlayer:
    return FillerAudioPlayer(player)
