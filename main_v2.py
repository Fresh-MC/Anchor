# Uses config_v2 only

"""
Real-Time Voice AI Agent - MAIN PIPELINE
========================================
OPTIMIZED FOR SUB-500ms LATENCY

PIPELINE ORDER:
1. VAD detects speech START → start streaming to ASR
2. During speech → ASR accumulates chunks
3. VAD detects speech END → trigger transcription
4. Transcript → State Machine (DETERMINISTIC, <5ms)
5. If STALL → IMMEDIATELY play filler (preloaded, ~0ms)
6. State → LLM template fill (streaming tokens)
7. LLM → TTS synthesis (streaming, concurrent)
8. TTS → Speaker (non-blocking thread)

CONCURRENCY:
- Main thread: VAD (must be fast!)
- Pipeline thread: ASR → State → LLM → TTS
- Playback thread: Audio output
- Echo suppression: Mic muted during playback

LATENCY BUDGET:
- VAD → ASR: <50ms
- ASR: <150ms
- State: <5ms
- LLM first token: <100ms
- TTS first audio: <150ms
- TOTAL: <500ms
"""

import time
import threading
import signal
import sys
import queue
from typing import Optional
import numpy as np

# Import v2 optimized components
from vad_v2 import StreamingVAD, create_vad
from asr_v2 import StreamingASR, create_asr
from state_machine_v2 import DeterministicStateMachine, AgentState, create_state_machine
from llm_v2 import TemplateBasedLLM, create_llm
from tts_v2 import StreamingTTS, create_tts
from audio_utils_v2 import (
    EchoAwareRecorder, NonBlockingPlayer, FillerAudioPlayer,
    create_recorder, create_player, create_filler_player
)

import config_v2 as config


class RealTimeVoiceAgent:
    """
    Real-time voice AI with sub-500ms latency.
    
    ARCHITECTURE:
    ┌───────────┐   ┌───────────┐   ┌───────────┐
    │ Microphone│──▶│  VAD      │──▶│  ASR      │
    │ (stream)  │   │ (gating)  │   │ (stream)  │
    └───────────┘   └───────────┘   └─────┬─────┘
                                          │
    ┌───────────┐   ┌───────────┐   ┌─────▼─────┐
    │  Speaker  │◀──│  TTS      │◀──│  State    │
    │ (thread)  │   │ (stream)  │   │  Machine  │
    └───────────┘   └─────┬─────┘   └─────┬─────┘
                          │               │
                    ┌─────▼───────────────▼─────┐
                    │     LLM (templates)       │
                    │     (streaming)           │
                    └───────────────────────────┘
    """
    
    def __init__(self):
        print("=" * 70)
        print("   REAL-TIME VOICE AI AGENT")
        print("   Target: <500ms end-to-end latency")
        print("=" * 70)
        
        # ═══════════════════════════════════════════════════════════════════
        # COMPONENTS
        # ═══════════════════════════════════════════════════════════════════
        print("\n[INIT] Loading components...")
        
        print("[INIT] VAD (Silero, streaming)...")
        self.vad = create_vad()
        
        print("[INIT] ASR (faster-whisper, streaming)...")
        self.asr = create_asr()
        
        print("[INIT] State Machine (deterministic)...")
        self.state_machine = create_state_machine()
        
        print("[INIT] LLM (template-based, streaming)...")
        self.llm = create_llm()
        
        print("[INIT] TTS (streaming)...")
        self.tts = create_tts()
        
        print("[INIT] Audio (echo-aware)...")
        self.recorder = create_recorder()
        self.player = create_player()
        self.filler_player = create_filler_player(self.player)
        
        # ═══════════════════════════════════════════════════════════════════
        # STATE & CONCURRENCY
        # ═══════════════════════════════════════════════════════════════════
        self._running = False
        self._processing = False
        self._process_lock = threading.Lock()
        
        # Pipeline queue
        self._pipeline_queue: queue.Queue[np.ndarray] = queue.Queue()
        self._pipeline_thread: Optional[threading.Thread] = None
        
        # ═══════════════════════════════════════════════════════════════════
        # METRICS
        # ═══════════════════════════════════════════════════════════════════
        self.metrics = {
            "turns": 0,
            "total_latency_ms": 0,
            "latencies": [],
            "forced_extracts": 0,
        }
        
        # Wire callbacks
        self._setup_callbacks()
        
        print("\n" + "=" * 70)
        print("   ✅ Agent ready!")
        print("=" * 70)
    
    def _setup_callbacks(self):
        """Wire component callbacks"""
        # Recorder → VAD
        self.recorder.on_audio_chunk = self._on_audio_chunk
        
        # VAD callbacks
        self.vad.on_speech_start = self._on_speech_start
        self.vad.on_speech_chunk = self._on_speech_chunk
        self.vad.on_speech_end = self._on_speech_end
        
        # Player → Recorder (echo suppression)
        self.player.on_playback_start = self._on_playback_start
        self.player.on_playback_end = self._on_playback_end
    
    # ═══════════════════════════════════════════════════════════════════════
    # AUDIO CALLBACKS
    # ═══════════════════════════════════════════════════════════════════════
    
    def _on_audio_chunk(self, chunk: np.ndarray):
        """Audio chunk from mic → VAD"""
        self.vad.process_chunk(chunk)
    
    def _on_speech_start(self):
        """VAD detected speech start"""
        print("\n[AGENT] 🎤 Listening...")
        self.asr.clear_buffer()
    
    def _on_speech_chunk(self, chunk: np.ndarray):
        """Streaming chunk during speech → ASR"""
        self.asr.add_audio_chunk(chunk)
    
    def _on_speech_end(self, audio: np.ndarray):
        """VAD detected speech end → Pipeline"""
        print("[AGENT] 🔇 Processing...")
        
        if not self._processing:
            self._pipeline_queue.put(audio)
    
    # ═══════════════════════════════════════════════════════════════════════
    # ECHO SUPPRESSION
    # ═══════════════════════════════════════════════════════════════════════
    
    def _on_playback_start(self, duration_sec: float):
        """Mute mic during playback"""
        self.recorder.mute_for_playback(duration_sec)
    
    def _on_playback_end(self):
        """Playback ended"""
        pass  # Mic auto-unmutes after tail time
    
    # ═══════════════════════════════════════════════════════════════════════
    # MAIN PIPELINE
    # ═══════════════════════════════════════════════════════════════════════
    
    def _pipeline_worker(self):
        """Pipeline worker thread"""
        while self._running:
            try:
                audio = self._pipeline_queue.get(timeout=0.1)
                if audio is None:
                    break
                self._process_speech(audio)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[ERROR] Pipeline: {e}")
                import traceback
                traceback.print_exc()
    
    def _process_speech(self, audio: np.ndarray):
        """
        FULL PIPELINE:
        1. ASR (~150ms)
        2. State machine (<5ms)
        3. Filler if STALL (~0ms)
        4. LLM (~100ms)
        5. TTS (~150ms)
        6. Play (non-blocking)
        """
        with self._process_lock:
            if self._processing:
                return
            self._processing = True
        
        start = time.time()
        timings = {}
        
        try:
            # ═══════════════════════════════════════════════════════════════
            # STEP 1: ASR
            # ═══════════════════════════════════════════════════════════════
            t0 = time.time()
            transcript = self.asr.transcribe(audio)
            timings['asr'] = (time.time() - t0) * 1000
            
            if not transcript or len(transcript.strip()) < 2:
                print("[AGENT] Empty transcript")
                return
            
            print(f"[AGENT] 📝 '{transcript}'")
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 2: STATE MACHINE (DETERMINISTIC!)
            # Includes JAILBREAK detection - highest priority
            # ═══════════════════════════════════════════════════════════════
            t0 = time.time()
            state, analysis = self.state_machine.analyze_and_transition(transcript)
            timings['state'] = (time.time() - t0) * 1000
            
            # Log security events
            if analysis.get('jailbreak_attempt'):
                print(f"[AGENT] 🛡️ JAILBREAK BLOCKED: '{analysis.get('jailbreak_pattern')}'")
            elif analysis.get('forced_extract'):
                print(f"[AGENT] ⚠️ FORCED EXTRACT: '{analysis.get('matched_pattern')}'")
            
            print(f"[AGENT] 🎯 State: {state.name}")
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 3: FILLER (if STALL) - INSTANT!
            # ═══════════════════════════════════════════════════════════════
            if state == AgentState.STALL:
                t0 = time.time()
                self.filler_player.play_filler("stall")
                timings['filler'] = (time.time() - t0) * 1000
                print(f"[AGENT] 🔊 Filler (non-blocking)")
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 4: LLM (template fill)
            # SECURITY: Pass analysis to get jailbreak-specific responses
            # LLM never receives raw transcript
            # ═══════════════════════════════════════════════════════════════
            t0 = time.time()
            
            # Pass analysis for jailbreak-aware template selection
            template, fills = self.state_machine.get_template_for_state(state, analysis)
            context = self.state_machine.get_conversation_summary()
            response = self.llm.generate_response(state, template, fills, context)
            
            timings['llm'] = (time.time() - t0) * 1000
            print(f"[AGENT] 💬 '{response}'")
            
            self.state_machine.add_agent_response(response)
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 5: TTS
            # ═══════════════════════════════════════════════════════════════
            t0 = time.time()
            audio_out = self.tts.synthesize(response)
            timings['tts'] = (time.time() - t0) * 1000
            
            # ═══════════════════════════════════════════════════════════════
            # STEP 6: PLAY (non-blocking)
            # ═══════════════════════════════════════════════════════════════
            if audio_out is not None:
                self.player.queue_audio(audio_out)
            
            # ═══════════════════════════════════════════════════════════════
            # METRICS
            # ═══════════════════════════════════════════════════════════════
            total = (time.time() - start) * 1000
            
            self.metrics['turns'] += 1
            self.metrics['total_latency_ms'] += total
            self.metrics['latencies'].append(total)
            if analysis.get('forced_extract'):
                self.metrics['forced_extracts'] += 1
            
            # Print breakdown
            print(f"\n[TIMING]")
            print(f"  ASR:   {timings.get('asr', 0):6.0f}ms")
            print(f"  State: {timings.get('state', 0):6.0f}ms")
            if 'filler' in timings:
                print(f"  Filler:{timings.get('filler', 0):6.0f}ms")
            print(f"  LLM:   {timings.get('llm', 0):6.0f}ms")
            print(f"  TTS:   {timings.get('tts', 0):6.0f}ms")
            print(f"  ─────────────")
            print(f"  TOTAL: {total:6.0f}ms", end="")
            
            if total <= config.TARGET_LATENCY_MS:
                print(" ✅")
            else:
                print(f" ⚠️ Over {config.TARGET_LATENCY_MS}ms")
            
        finally:
            with self._process_lock:
                self._processing = False
    
    # ═══════════════════════════════════════════════════════════════════════
    # LIFECYCLE
    # ═══════════════════════════════════════════════════════════════════════
    
    def start(self):
        """Start agent"""
        print("\n" + "=" * 70)
        print("   🚀 Starting Real-Time Voice Agent")
        print("   Press Ctrl+C to stop")
        print("=" * 70 + "\n")
        
        self._running = True
        
        # Start pipeline thread
        self._pipeline_thread = threading.Thread(
            target=self._pipeline_worker,
            daemon=True
        )
        self._pipeline_thread.start()
        
        # Start recording
        self.recorder.start()
        
        print("[AGENT] 🎙️ Listening...\n" + "-" * 50)
        
        try:
            while self._running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[AGENT] Interrupted")
        
        self.stop()
    
    def stop(self):
        """Stop agent"""
        print("\n[AGENT] Stopping...")
        
        self._running = False
        
        self.recorder.stop()
        self.player.stop()
        
        self._pipeline_queue.put(None)
        if self._pipeline_thread:
            self._pipeline_thread.join(timeout=2)
        
        self.vad.reset()
        self.state_machine.reset()
        
        self._print_metrics()
    
    def _print_metrics(self):
        """Print metrics"""
        print("\n" + "=" * 70)
        print("   SESSION METRICS")
        print("=" * 70)
        
        turns = self.metrics['turns']
        if turns > 0:
            latencies = self.metrics['latencies']
            avg = self.metrics['total_latency_ms'] / turns
            
            print(f"   Turns:           {turns}")
            print(f"   Forced EXTRACTs: {self.metrics['forced_extracts']}")
            print(f"   Avg latency:     {avg:.0f}ms")
            print(f"   Min latency:     {min(latencies):.0f}ms")
            print(f"   Max latency:     {max(latencies):.0f}ms")
            
            under = sum(1 for l in latencies if l <= config.TARGET_LATENCY_MS)
            pct = (under / turns) * 100
            print(f"   Under {config.TARGET_LATENCY_MS}ms:     {under}/{turns} ({pct:.0f}%)")
        else:
            print("   No turns")
        
        print("=" * 70)


def main():
    """Entry point"""
    agent = None
    
    def handler(sig, frame):
        if agent:
            agent.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, handler)
    
    agent = RealTimeVoiceAgent()
    agent.start()


if __name__ == "__main__":
    main()
