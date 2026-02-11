"""
Main entry point for the Voice AI Agent
Wires together all components into a real-time pipeline
"""

import time
import threading
import signal
import sys
from typing import Optional
import numpy as np

# Import components
import config
from vad import SileroVAD, create_vad
from asr import WhisperASR, create_asr
from state_machine import StateMachine, AgentState, create_state_machine
from llm import LocalLLM, create_llm
from tts import CoquiTTS, create_tts
from audio_utils import (
    AudioRecorder, AudioPlayer, FillerAudioPlayer,
    create_recorder, create_player, create_filler_player
)


class VoiceAIAgent:
    """
    Main voice AI agent that orchestrates all components
    Pipeline: Mic -> VAD -> ASR -> State Machine -> LLM -> TTS -> Speaker
    """
    
    def __init__(self):
        print("=" * 60)
        print("Initializing Voice AI Agent...")
        print("=" * 60)
        
        # Initialize components
        print("\n[INIT] Loading VAD...")
        self.vad = create_vad()
        
        print("\n[INIT] Loading ASR...")
        self.asr = create_asr()
        
        print("\n[INIT] Loading State Machine...")
        self.state_machine = create_state_machine()
        
        print("\n[INIT] Loading LLM...")
        self.llm = create_llm()
        
        print("\n[INIT] Loading TTS...")
        self.tts = create_tts()
        
        print("\n[INIT] Loading Audio...")
        self.recorder = create_recorder()
        self.player = create_player()
        self.filler_player = create_filler_player()
        
        # State
        self._running = False
        self._processing = False
        self._lock = threading.Lock()
        
        # Metrics
        self.metrics = {
            "total_turns": 0,
            "total_latency_ms": 0,
            "min_latency_ms": float('inf'),
            "max_latency_ms": 0,
        }
        
        # Wire up callbacks
        self._setup_callbacks()
        
        print("\n" + "=" * 60)
        print("Voice AI Agent initialized!")
        print("=" * 60)
    
    def _setup_callbacks(self):
        """Set up VAD callbacks"""
        self.vad.on_speech_start = self._on_speech_start
        self.vad.on_speech_end = self._on_speech_end
    
    def _on_speech_start(self):
        """Called when speech starts"""
        print("\n[AGENT] Speech detected - listening...")
    
    def _on_speech_end(self, audio: np.ndarray):
        """Called when speech ends - process the audio"""
        if self._processing:
            print("[AGENT] Already processing, skipping...")
            return
        
        # Process in separate thread to not block audio
        thread = threading.Thread(
            target=self._process_speech,
            args=(audio,)
        )
        thread.start()
    
    def _process_speech(self, audio: np.ndarray):
        """
        Main processing pipeline for detected speech
        Mic -> VAD -> ASR -> State Machine -> LLM -> TTS -> Speaker
        """
        with self._lock:
            if self._processing:
                return
            self._processing = True
        
        start_time = time.time()
        
        try:
            # Step 1: Transcribe audio
            print("[PIPELINE] Step 1: Transcribing...")
            transcript = self.asr.transcribe(audio)
            
            if not transcript or len(transcript.strip()) < 2:
                print("[PIPELINE] Empty transcript, skipping...")
                return
            
            print(f"[PIPELINE] Transcript: '{transcript}'")
            
            # Step 2: Determine state
            print("[PIPELINE] Step 2: Analyzing state...")
            state = self.state_machine.analyze_and_transition(transcript)
            print(f"[PIPELINE] State: {state.name}")
            
            # Step 3: If STALL, play filler immediately
            if state == AgentState.STALL:
                print("[PIPELINE] Playing filler audio...")
                self.filler_player.play_filler("stall", blocking=False)
            
            # Step 4: Generate response
            print("[PIPELINE] Step 3: Generating response...")
            context = self.state_machine.get_conversation_summary()
            state_info = self.state_machine.get_state_info(state)
            
            response = self.llm.generate_response(state, context, state_info)
            print(f"[PIPELINE] Response: '{response}'")
            
            # Record response in state machine
            self.state_machine.add_agent_response(response)
            
            # Step 5: Synthesize speech
            print("[PIPELINE] Step 4: Synthesizing speech...")
            audio_response = self.tts.synthesize(response)
            
            # Step 6: Play response
            if audio_response is not None:
                print("[PIPELINE] Step 5: Playing response...")
                self.player.play(audio_response, blocking=True)
            
            # Calculate latency
            latency_ms = (time.time() - start_time) * 1000
            self._update_metrics(latency_ms)
            
            print(f"[PIPELINE] Complete! Latency: {latency_ms:.0f}ms")
            
            # Check if we met target
            if latency_ms > config.TARGET_LATENCY_MS:
                print(f"[WARNING] Latency exceeded target ({config.TARGET_LATENCY_MS}ms)")
            
        except Exception as e:
            print(f"[ERROR] Pipeline error: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            with self._lock:
                self._processing = False
    
    def _update_metrics(self, latency_ms: float):
        """Update performance metrics"""
        self.metrics["total_turns"] += 1
        self.metrics["total_latency_ms"] += latency_ms
        self.metrics["min_latency_ms"] = min(self.metrics["min_latency_ms"], latency_ms)
        self.metrics["max_latency_ms"] = max(self.metrics["max_latency_ms"], latency_ms)
    
    def start(self):
        """Start the agent"""
        print("\n" + "=" * 60)
        print("Starting Voice AI Agent...")
        print("Press Ctrl+C to stop")
        print("=" * 60 + "\n")
        
        self._running = True
        self.recorder.start()
        
        # Main loop - process audio chunks
        try:
            while self._running:
                chunk = self.recorder.get_chunk(timeout=0.1)
                if chunk is not None:
                    self.vad.process_chunk(chunk)
        except KeyboardInterrupt:
            print("\n[AGENT] Interrupted by user")
        
        self.stop()
    
    def stop(self):
        """Stop the agent"""
        print("\n[AGENT] Stopping...")
        
        self._running = False
        self.recorder.stop()
        self.vad.reset_states()
        
        # Print metrics
        self._print_metrics()
    
    def _print_metrics(self):
        """Print performance metrics"""
        print("\n" + "=" * 60)
        print("Session Metrics")
        print("=" * 60)
        
        turns = self.metrics["total_turns"]
        if turns > 0:
            avg_latency = self.metrics["total_latency_ms"] / turns
            print(f"Total turns: {turns}")
            print(f"Average latency: {avg_latency:.0f}ms")
            print(f"Min latency: {self.metrics['min_latency_ms']:.0f}ms")
            print(f"Max latency: {self.metrics['max_latency_ms']:.0f}ms")
        else:
            print("No turns recorded")
        
        print("=" * 60)


def main():
    """Main entry point"""
    # Handle Ctrl+C gracefully
    agent = None
    
    def signal_handler(sig, frame):
        print("\n[MAIN] Received shutdown signal")
        if agent:
            agent.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create and start agent
    agent = VoiceAIAgent()
    agent.start()


if __name__ == "__main__":
    main()
