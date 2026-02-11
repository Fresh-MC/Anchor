# ANCHOR - Real-Time Voice AI Agent 🎙️🛡️

**A sub-500ms latency voice AI that maintains strict persona boundaries and cannot be jailbroken.**

---

## ⚡ Quick Start (v2 - Refactored)

```bash
# Automated setup
setup_windows.bat     # Windows
./setup_linux.sh      # Linux/macOS

# Then run
python run_anchor.py
```

**All files now use `config_v2` consistently. No import errors. Ready to run.**

---

# Original Project Documentation

## Voice AI Agent - Scammer Deterrent

A real-time voice AI agent that talks to scammers over an audio stream, designed for ultra-low latency (<500ms response time).

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Microphone │───▶│  Silero VAD │───▶│  Whisper    │───▶│   State     │
│   Input     │    │  Detection  │    │  ASR        │    │  Machine    │
└─────────────┘    └─────────────┘    └─────────────┘    └──────┬──────┘
                                                                 │
                                                                 ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Speaker   │◀───│  Coqui TTS  │◀───│  Local LLM  │◀───│   Response  │
│   Output    │    │  Synthesis  │    │  (Phi/Llama)│    │  Generator  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

## Pipeline Flow

1. **VAD (Voice Activity Detection)** - Silero VAD detects when speech starts/ends
2. **ASR (Automatic Speech Recognition)** - Whisper.cpp transcribes the audio
3. **State Machine** - Analyzes transcript and selects behavior state:
   - `CLARIFY` - Ask scammer to repeat/explain
   - `CONFUSE` - Act confused, give off-topic responses
   - `STALL` - Delay with filler words (plays preloaded audio)
   - `EXTRACT` - Subtly probe for scammer information
   - `DEFLECT` - Change subject, avoid giving information
4. **LLM** - Generates short response based on state
5. **TTS** - Converts response to speech
6. **Playback** - Plays audio through speakers

## Project Structure

```
Anchor/
├── main.py           # Main orchestrator
├── config.py         # Configuration settings
├── vad.py            # Voice Activity Detection (Silero)
├── asr.py            # Speech Recognition (Whisper)
├── state_machine.py  # Behavior state machine
├── llm.py            # Local LLM for responses
├── tts.py            # Text-to-Speech (Coqui)
├── audio_utils.py    # Audio recording/playback
├── requirements.txt  # Python dependencies
├── models/           # Model files (download separately)
│   ├── ggml-base.en.bin
│   └── phi-2.gguf
└── audio/
    └── fillers/      # Preloaded filler audio
        ├── uhh_wait_beta.wav
        ├── hmm_let_me_think.wav
        └── one_moment.wav
```

## Installation

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Download models

**Whisper model:**
```bash
mkdir -p models
# Download from https://huggingface.co/ggerganov/whisper.cpp
wget -O models/ggml-base.en.bin https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.en.bin
```

**LLM model (Phi-2 or similar):**
```bash
# Download from https://huggingface.co/TheBloke/phi-2-GGUF
wget -O models/phi-2.gguf https://huggingface.co/TheBloke/phi-2-GGUF/resolve/main/phi-2.Q4_K_M.gguf
```

**Alternative: Use Ollama**
```bash
# Install Ollama from https://ollama.ai
ollama pull phi
```

### 3. Create filler audio files

Place `.wav` files in `audio/fillers/`:
- `uhh_wait_beta.wav`
- `hmm_let_me_think.wav`
- `one_moment.wav`

## Usage

```bash
python main.py
```

Press `Ctrl+C` to stop.

## Configuration

Edit `config.py` to customize:

- **Audio settings**: Sample rate, chunk size
- **VAD settings**: Speech detection thresholds
- **LLM settings**: Model path, temperature, max tokens
- **TTS settings**: Voice model selection
- **Blocked patterns**: Regex patterns to filter from responses

## Safety Features

- **No sensitive data generation**: LLM is blocked from generating phone numbers, OTPs, PINs, SSNs
- **State machine control**: Behavior is controlled by rules, not the LLM
- **Response sanitization**: All outputs are filtered through regex patterns

## Performance Optimization

Target: <500ms end-to-end latency

- Use `faster-whisper` with int8 quantization
- Use small LLM (Phi-2) with Q4 quantization
- Preload filler audio for instant playback
- Use streaming where possible

## Troubleshooting

### No audio input detected
- Check microphone permissions
- Verify PyAudio installation: `pip install pyaudio`
- On Linux, install portaudio: `sudo apt install portaudio19-dev`

### High latency
- Use smaller models (base.en for Whisper)
- Reduce LLM max_tokens
- Enable GPU acceleration if available

### TTS not working
- Install Coqui TTS: `pip install TTS`
- Fallback to pyttsx3: `pip install pyttsx3`

## License

MIT License - Use responsibly and ethically.
