# ANCHOR Setup & Run Guide

## Quick Start (All Platforms)

### 1. Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements_v2.txt
```

### 3. Run ANCHOR
```bash
python run_anchor.py
```

---

## Platform-Specific Setup

### Windows (Recommended: Conda)
```bash
# Install Conda from https://docs.conda.io/en/latest/miniconda.html

# Create environment with PyAudio pre-built
conda create -n anchor python=3.10
conda activate anchor
conda install pyaudio

# Install other dependencies
pip install -r requirements_v2.txt

# Run
python run_anchor.py
```

### Linux (Ubuntu/Debian)
```bash
# Install audio system dependencies
sudo apt update
sudo apt install portaudio19-dev python3-dev python3-venv

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install -r requirements_v2.txt

# Run
python run_anchor.py
```

### macOS
```bash
# Install Homebrew if not already: https://brew.sh

# Install portaudio
brew install portaudio

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install -r requirements_v2.txt

# Run
python run_anchor.py
```

---

## Troubleshooting

### PyAudio Installation Issues

**Windows:**
```bash
# Use conda instead:
conda install pyaudio

# Or download wheel from:
# https://www.lfd.uci.edu/~gohlke/pythonlibs/#pyaudio
pip install PyAudio‑0.2.11‑cp310‑cp310‑win_amd64.whl
```

**Linux:**
```bash
sudo apt install portaudio19-dev python3-dev
pip install pyaudio
```

**macOS:**
```bash
brew install portaudio
pip install pyaudio
```

### faster-whisper Issues

If faster-whisper fails, use OpenAI Whisper:
```bash
pip install openai-whisper
```

Then the code will fallback automatically.

### TTS (Coqui) Issues

If Coqui TTS fails, it will fallback to pyttsx3 automatically.
Ensure pyttsx3 is installed:
```bash
pip install pyttsx3
```

### llama-cpp-python Issues

For GPU support:
```bash
# CUDA
CMAKE_ARGS="-DLLAMA_CUBLAS=on" pip install llama-cpp-python

# Metal (macOS)
CMAKE_ARGS="-DLLAMA_METAL=on" pip install llama-cpp-python
```

For CPU-only (default):
```bash
pip install llama-cpp-python
```

---

## Running Tests

### Test Jailbreak Protection
```bash
python test_jailbreak.py           # Basic test
python test_jailbreak.py --verbose # Detailed output
python test_jailbreak.py --strict  # Strict mode
```

---

## Project Structure

```
Anchor/
├── run_anchor.py           # Main entry point (START HERE)
├── requirements_v2.txt     # Dependencies
├── config_v2.py            # Configuration
├── main_v2.py              # Pipeline orchestration
├── vad_v2.py               # Voice Activity Detection
├── asr_v2.py               # Speech Recognition
├── state_machine_v2.py     # State machine + jailbreak guard
├── llm_v2.py               # Template-based LLM
├── tts_v2.py               # Text-to-Speech
├── audio_utils_v2.py       # Audio I/O + echo prevention
└── test_jailbreak.py       # Jailbreak protection tests
```

---

## Configuration

Edit `config_v2.py` to adjust:
- Latency targets
- Model paths
- Audio settings
- State machine templates
- Jailbreak patterns

---

## Performance Targets

- **Total latency:** <500ms end-to-end
- **VAD → ASR:** <50ms
- **ASR:** <150ms
- **State machine:** <5ms
- **LLM first token:** <100ms
- **TTS first audio:** <150ms

---

## Notes

- All v2 files use `config_v2` only
- No circular imports
- Template-only mode works without LLM
- Echo suppression prevents AI hearing itself
- Jailbreak protection prevents prompt injection
