# ANCHOR - Terminal Command Reference

## 🚀 Quick Start (Copy & Paste)

### Windows
```cmd
REM Run the setup script
setup_windows.bat

REM Or manually:
python -m venv venv
venv\Scripts\activate
pip install -r requirements_v2.txt
python run_anchor.py
```

### Linux/macOS
```bash
# Run the setup script
chmod +x setup_linux.sh
./setup_linux.sh

# Or manually:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements_v2.txt
python run_anchor.py
```

---

## 📦 Installation Steps (Manual)

### Step 1: Create Virtual Environment
```bash
# Windows
python -m venv venv

# Linux/macOS
python3 -m venv venv
```

### Step 2: Activate Virtual Environment
```bash
# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements_v2.txt
```

### Step 4: Run ANCHOR
```bash
python run_anchor.py
```

---

## 🧪 Testing

### Run Jailbreak Protection Tests
```bash
# Basic test
python test_jailbreak.py

# Verbose output (shows all test details)
python test_jailbreak.py --verbose

# Strict mode (warnings = failures)
python test_jailbreak.py --strict
```

---

## 🔧 Troubleshooting Commands

### If PyAudio Fails (Windows)
```bash
# Option 1: Use conda
conda install pyaudio
pip install -r requirements_v2.txt

# Option 2: Download pre-built wheel
# Visit: https://www.lfd.uci.edu/~gohlke/pythonlibs/#pyaudio
pip install PyAudio-0.2.11-cp310-cp310-win_amd64.whl
```

### If PyAudio Fails (Linux)
```bash
sudo apt update
sudo apt install portaudio19-dev python3-dev
pip install pyaudio
```

### If PyAudio Fails (macOS)
```bash
brew install portaudio
pip install pyaudio
```

### If faster-whisper Fails
```bash
# Install OpenAI Whisper instead
pip install openai-whisper
# Code will auto-fallback
```

### If llama-cpp-python Fails
```bash
# Clean install
pip uninstall llama-cpp-python
pip install llama-cpp-python --no-cache-dir

# For GPU support (CUDA)
CMAKE_ARGS="-DLLAMA_CUBLAS=on" pip install llama-cpp-python

# For GPU support (Metal/macOS)
CMAKE_ARGS="-DLLAMA_METAL=on" pip install llama-cpp-python
```

### If Coqui TTS Fails
```bash
# Install without dependencies first
pip install TTS --no-deps
# Then install other requirements
pip install -r requirements_v2.txt
# Code will fallback to pyttsx3 if needed
```

---

## 🔍 Verification Commands

### Check Python Version
```bash
python --version
# Should be 3.9 or higher
```

### Check Installed Packages
```bash
pip list | grep -E "torch|numpy|faster-whisper|TTS|llama-cpp"
```

### Test Imports
```python
python -c "import config_v2; print('Config OK')"
python -c "import torch; print('PyTorch OK')"
python -c "import numpy; print('NumPy OK')"
python -c "from faster_whisper import WhisperModel; print('faster-whisper OK')"
```

---

## 📁 Project File Verification

### Check All v2 Files Exist
```bash
# Windows
dir *_v2.py

# Linux/macOS
ls -la *_v2.py
```

Expected files:
- `config_v2.py`
- `vad_v2.py`
- `asr_v2.py`
- `state_machine_v2.py`
- `llm_v2.py`
- `tts_v2.py`
- `audio_utils_v2.py`
- `main_v2.py`

---

## 🎯 Running Different Modes

### Template-Only Mode (No LLM)
```bash
# Edit config_v2.py and set:
# LLM_MODEL_PATH = ""
python run_anchor.py
# Will use templates only (fastest)
```

### With Local LLM
```bash
# Download a model (e.g., Phi-2 GGUF)
# Place in ./models/
# Update config_v2.py: LLM_MODEL_PATH = "./models/phi-2.gguf"
python run_anchor.py
```

### With Ollama
```bash
# Start Ollama server
ollama serve

# In another terminal:
ollama pull phi

# Then run ANCHOR
python run_anchor.py
```

---

## 📊 Performance Monitoring

### Run with Metrics
```bash
python run_anchor.py
# Metrics printed on Ctrl+C
```

### Expected Output
```
[VAD] 🎤 Speech START
[ASR] 150ms for 2000ms audio
[STATE] CLARIFY -> DEFLECT (3ms)
[LLM] 95ms: "What was that dear?"
[TTS] 120ms for 800ms audio

[TIMING]
  ASR:    150ms
  State:    3ms
  LLM:     95ms
  TTS:    120ms
  ──────────────
  TOTAL:  368ms ✅
```

---

## 🛠 Development Commands

### Format Code
```bash
pip install black
black *_v2.py test_jailbreak.py run_anchor.py
```

### Type Checking
```bash
pip install mypy
mypy --ignore-missing-imports *_v2.py
```

### Run Tests with Coverage
```bash
pip install pytest pytest-cov
pytest test_jailbreak.py --cov=. --cov-report=html
```

---

## 🔄 Update Dependencies
```bash
pip install --upgrade -r requirements_v2.txt
```

---

## 🧹 Clean Install
```bash
# Remove old environment
rm -rf venv  # Linux/macOS
rmdir /s venv  # Windows

# Recreate from scratch
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate  # Windows
pip install -r requirements_v2.txt
```

---

## ❓ Getting Help

### Check Logs
```bash
python run_anchor.py 2>&1 | tee anchor.log
```

### Check System Info
```bash
python --version
pip --version
pip list
```

### Common Error Messages

**"Import Error: config_v2"**
→ Make sure you're in the project directory

**"No module named torch"**
→ Run: `pip install torch`

**"PortAudio not found"**
→ Install system dependencies (see setup scripts)

**"Model file not found"**
→ Check `config_v2.py` paths or use template-only mode
