#!/bin/bash
# ANCHOR Setup Script for Linux/macOS
# ====================================

set -e

echo "======================================================================"
echo "   ANCHOR - Real-Time Voice AI Agent Setup (Linux/macOS)"
echo "======================================================================"
echo ""

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 not found! Please install Python 3.9+"
    exit 1
fi

echo "[1/5] Installing system dependencies..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Detected Linux - installing portaudio19-dev..."
    if command -v apt &> /dev/null; then
        sudo apt update
        sudo apt install -y portaudio19-dev python3-dev python3-venv
    elif command -v yum &> /dev/null; then
        sudo yum install -y portaudio-devel python3-devel
    else
        echo "WARNING: Could not detect package manager. Please install portaudio manually."
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Detected macOS - installing portaudio..."
    if command -v brew &> /dev/null; then
        brew install portaudio
    else
        echo "WARNING: Homebrew not found. Please install from https://brew.sh"
        echo "Then run: brew install portaudio"
    fi
fi

echo "[2/5] Creating virtual environment..."
python3 -m venv venv

echo "[3/5] Activating virtual environment..."
source venv/bin/activate

echo "[4/5] Upgrading pip..."
pip install --upgrade pip setuptools wheel

echo "[5/5] Installing dependencies from requirements_v2.txt..."
pip install -r requirements_v2.txt || {
    echo ""
    echo "WARNING: Some packages may have failed to install."
    echo ""
    echo "Common fixes:"
    echo "  - For PyAudio errors on macOS: brew install portaudio"
    echo "  - For PyAudio errors on Linux: sudo apt install portaudio19-dev"
    echo "  - For llama-cpp errors: pip install llama-cpp-python --no-cache-dir"
    echo ""
}

echo ""
echo "======================================================================"
echo "   Setup Complete!"
echo "======================================================================"
echo ""
echo "To run ANCHOR:"
echo "  1. Activate the environment: source venv/bin/activate"
echo "  2. Run: python run_anchor.py"
echo ""
echo "To test jailbreak protection:"
echo "  python test_jailbreak.py"
echo ""
