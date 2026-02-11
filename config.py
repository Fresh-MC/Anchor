"""
Configuration settings for the Voice AI Agent
"""

# Audio settings
SAMPLE_RATE = 16000
CHANNELS = 1
CHUNK_SIZE = 512  # ~32ms chunks for low latency
AUDIO_FORMAT = "int16"

# VAD settings
VAD_THRESHOLD = 0.5
VAD_MIN_SPEECH_DURATION_MS = 250
VAD_MIN_SILENCE_DURATION_MS = 500
VAD_WINDOW_SIZE_SAMPLES = 512

# ASR settings (whisper.cpp)
WHISPER_MODEL_PATH = "./models/ggml-base.en.bin"
WHISPER_LANGUAGE = "en"

# LLM settings
LLM_MODEL_PATH = "./models/phi-2.gguf"
LLM_MAX_TOKENS = 50  # Keep responses short for low latency
LLM_TEMPERATURE = 0.7

# TTS settings
TTS_MODEL_NAME = "tts_models/en/ljspeech/tacotron2-DDC"
TTS_SPEAKER = None

# Filler audio paths
FILLER_AUDIO_DIR = "./audio/fillers/"
FILLER_FILES = {
    "stall": [
        "uhh_wait_beta.wav",
        "hmm_let_me_think.wav",
        "one_moment.wav",
    ]
}

# Response latency target (ms)
TARGET_LATENCY_MS = 500

# Blocked patterns (phone numbers, OTPs, etc.)
BLOCKED_PATTERNS = [
    r'\b\d{10,}\b',           # 10+ digit numbers
    r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # Phone number formats
    r'\b\d{4,6}\b',           # OTP-like sequences
    r'\bOTP\b',
    r'\bPIN\b',
    r'\bpassword\b',
    r'\bSSN\b',
    r'\b\d{3}-\d{2}-\d{4}\b', # SSN format
]

# State machine prompts
STATE_PROMPTS = {
    "CLARIFY": "You are confused and need clarification. Ask a simple question to make them repeat or explain.",
    "CONFUSE": "You are intentionally confused. Give a slightly off-topic or nonsensical response.",
    "STALL": "You need more time. Use filler words and delay tactics.",
    "EXTRACT": "You want to extract information about their operation. Ask probing questions subtly.",
    "DEFLECT": "You want to change the subject or avoid giving information. Deflect politely.",
}

# Base system prompt
SYSTEM_PROMPT = """You are an elderly person who received a suspicious phone call. 
You are slightly hard of hearing and easily confused.
Keep responses SHORT (1-2 sentences max).
Never share real personal information.
Never generate phone numbers, OTPs, PINs, or passwords.
Sound natural and conversational."""
