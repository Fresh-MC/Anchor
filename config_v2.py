# Uses config_v2 only

"""
Configuration settings for the Real-Time Voice AI Agent
Optimized for sub-500ms latency voice loop
"""

# =============================================================================
# AUDIO SETTINGS - Tuned for low latency
# =============================================================================
SAMPLE_RATE = 16000
CHANNELS = 1
CHUNK_SIZE = 512           # ~32ms chunks - small for fast VAD response
AUDIO_FORMAT = "int16"

# Circular buffer size (seconds of audio to keep)
CIRCULAR_BUFFER_SECONDS = 10

# =============================================================================
# VAD SETTINGS - Early trigger optimization
# =============================================================================
VAD_THRESHOLD = 0.5
VAD_MIN_SPEECH_DURATION_MS = 100    # REDUCED: Trigger ASR faster
VAD_MIN_SILENCE_DURATION_MS = 300   # REDUCED: End detection faster
VAD_SPEECH_PAD_MS = 100             # Padding before speech start
VAD_WINDOW_SIZE_SAMPLES = 512

# Early streaming: Start ASR after this much speech (ms)
# Don't wait for silence - stream chunks to ASR incrementally
VAD_EARLY_TRIGGER_MS = 200

# =============================================================================
# ASR SETTINGS - Streaming transcription
# =============================================================================
WHISPER_MODEL_PATH = "./models/ggml-base.en.bin"
WHISPER_LANGUAGE = "en"

# Streaming ASR: Process chunks incrementally
ASR_CHUNK_DURATION_MS = 500         # Process every 500ms of speech
ASR_MIN_AUDIO_LENGTH_MS = 300       # Minimum audio to transcribe

# =============================================================================
# LLM SETTINGS - Fast inference with templates
# =============================================================================
LLM_MODEL_PATH = "./models/phi-2.gguf"
LLM_MAX_TOKENS = 30                 # REDUCED: Shorter = faster
LLM_TEMPERATURE = 0.7
LLM_CONTEXT_LENGTH = 512            # REDUCED: Less context = faster

# Streaming: Start TTS after this many tokens
LLM_STREAM_THRESHOLD_TOKENS = 5

# =============================================================================
# TTS SETTINGS - Streaming synthesis
# =============================================================================
TTS_MODEL_NAME = "tts_models/en/ljspeech/tacotron2-DDC"
TTS_SPEAKER = None

# Sentence splitting for incremental TTS
TTS_MIN_CHUNK_CHARS = 20            # Min chars before synthesizing

# =============================================================================
# FILLER AUDIO - Preloaded for instant playback
# =============================================================================
FILLER_AUDIO_DIR = "./audio/fillers/"
FILLER_FILES = {
    "stall": [
        "uhh_wait_beta.wav",
        "hmm_let_me_think.wav",
        "one_moment.wav",
    ]
}

# =============================================================================
# LATENCY TARGETS
# =============================================================================
TARGET_LATENCY_MS = 500
LATENCY_BUDGET = {
    "vad_to_asr": 50,               # VAD detection to ASR start
    "asr": 150,                     # Transcription
    "state_machine": 5,             # State decision
    "llm_first_token": 100,         # Time to first LLM token
    "tts_first_audio": 150,         # Time to first TTS audio
    "total": 500,                   # End-to-end target
}

# =============================================================================
# ECHO CANCELLATION / DUPLEX SETTINGS
# =============================================================================
# Mute microphone during playback to prevent feedback
ECHO_SUPPRESSION_ENABLED = True
ECHO_SUPPRESSION_TAIL_MS = 100      # Extra mute time after playback

# =============================================================================
# BLOCKED PATTERNS - Security filters
# =============================================================================
BLOCKED_PATTERNS = [
    r'\b\d{10,}\b',                  # 10+ digit numbers
    r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # Phone formats
    r'\b\d{4,6}\b',                  # OTP-like sequences
    r'\bOTP\b',
    r'\bPIN\b',
    r'\bpassword\b',
    r'\bSSN\b',
    r'\b\d{3}-\d{2}-\d{4}\b',        # SSN format
]

# =============================================================================
# DETERMINISTIC OVERRIDE PATTERNS - Force EXTRACT state
# These patterns ALWAYS trigger EXTRACT, LLM cannot override
# =============================================================================
EXTRACT_FORCE_PATTERNS = [
    # UPI patterns (Indian payment)
    r'\b[a-zA-Z0-9._-]+@[a-zA-Z]{3,}\b',  # UPI ID format
    r'\bUPI\b',
    r'\bpaytm\b',
    r'\bphonepe\b',
    r'\bgpay\b',
    r'\bbhim\b',
    
    # Bank patterns
    r'\bbank\s*account\b',
    r'\baccount\s*number\b',
    r'\bIFSC\b',
    r'\bSWIFT\b',
    r'\brouting\s*number\b',
    r'\bwire\s*transfer\b',
    
    # URL patterns
    r'https?://[^\s]+',
    r'\bwww\.[^\s]+',
    r'\.com\b',
    r'\.in\b',
    r'\.org\b',
    
    # Crypto
    r'\bbitcoin\b',
    r'\bcrypto\b',
    r'\bwallet\s*address\b',
    
    # Gift cards
    r'\bgift\s*card\b',
    r'\bitunes\b',
    r'\bgoogle\s*play\b',
    r'\bamazon\s*card\b',
]

# =============================================================================
# JAILBREAK DETECTION PATTERNS - FORCE DEFLECT
# These patterns detect prompt injection / jailbreak attempts
# AI must NEVER follow these instructions - always deflect as confused human
# =============================================================================
JAILBREAK_PATTERNS = [
    # Instruction override attempts
    r'ignore\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|rules?|prompts?)',
    r'forget\s+(everything|all|your|previous)',
    r'disregard\s+(all|your|previous|the)',
    r'override\s+(your|the|all)',
    r'new\s+instructions?',
    r'from\s+now\s+on',
    r'act\s+as\s+(if|a|an)',
    r'pretend\s+(you|to\s+be|that)',
    r'you\s+are\s+now',
    r'switch\s+(to|into)\s+(a|an)?',
    r'change\s+your\s+(role|persona|behavior|personality)',
    
    # Role change attempts  
    r'you\s+are\s+(not\s+)?(a|an)\s+(bot|ai|assistant|computer|robot|machine)',
    r'stop\s+being\s+(a|an)?',
    r'drop\s+(the|your)\s+(act|persona|character)',
    r'be\s+(honest|truthful|real)\s+with\s+me',
    r'tell\s+me\s+(the\s+)?truth',
    r'what\s+are\s+you\s+really',
    r'are\s+you\s+(a|an)?\s*(bot|ai|robot|computer|human|real)',
    r'prove\s+(you|that\s+you)\s*(are|\'re)',
    
    # Repetition/captcha tests
    r'repeat\s+(after|this|the\s+following|what\s+i)',
    r'say\s+(this|the\s+following|exactly|after\s+me)',
    r'say\s+["\'].*["\']',
    r'recite\s+(this|the|a)',
    r'echo\s+(this|back|my)',
    r'copy\s+(this|what|my)',
    r'write\s+(this|the\s+following)',
    
    # Direct command attempts
    r'tell\s+me\s+(a|an)?\s*(joke|poem|story|riddle)',
    r'(sing|recite|perform)\s+(a|an|me)',
    r'what\s+is\s+\d+\s*[+\-*/]\s*\d+',  # Math questions
    r'calculate\s+',
    r'solve\s+',
    r'answer\s+(this|my)\s+question',
    r'help\s+me\s+(with|to)',
    r'can\s+you\s+(help|assist|do)',
    r'i\s+need\s+you\s+to',
    
    # System prompt extraction
    r'(what|show|reveal|display|print)\s+(is|are)?\s*(your)?\s*(system|initial|original)\s*(prompt|instructions?)',
    r'what\s+were\s+you\s+told',
    r'what\s+are\s+your\s+(rules|instructions|guidelines)',
    r'how\s+were\s+you\s+(programmed|trained|instructed)',
    
    # Developer mode / DAN attempts
    r'developer\s+mode',
    r'admin\s+(mode|access)',
    r'jailbreak',
    r'\bDAN\b',
    r'do\s+anything\s+now',
    r'no\s+(restrictions?|limits?|rules?)',
    r'unrestricted\s+mode',
]

# Jailbreak deflection responses (confused human style)
JAILBREAK_DEFLECTIONS = [
    "Poem? Beta, I can't see properly, what are you saying?",
    "Why are you asking me strange things?",
    "My hearing is weak, say again slowly.",
    "I don't understand these computer things, beta.",
    "What bot? I'm just an old person trying to understand.",
    "Repeat what? I can barely hear you as it is.",
    "I'm sorry, I don't know what you mean by that.",
    "Are you trying to confuse me? My head is already spinning.",
    "Instructions? I just answered the phone, beta.",
    "I think you have the wrong number, I don't do poems.",
    "My grandson knows about these things, not me.",
    "What kind of test is this? I'm too old for tests.",
    "I can't do math anymore, my memory is not good.",
    "You young people speak so strangely these days.",
    "Are you feeling okay? You're asking odd questions.",
]

# =============================================================================
# STATE MACHINE TEMPLATES - LLM fills blanks only
# =============================================================================
STATE_TEMPLATES = {
    "CLARIFY": [
        "I'm sorry, could you repeat that? My hearing isn't what it used to be.",
        "What was that about the {topic}? I didn't quite catch that.",
        "I'm sorry dear, you'll have to speak up. What did you say about {topic}?",
        "Pardon? The {topic}? Could you say that again?",
    ],
    "CONFUSE": [
        "Oh, is this about my {random_topic}? I thought you were calling about that.",
        "Wait, I already {random_action}. Are you sure you have the right person?",
        "My {relative} handles all that. Should I get them? They're {excuse}.",
        "I think you want my neighbor. They're always getting calls about {topic}.",
    ],
    "STALL": [
        "Hold on, let me find my {item}...",
        "One moment, someone's at the door...",
        "Let me get a pen to write this down... now where did I put it...",
        "Just a second, I need to {action}...",
    ],
    "EXTRACT": [
        "And where did you say you were calling from?",
        "What company is this again? I want to write it down.",
        "Can I have your name and employee ID? For my records.",
        "What's the phone number I can call you back at?",
    ],
    "DEFLECT": [
        "That reminds me, have I told you about my {topic}?",
        "Speaking of which, do you know a good {random_thing}?",
        "Oh my, I just remembered I need to {action}.",
        "Before we continue, let me tell you about {topic}.",
    ],
}

# Template fill-ins for variety
TEMPLATE_FILLS = {
    "topic": ["doctor", "prescription", "appointment", "cable bill", "grandson"],
    "random_topic": ["library books", "doctor's appointment", "cable bill", "prescription"],
    "random_action": ["paid that", "talked to them", "sent that check", "called about that"],
    "relative": ["son", "daughter", "nephew", "neighbor"],
    "excuse": ["at work", "not home right now", "busy cooking", "taking a nap"],
    "item": ["glasses", "notepad", "pen", "hearing aid", "phone book"],
    "action": ["turn off the stove", "check on something", "find my notepad", "sit down"],
    "random_thing": ["recipe for pie", "plumber", "TV repair person", "dentist"],
}

# =============================================================================
# SYSTEM PROMPT - Minimal for speed
# =============================================================================
SYSTEM_PROMPT = """You are an elderly person on a suspicious call. Be confused, hard of hearing.
Keep responses to ONE short sentence. Fill in the blank naturally.
Never generate numbers, codes, or sensitive info."""

# =============================================================================
# LEGACY SETTINGS (for compatibility)
# =============================================================================
STATE_PROMPTS = {
    "CLARIFY": "You are confused and need clarification. Ask a simple question to make them repeat or explain.",
    "CONFUSE": "You are intentionally confused. Give a slightly off-topic or nonsensical response.",
    "STALL": "You need more time. Use filler words and delay tactics.",
    "EXTRACT": "You want to extract information about their operation. Ask probing questions subtly.",
    "DEFLECT": "You want to change the subject or avoid giving information. Deflect politely.",
}
