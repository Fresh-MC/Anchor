#!/usr/bin/env python3
# Uses config_v2 only

"""
ANCHOR - Real-Time Voice AI Agent
=================================
Entry point for running the ANCHOR voice AI system.

This script imports and starts the main_v2.py voice agent.
All configuration is in config_v2.py.

Usage:
    python run_anchor.py
    
Requirements:
    See requirements_v2.txt
    Install with: pip install -r requirements_v2.txt
"""

import sys
import os

# Ensure we're using the v2 modules
print("=" * 70)
print("   ANCHOR - Real-Time Voice AI Agent")
print("   Loading v2 modules...")
print("=" * 70)

try:
    # Import main_v2 and run
    from main_v2 import main
    
    print("\n✅ All modules loaded successfully\n")
    
    # Run the agent
    main()
    
except ImportError as e:
    print("\n❌ Import Error - Missing dependencies")
    print(f"   Error: {e}")
    print("\nPlease install dependencies:")
    print("   pip install -r requirements_v2.txt")
    print("\nOr if using a virtual environment:")
    print("   python -m venv venv")
    print("   source venv/bin/activate  # On Windows: venv\\Scripts\\activate")
    print("   pip install -r requirements_v2.txt")
    sys.exit(1)
    
except KeyboardInterrupt:
    print("\n\n👋 Shutting down ANCHOR...")
    sys.exit(0)
    
except Exception as e:
    print(f"\n❌ Unexpected error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
