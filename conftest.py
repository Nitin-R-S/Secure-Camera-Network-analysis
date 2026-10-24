"""
conftest.py

Ensures the project root is importable as a package root when running
pytest from the project directory, and provides a minimal AES_KEY / secrets
for tests that instantiate encryption/auth objects without needing a real
.env file.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Provide safe dummy values so config.settings doesn't blow up during tests
# when no .env is present. Individual tests generate their own keys/secrets
# where cryptographic correctness matters.
os.environ.setdefault("AES_KEY", "")
os.environ.setdefault("ADMIN_API_KEY", "test-admin-key")
