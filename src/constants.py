"""
src/constants.py

Application-wide constants. Unlike src/env_config.py, these are not derived from
environment variables, they are fixed values baked into the application.
"""

from pathlib import Path

# Filesystem paths

PROJECT_ROOT: Path = Path(__file__).parent.parent
PAYLOADS_DIR: Path = PROJECT_ROOT / "payloads"
