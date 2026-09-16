"""Put the repository root on sys.path for every test directory."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
