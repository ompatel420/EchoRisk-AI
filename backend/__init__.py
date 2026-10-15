"""
EchoRisk AI Backend Package.
"""
import sys
sys.dont_write_bytecode = True

try:
    from backend.app import app
except ImportError:
    from .app import app

__all__ = ["app"]
