"""
EchoRisk AI Backend Package.
"""
try:
    from backend.app import app
except ImportError:
    from .app import app

__all__ = ["app"]
