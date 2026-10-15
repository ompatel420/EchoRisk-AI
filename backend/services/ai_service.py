"""
Legacy alias for backend.ai_risk_engine.
Redirects to the new clear module: backend.ai_risk_engine.
"""
try:
    from backend.ai_risk_engine import *
except ImportError:
    from ai_risk_engine import *
