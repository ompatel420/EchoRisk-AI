"""
Legacy alias for backend.breach_intel.
Redirects to the new clear module: backend.breach_intel.
"""
try:
    from backend.breach_intel import *
except ImportError:
    from breach_intel import *
