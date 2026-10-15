"""
Legacy alias for backend.input_validator.
Redirects to the new clear module: backend.input_validator.
"""
try:
    from backend.input_validator import *
except ImportError:
    from input_validator import *
