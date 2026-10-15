"""
Legacy alias for backend.report_builder.
Redirects to the new clear module: backend.report_builder.
"""
try:
    from backend.report_builder import *
except ImportError:
    from report_builder import *
