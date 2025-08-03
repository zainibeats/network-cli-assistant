"""
Formatting module.

This module provides output formatting and color utilities for terminal display.
"""

# Import all formatting functions and classes
from .output import format_output
from .colors import Colors

# Export all functions and classes for easy importing
__all__ = [
    'format_output',
    'Colors'
]