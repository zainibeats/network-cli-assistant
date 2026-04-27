"""
Formatting module.

This module provides output formatting and color utilities for terminal display.
"""

# Import all formatting functions and classes
from .colors import Colors
from .output import format_output

# Export all functions and classes for easy importing
__all__ = ["format_output", "Colors"]
