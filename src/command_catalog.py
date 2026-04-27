"""
Command catalog exposed to the language model.

The catalog keeps prompt generation and command validation in one place so
model providers can stay thin adapters.
"""

import inspect
from typing import Callable, Dict

from . import core_functions


def get_available_functions() -> Dict[str, Callable]:
    """Return public network functions available to the assistant."""
    return {
        name: func
        for name, func in inspect.getmembers(core_functions, inspect.isfunction)
        if not name.startswith("_")
    }


def get_function_specs() -> str:
    """Build compact function specs for prompt context."""
    specs = []
    for name, func in get_available_functions().items():
        signature = inspect.signature(func)
        docstring = inspect.getdoc(func) or "No documentation available"
        specs.append(f'Function: {name}{signature}\n"""{docstring}"""')

    return "\n\n".join(specs)


def has_function(name: str) -> bool:
    """Return whether a function name is available for execution."""
    return name in get_available_functions()


def get_function(name: str) -> Callable:
    """Return an available function by name."""
    return get_available_functions()[name]
