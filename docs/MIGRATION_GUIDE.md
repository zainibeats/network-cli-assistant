# Migration Guide: Modular Code Structure

This document describes the new modular code structure implemented in the Network CLI Assistant and provides guidance for future development.

## Overview

The codebase has been refactored from a monolithic structure into smaller, focused modules organized by functionality. This improves maintainability, testability, and separation of concerns.

## New Module Structure

### Network Operations (`src/network/`)

All network-related functionality has been organized into focused modules:

- **`ssh.py`** - SSH command execution functions (`run_command`)
- **`acl.py`** - ACL generation functions (`generate_acl`)
- **`connectivity.py`** - Basic connectivity functions (`ping`, `traceroute`)
- **`dns.py`** - DNS lookup functions (`dns_lookup`)
- **`discovery.py`** - Host and network discovery functions (`discover_hosts`)
- **`scanning.py`** - Port scanning functions (`run_nmap_scan`, `run_netstat`)
- **`analysis.py`** - Result analysis and interpretation functions (`interpret_nmap_results`)

### Validation (`src/validation/`)

Input validation has been split into focused modules:

- **`network.py`** - Network-specific validation functions
  - `validate_ip()`, `validate_ip_with_details()`
  - `validate_hostname()`, `validate_target()`
  - `validate_network_target()`, `validate_port()`
- **`input.py`** - General input validation functions
  - `create_validation_error()`
  - `validate_network_operation_input()`
  - `retry_network_operation()`

### Formatting (`src/formatting/`)

Output formatting has been organized into:

- **`output.py`** - Output formatting and display functions (`format_output`)
- **`colors.py`** - Color constants and terminal formatting (`Colors` class)

### Error Handling (`src/error_handling/`)

Error handling has been split into:

- **`network.py`** - Network-specific error handling functions
  - `handle_network_timeout()`, `handle_dns_resolution_error()`
  - `handle_connection_refused_error()`, `handle_permission_denied_error()`
  - `handle_command_not_found_error()`
- **`common.py`** - Common error handling utilities
  - `create_generic_error()`, `handle_unexpected_error()`
  - `is_recoverable_error()`, `format_error_for_logging()`

## Backward Compatibility

The refactoring maintains full backward compatibility:

- **`src/core_functions.py`** - Now imports all functions from `src/network/` modules
- **`src/utils.py`** - Now imports all functions from validation, formatting, and error handling modules

Existing code that imports from these modules will continue to work without changes.

## Import Patterns

### For New Code

Use specific imports from the new modules:

```python
# Network operations
from src.network.ssh import run_command
from src.network.connectivity import ping, traceroute
from src.network.scanning import run_nmap_scan

# Validation
from src.validation.network import validate_ip, validate_target
from src.validation.input import create_validation_error

# Formatting
from src.formatting.output import format_output
from src.formatting.colors import Colors

# Error handling
from src.error_handling.network import handle_network_timeout
from src.error_handling.common import create_generic_error
```

### For Existing Code

Continue using existing imports (backward compatible):

```python
# These still work
from src.core_functions import run_command, ping, run_nmap_scan
from src.utils import validate_ip, format_output, Colors
```

## Adding New Functions

### Network Functions

1. **Choose the appropriate module** based on functionality:
   - SSH operations → `src/network/ssh.py`
   - Connectivity tests → `src/network/connectivity.py`
   - Port/host scanning → `src/network/scanning.py`
   - DNS operations → `src/network/dns.py`
   - Host discovery → `src/network/discovery.py`
   - Result analysis → `src/network/analysis.py`

2. **Add the function** to the appropriate module
3. **Export it** in the module's `__all__` list
4. **Import it** in `src/network/__init__.py`
5. **Add it** to `src/core_functions.py` for backward compatibility

### Validation Functions

1. **Network-specific validation** → `src/validation/network.py`
2. **General input validation** → `src/validation/input.py`
3. **Export and import** following the same pattern as network functions

### Formatting Functions

1. **Output formatting** → `src/formatting/output.py`
2. **Color/style constants** → `src/formatting/colors.py`

### Error Handling Functions

1. **Network-specific errors** → `src/error_handling/network.py`
2. **General error utilities** → `src/error_handling/common.py`

## Module Guidelines

### Function Organization

- **One responsibility per module** - Each module should have a clear, focused purpose
- **Related functions together** - Group functions that work with similar data or serve similar purposes
- **Consistent interfaces** - Functions in the same module should follow similar patterns

### Documentation

- **Module-level docstrings** - Each module should have a clear docstring explaining its purpose
- **Function docstrings** - All public functions should have comprehensive docstrings
- **Type hints** - Use type hints for all function parameters and return values

### Testing

- **Module-specific tests** - Create test files that mirror the module structure
- **Import testing** - Test both new modular imports and backward-compatible imports
- **Integration testing** - Ensure modules work together correctly

## Benefits of New Structure

1. **Improved Maintainability** - Smaller, focused files are easier to understand and modify
2. **Better Testing** - Modules can be tested in isolation
3. **Clearer Dependencies** - Import statements clearly show what functionality is being used
4. **Easier Debugging** - Issues can be traced to specific modules more easily
5. **Enhanced Reusability** - Individual modules can be reused in other projects
6. **Better Code Organization** - Related functionality is grouped together logically

## Migration Checklist for Developers

When working with the new structure:

- [ ] Use specific imports from new modules for new code
- [ ] Update existing imports gradually (optional, backward compatibility maintained)
- [ ] Add new functions to appropriate modules based on functionality
- [ ] Update module `__init__.py` files when adding new functions
- [ ] Maintain backward compatibility in `core_functions.py` and `utils.py`
- [ ] Write tests for new modules and functions
- [ ] Update documentation to reflect new structure

## Future Considerations

- **Plugin Architecture** - The modular structure makes it easier to implement a plugin system
- **Configuration Management** - Consider adding a dedicated `src/config/` module
- **API Layer** - The modular structure supports adding REST/GraphQL APIs
- **Async Operations** - Individual modules can be enhanced with async support independently