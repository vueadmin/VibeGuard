# VibeGuard Source Code Structure

This document describes the organization of the VibeGuard VSCode extension source code.

## Directory Structure

```
src/
├── extension.ts              # Main extension entry point
├── types/
│   └── index.ts             # Core type definitions and interfaces
├── constants/
│   └── index.ts             # Configuration constants and defaults
├── utils/
│   └── index.ts             # Utility functions
├── services/
│   └── index.ts             # Service exports (implementations added in later tasks)
├── monitor/                 # Document monitoring (Task 2.1)
├── analyzer/                # Analysis engine (Task 2.2)
├── rules/                   # Rule engine and definitions (Tasks 3+)
│   └── definitions/         # Rule definition files
├── diagnostics/             # Diagnostic management (Task 5.1)
├── quickfix/                # Quick fix provider (Task 6.1)
└── test/                    # Test files
```

## Core Components

### 1. Extension Entry Point (`extension.ts`)
- Manages extension lifecycle (activation/deactivation)
- Registers commands and event listeners
- Initializes core services
- Handles configuration changes

### 2. Type Definitions (`types/index.ts`)
- Defines all interfaces and types used throughout the extension
- Establishes contracts between different components
- Includes security issue models, rule definitions, and service interfaces

### 3. Constants (`constants/index.ts`)
- Default configuration values
- Error and success messages
- Command identifiers
- File extension mappings
- Common regex patterns

### 4. Utilities (`utils/index.ts`)
- Language detection functions
- Text processing utilities
- Configuration helpers
- Error handling utilities
- VSCode integration helpers

## Implementation Progress

- [x] Task 1: Project foundation and core interfaces
- [ ] Task 2.1: Document monitoring
- [ ] Task 2.2: Analysis engine
- [ ] Task 3+: Rule implementations
- [ ] Task 5.1: Diagnostic management
- [ ] Task 6.1: Quick fix provider

## Key Design Principles

1. **Zero Configuration**: Extension works out of the box
2. **Performance First**: Debounced analysis with timeout protection
3. **User-Friendly**: Chinese error messages, avoid technical jargon
4. **Extensible**: Rule-based architecture for easy addition of new checks
5. **Robust**: Graceful error handling, silent failures when appropriate

## Next Steps

The foundation is now in place. Subsequent tasks will implement:
1. Document monitoring service
2. Analysis engine with rule execution
3. Specific security rule definitions
4. Diagnostic display and management
5. Quick fix functionality