# Pynagent Workspace

This workspace contains two Rust crates:

1. **Pynagent-core** (AGPL-3.0) - Open source core scanner
2. **Pynagent-pro-engine** (PROPRIETARY) - Advanced proprietary features

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Pynagent Workspace                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  Pynagent-core (AGPL-3.0)                            │ │
│  │  ├── Basic linting rules                            │ │
│  │  ├── Tree-sitter AST parsing                        │ │
│  │  ├── Multi-language support                         │ │
│  │  ├── SARIF/JSON output                           │ │
│  │  └── LSP server                                   │ │
│  │                                                     │ │
│  │  ↕ JSON IPC (stdin/stdout)                       │ │
│  │                                                     │ │
│  └─────────────────────────────────────────────────────┘ │
│                           ▲                               │
│                           │                               │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  Pynagent-pro-engine (PROPRIETARY)                   │ │
│  │  ├── Semantic analysis engine                      │ │
│  │  ├── Type validation (mypy/pyright)               │ │
│  │  ├── AI bug detection                             │ │
│  │  ├── Dependency vulnerability scanning             │ │
│  │  ├── CVE/GHSA integration                        │ │
│  │  └── Advanced security rules                       │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Building

### Build Core Only
```bash
cargo build -p Pynagent-core --release
```

### Build Pro Engine (requires license)
```bash
cargo build -p Pynagent-pro-engine --release
```

### Build Both
```bash
cargo build --release
```

## Usage

### Core Only (Open Source)
```bash
./target/release/Pynagent-core scan ./src

# List available rules
./target/release/Pynagent-core list-rules

# Check Pro Engine status
./target/release/Pynagent-core pro-status
```

### With Pro Engine
If `Pynagent-pro-engine` binary is installed, it will be automatically detected and used for advanced features.

## License

- **Pynagent-core**: AGPL-3.0-or-later
- **Pynagent-pro-engine**: PROPRIETARY (requires separate license)

## Directory Structure

```
Pynagent-workspace/
├── Cargo.toml              # Workspace configuration
├── Pynagent-core/            # Open source core
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs        # Library exports
│   │   ├── bin/main.rs    # CLI binary
│   │   ├── protocol.rs    # IPC protocol types
│   │   └── pro_engine.rs  # Pro Engine integration
│   └── ...
│
└── Pynagent-pro-engine/     # Proprietary engine
    ├── Cargo.toml
    ├── src/
    │   ├── main.rs        # Binary entry point
    │   ├── protocol.rs     # IPC protocol types
    │   ├── handlers.rs     # Request handlers
    │   ├── semantic.rs     # Semantic analysis
    │   ├── type_checker.rs # Type validation
    │   ├── ai_security.rs # AI bug detection
    │   ├── security_engine.rs # Extended security
    │   └── dependency.rs   # CVE/GHSA scanning
    └── ...
```
