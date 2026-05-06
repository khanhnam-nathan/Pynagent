# Architecture

This document describes the architecture of Pynagent.

## Overview

Pynagent is an AI-Generated Code Scanner that detects and fixes common issues in AI-generated code. The architecture is designed to be modular, extensible, and performant.

## System Components

```mermaid
graph TB
    subgraph "User Interface"
        CLI[CLI - cli.py]
        API[Python API]
        LSP[LSP Server]
    end

    subgraph "Core Engine"
        Engine[RuleEngine]
        Cache[IncrementalCache]
        SemanticGuard[SemanticDiffGuard]
        TypeShield[TypeAwareShield]
    end

    subgraph "Rust Backend pynagent"
        RustCLI[Rust CLI - main.rs]
        PyO3[PyO3 Bindings]
        LN_AST[LN-AST Normalizer]
        RustRules[Rust Rule Engine]
        Rayon[Rayon Parallelism]
        tree_sitter[tree-sitter Parsers]
    end

    subgraph "Rules"
        subgraph "Safe (always on)"
            IsNotNone[IsNotNoneRule]
            RangeLen[RangeLenRule]
            Security[SecurityScannerRule]
            Typing[TypingRule]
        end

        subgraph "Conservative (opt-in)"
            Unused[UnusedImportRule]
            FString[FStringRule]
            Magic[MagicNumberRule]
        end

        subgraph "Destructive (opt-in)"
            ImportCleaning[ImportCleaningRule]
            Naming[NamingConventionRule]
            DeadCode[DeadCodeRule]
        end

        subgraph "AI Security"
            PromptInject[Prompt Injection]
            ContextConfusion[Context Confusion]
            ToolCollision[Tool Call Collision]
        end
    end

    subgraph "Parsers"
        LibCST[LibCST - Python]
        tree_sitter_py[tree-sitter - Python]
        tree_sitter_js[tree-sitter - JS/TS/Go/Java/Rust/C#/PHP/Ruby]
    end

    CLI --> Engine
    API --> Engine
    Engine --> Cache
    Engine --> SemanticGuard
    Engine --> IsNotNone
    Engine --> Security
    Engine --> Typing
    Security --> LibCST
    Security --> RustRules
    LSP --> RustRules
    RustCLI --> PyO3
    PyO3 --> LN_AST
    LN_AST --> RustRules
    RustRules --> Rayon
    RustRules --> tree_sitter
    tree_sitter_py --> LN_AST
    tree_sitter_js --> LN_AST
```

## Component Descriptions

### CLI (`Pynagent/cli.py`)

The command-line interface provides user-facing commands:

- `Pynagent clean <file>` - Clean a single file
- `Pynagent check <target>` - Security scan
- `Pynagent explain <rule_id>` - Explain a rule
- `Pynagent report <target>` - Generate report
- `Pynagent lsp` - Start LSP server

### RuleEngine (`Pynagent/core/engine.py`)

The core orchestration engine:

1. Parses source code using LibCST or tree-sitter (via Rust)
2. Runs rules in priority order (safe -> conservative -> destructive)
3. Validates output (AST compile check)
4. Detects conflicts between rules
5. Applies semantic guards and type shields

### Rules (`Pynagent/rules/`)

Each rule is a standalone class that:

1. Inherits from `Rule` base class
2. Implements `apply(CodeFile) -> TransformationResult`
3. Can read/write AST/CST nodes
4. Returns changes and security findings

### Rust Backend (`pynagent/`)

High-performance scanner written in Rust:

- **tree-sitter** for AST parsing across 9 languages
- **Rayon** for parallel rule evaluation
- **PyO3** for seamless Python bindings
- **LN-AST** normalizer for language-neutral code representation
- See [pynagent/README.md](../pynagent/README.md) for full details

## Data Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Engine
    participant Rust
    participant Rule
    participant LibCST

    User->>CLI: Pynagent clean file.py
    CLI->>Engine: process_file(file)

    alt Python Path
        Engine->>Engine: Parse AST/CST (LibCST)
        Engine->>Engine: Check incremental cache
        Engine->>Rule: apply(code_file)
        Rule->>LibCST: Transform CST
        LibCST-->>Rule: Transformed CST
    else Rust Path
        Engine->>Rust: scan_security(code)
        Rust->>Rust: Parse LN-AST (tree-sitter)
        Rust->>Rust: Run rules in parallel (Rayon)
        Rust-->>Engine: findings
    end

    Rule-->>Engine: TransformationResult
    Engine->>Engine: Validate AST
    Engine->>Engine: Semantic Guard Check
    Engine->>Engine: Type Shield Check
    Engine-->>CLI: Result
    CLI-->>User: Output
```

## Configuration System

```mermaid
graph LR
    Config[Config Files<br/>pyproject.toml<br/>Pynagent.yaml]
    Env[Environment Variables]
    CLI[CLI Arguments]
    Pyproject[tool.Pynagent<br/>section]

    Config --> Loader[ConfigLoader]
    Env --> Loader
    CLI --> Loader
    Pyproject --> Loader
    Loader --> Engine
```

## Extension Points

### Custom Rules

Create a custom rule by subclassing `Rule`:

```python
from Pynagent.rules.base import Rule
from Pynagent.core.types import CodeFile, TransformationResult, RuleConfig

class MyCustomRule(Rule):
    """Description of what this rule does."""

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)

    @property
    def description(self) -> str:
        return "One-line description of the rule"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        content = code_file.content
        transformed = self._transform(content)
        return self._create_result(code_file, transformed, ["Change description"])

    def _transform(self, content: str) -> str:
        # Transformation logic
        return content
```

### Plugins

Load plugins via entry points:

```toml
# pyproject.toml
[project.entry-points."Pynagent.plugins"]
my-plugin = "my_package:MyPlugin"
```

### Rule Registry

Register rules with package and priority:

```python
from Pynagent.rules.registry import RuleRegistry, register_rule

@RuleRegistry.register(package="safe", priority=10)
class MyRule(Rule):
    ...
```

## Performance Optimizations

1. **Incremental Cache**: AST/CST trees cached across RuleEngine instances
2. **Rule Priority**: Safe rules run first, destructive rules last
3. **Conflict Detection**: Skip conflicting rules automatically
4. **Semantic Guards**: Validate AST before/after transformations
5. **Rust Backend**: Parallel tree-sitter parsing and rule evaluation with Rayon
6. **LN-AST**: Language-neutral AST enables universal rule application

## Security Architecture

Security findings include:

- CWE/OWASP mapping
- CVSS scoring
- Fix guidance
- Auto-fix availability

```python
@dataclass(frozen=True)
class SecurityFinding:
    rule_id: str
    severity: str
    cwe_id: Optional[str]
    owasp_id: Optional[str]
    cvss_score: float
    auto_fix_available: bool
```
