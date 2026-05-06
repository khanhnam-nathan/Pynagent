# Pynagent Quick Start Guide

Get up and running with Pynagent in 5 minutes!

## Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

## Installation

### From PyPI (Recommended)

```bash
pip install Pynagent
```

### From Source

```bash
git clone https://github.com/khanhnam-nathan/Pynagent.git
cd Pynagent
pip install -e .
```

### With Rust Backend

For better performance on large codebases:

```bash
pip install Pynagent[rust]
# Or install from source
cd pynagent
cargo build --release
```

## Quick Examples

### 1. Scan a File for Issues

```bash
Pynagent check your_file.py
```

### 2. Clean AI-Generated Code

```bash
# Dry run (preview changes)
Pynagent clean your_file.py --dry-run --diff

# Apply fixes in-place
Pynagent clean your_file.py --in-place
```

### 3. Security Scan

```bash
Pynagent check your_file.py --severity
```

### 4. Multi-Language Support

```bash
# Scan entire directory
Pynagent check ./src

# Specify language
Pynagent clean script.py --lang python
```

### 5. Use with Pre-commit Hooks

```bash
pip install pre-commit
pre-commit install

# Add to .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: Pynagent-security
        name: Pynagent Security Scan
        entry: Pynagent check
        language: system
        types: [python]
        stages: [pre-commit]
```

## Python API Usage

### Basic Scanning

```python
from Pynagent import clean_code, analyze_code

# Clean code string (auto-fix x != None -> x is not None)
result = clean_code("x != None")
print(result)  # "x is not None"

# Analyze without fixing (returns report)
report = analyze_code("x == None; print('debug')")
for issue in report['issues']:
    print(f"  - {issue}")
```

### Using the RuleEngine Directly

```python
from pathlib import Path
from Pynagent import RuleEngine, CodeFile, RuleConfig
from Pynagent.rules import IsNotNoneRule, DebugCleaner

engine = RuleEngine(rules=[
    IsNotNoneRule(RuleConfig(enabled=True)),
    DebugCleaner(mode="safe"),
])

source = "x = None\nprint('debug')"
code_file = CodeFile(path=Path("demo.py"), content=source)
result = engine.process_code_file(code_file)

print(result.transformed_content)
print(f"Changes: {result.changes_made}")
```

### Security Scanning

```python
from Pynagent import RuleEngine, CodeFile, RuleConfig
from Pynagent.rules import SecurityScannerRule

engine = RuleEngine(rules=[SecurityScannerRule(RuleConfig(enabled=True))])
result = engine.process_code_file(CodeFile(path=Path("app.py"), content=code))
for finding in result.changes_made:
    print(f"Security: {finding}")
```

### Auto-fixing a File

```python
from pathlib import Path
from Pynagent import clean_file

result = clean_file(Path("my_script.py"), in_place=True, backup=True)
if result.success:
    print(f"Made {len(result.changes_made)} changes")
```

### Export Reports

```python
from pathlib import Path
from Pynagent.core.manifest import (
    export_to_sarif,
    export_to_junit_xml,
    export_to_gitlab_sast,
    export_to_html_report,
)
from Pynagent import RuleEngine, CodeFile, RuleConfig
from Pynagent.rules import SecurityScannerRule

# Analyze and collect markers
engine = RuleEngine(rules=[SecurityScannerRule(RuleConfig(enabled=True))])
result = engine.process_code_file(CodeFile(path=Path("app.py"), content=code))

# SARIF for GitHub Code Scanning
sarif = export_to_sarif(result.agent_markers, Path("app.py"))

# JUnit XML for CI/CD
junit = export_to_junit_xml(result.agent_markers, Path("app.py"))

# HTML report
html = export_to_html_report(result.agent_markers, title="Pynagent Scan")
```

## Configuration

### Package Levels

Pynagent has three package levels for different safety needs:

| Package | Use Case | Command |
|---------|----------|---------|
| `safe` (default) | Zero-risk fixes | `Pynagent clean file.py` |
| `conservative` | Cleaner code | `Pynagent clean file.py --package conservative` |
| `destructive` | Full cleanup | `Pynagent clean file.py --package destructive` |

### Rule Configuration

```yaml
# Pynagent.yaml
rules:
  enabled:
    - IsNotNoneRule
    - SecurityScannerRule
  disabled:
    - PrintDebugRule
```

### Ignore Specific Issues

```bash
# Ignore a specific rule
Pynagent clean file.py --ignore SecurityScannerRule

# Ignore specific lines
# Pynagent: ignore-line
x != None  # Pynagent: ignore-line
```

## Common Workflows

### CI/CD Integration

```yaml
# GitHub Actions
- name: Pynagent Security Scan
  run: |
    pip install Pynagent
    Pynagent report . -f sarif -o results.sarif
```

### Git Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
Pynagent check $(git diff --cached --name-only --diff-filter=ACM) || exit 1
```

### IDE Integration

VSCode: Install the Pynagent extension from the Marketplace.

## Troubleshooting

### Installation Issues

**Problem:** `Pynagent: command not found`

```bash
# Solution: Reinstall
pip uninstall Pynagent
pip install Pynagent

# Or use python -m
python -m Pynagent check file.py
```

**Problem:** Rust backend not working

```bash
# Check Rust installation
rustc --version

# Rebuild
cd pynagent
cargo build --release
```

### Scan Issues

**Problem:** No issues found

- Check if the file contains AI-generated patterns
- Try with `--verbose` flag
- Verify language is correctly detected

**Problem:** Too many false positives

- Use `--package safe` for fewer aggressive rules
- Configure specific rules in `Pynagent.yaml`
- Use `--ignore` for specific rules

## Next Steps

- Read the full [README.md](../README.md)
- Check out [docs/architecture.md](architecture.md) for technical details
- Check out [docs/writing-rules.md](writing-rules.md) to create custom rules

## Getting Help

- GitHub Issues: Report bugs and request features
- Documentation: Check the [docs/](../docs/) folder
