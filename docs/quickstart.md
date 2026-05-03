# PyNeat Quick Start Guide

Get up and running with PyNeat in 5 minutes!

## Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

## Installation

### From PyPI (Recommended)

```bash
pip install pyneat
```

### From Source

```bash
git clone https://github.com/khanhnam-nathan/Pyneat.git
cd Pyneat
pip install -e .
```

### With Rust Backend

For better performance on large codebases:

```bash
pip install pyneat[rust]
# Or install from source
cd pyneat-rs
cargo build --release
```

## Quick Examples

### 1. Scan a File for Issues

```bash
pyneat check your_file.py
```

### 2. Clean AI-Generated Code

```bash
# Dry run (preview changes)
pyneat clean your_file.py --dry-run --diff

# Apply fixes in-place
pyneat clean your_file.py --in-place
```

### 3. Security Scan

```bash
pyneat check your_file.py --severity
```

### 4. Multi-Language Support

```bash
# Scan entire directory
pyneat check ./src

# Specify language
pyneat clean script.py --lang python
```

### 5. Use with Pre-commit Hooks

```bash
pip install pre-commit
pre-commit install

# Add to .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pyneat-security
        name: PyNeat Security Scan
        entry: pyneat check
        language: system
        types: [python]
        stages: [pre-commit]
```

## Python API Usage

### Basic Scanning

```python
from pyneat import clean_code, analyze_code

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
from pyneat import RuleEngine, CodeFile, RuleConfig
from pyneat.rules import IsNotNoneRule, DebugCleaner

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
from pyneat import RuleEngine, CodeFile, RuleConfig
from pyneat.rules import SecurityScannerRule

engine = RuleEngine(rules=[SecurityScannerRule(RuleConfig(enabled=True))])
result = engine.process_code_file(CodeFile(path=Path("app.py"), content=code))
for finding in result.changes_made:
    print(f"Security: {finding}")
```

### Auto-fixing a File

```python
from pathlib import Path
from pyneat import clean_file

result = clean_file(Path("my_script.py"), in_place=True, backup=True)
if result.success:
    print(f"Made {len(result.changes_made)} changes")
```

### Export Reports

```python
from pathlib import Path
from pyneat.core.manifest import (
    export_to_sarif,
    export_to_junit_xml,
    export_to_gitlab_sast,
    export_to_html_report,
)
from pyneat import RuleEngine, CodeFile, RuleConfig
from pyneat.rules import SecurityScannerRule

# Analyze and collect markers
engine = RuleEngine(rules=[SecurityScannerRule(RuleConfig(enabled=True))])
result = engine.process_code_file(CodeFile(path=Path("app.py"), content=code))

# SARIF for GitHub Code Scanning
sarif = export_to_sarif(result.agent_markers, Path("app.py"))

# JUnit XML for CI/CD
junit = export_to_junit_xml(result.agent_markers, Path("app.py"))

# HTML report
html = export_to_html_report(result.agent_markers, title="PyNEAT Scan")
```

## Configuration

### Package Levels

PyNeat has three package levels for different safety needs:

| Package | Use Case | Command |
|---------|----------|---------|
| `safe` (default) | Zero-risk fixes | `pyneat clean file.py` |
| `conservative` | Cleaner code | `pyneat clean file.py --package conservative` |
| `destructive` | Full cleanup | `pyneat clean file.py --package destructive` |

### Rule Configuration

```yaml
# pyneat.yaml
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
pyneat clean file.py --ignore SecurityScannerRule

# Ignore specific lines
# pyneat: ignore-line
x != None  # pyneat: ignore-line
```

## Common Workflows

### CI/CD Integration

```yaml
# GitHub Actions
- name: PyNeat Security Scan
  run: |
    pip install pyneat
    pyneat report . -f sarif -o results.sarif
```

### Git Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
pyneat check $(git diff --cached --name-only --diff-filter=ACM) || exit 1
```

### IDE Integration

VSCode: Install the PyNeat extension from the Marketplace.

## Troubleshooting

### Installation Issues

**Problem:** `pyneat: command not found`

```bash
# Solution: Reinstall
pip uninstall pyneat
pip install pyneat

# Or use python -m
python -m pyneat check file.py
```

**Problem:** Rust backend not working

```bash
# Check Rust installation
rustc --version

# Rebuild
cd pyneat-rs
cargo build --release
```

### Scan Issues

**Problem:** No issues found

- Check if the file contains AI-generated patterns
- Try with `--verbose` flag
- Verify language is correctly detected

**Problem:** Too many false positives

- Use `--package safe` for fewer aggressive rules
- Configure specific rules in `pyneat.yaml`
- Use `--ignore` for specific rules

## Next Steps

- Read the full [README.md](../README.md)
- Check out [docs/architecture.md](architecture.md) for technical details
- Check out [docs/writing-rules.md](writing-rules.md) to create custom rules

## Getting Help

- GitHub Issues: Report bugs and request features
- Documentation: Check the [docs/](../docs/) folder
