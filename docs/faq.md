# Pynagent FAQ

Frequently Asked Questions about Pynagent.

## Installation

### Q: Python 3.12/3.13 is not supported?

Pynagent supports Python 3.10 and higher. If you encounter issues with newer Python versions, please report them on GitHub.

### Q: How do I install the Rust backend?

```bash
pip install Pynagent[rust]
```

For manual installation:
```bash
cd pynagent
cargo build --release
```

### Q: Installation fails with "Microsoft Visual C++" error

You need the Visual C++ Build Tools. Install from:
https://visualstudio.microsoft.com/visual-cpp-build-tools/

## Usage

### Q: How do I scan multiple files?

```bash
# Scan a directory
Pynagent check ./src

# Scan specific files
Pynagent check file1.py file2.py file3.py
```

### Q: How do I see what changes Pynagent will make?

```bash
Pynagent clean file.py --dry-run --diff
```

### Q: How do I apply fixes automatically?

```bash
# Creates a backup before modifying
Pynagent clean file.py --in-place --backup

# Or without backup
Pynagent clean file.py --in-place
```

### Q: Can I exclude certain files or directories?

Create a `Pynagent.yaml` config:

```yaml
exclude:
  - "**/test_*.py"
  - "**/venv/**"
  - "**/__pycache__/**"
```

### Q: How do I ignore specific rules?

```bash
# Ignore one rule
Pynagent clean file.py --ignore SecurityScannerRule

# Ignore multiple rules
Pynagent clean file.py --ignore "Rule1,Rule2,Rule3"
```

Or in code:
```python
from Pynagent.rules import exclude_rules

engine = RuleEngine(rules=exclude_rules(["SecurityScannerRule"]))
```

## Rules

### Q: What rules are available?

```bash
Pynagent rules
```

### Q: How do I create a custom rule?

See [writing-rules.md](writing-rules.md) for a complete guide.

Basic example:
```python
from Pynagent.rules.base import AIBugRule

class MyRule(AIBugRule):
    RULE_ID = "MYRULE-001"
    SEVERITY = "medium"

    def detect(self, node, context):
        # Your detection logic
        return []
```

### Q: What package level should I use?

| Package | When to Use |
|---------|-------------|
| `safe` (default) | Production code, want zero risk |
| `conservative` | Want additional cleanup, minor risk |
| `destructive` | Want aggressive refactoring, review changes |

### Q: Why are some issues not being detected?

- The issue may not match a known AI-generated pattern
- The rule might be disabled in your configuration
- The code pattern might be too complex for detection

## Security

### Q: Does Pynagent send my code anywhere?

No. Pynagent runs entirely locally on your machine. No code is sent to external servers.

### Q: How accurate is the security scanner?

Pynagent detects common security issues in AI-generated code. It should be used as a supplement to, not a replacement for, comprehensive security testing.

### Q: Can Pynagent fix security vulnerabilities automatically?

Some security issues can be auto-fixed:
- `yaml.load()` without SafeLoader
- Empty `except: pass`

Other issues are reported but require manual intervention.

## Performance

### Q: Pynagent is running slowly on large projects

- Use the Rust backend for better performance
- Run on specific files instead of entire directories
- Increase memory with `--max-memory` flag

### Q: How do I benchmark Pynagent?

```bash
# Python benchmark (compares Rust vs Python scanner)
cd pynagent
python benchmark.py --files 200 --iterations 5

# Rust criterion benchmarks
cargo bench --bench compare
```

For detailed benchmark results, see [pynagent/README.md](../pynagent/README.md).

### Q: Config file not being read

Pynagent looks for config in (in priority order):
1. `pyproject.toml` section `[tool.Pynagent]`
2. `./Pynagent.yaml`
3. `./Pynagent.yml`
4. `~/.Pynagent.yaml`

Make sure the file is in the correct location.

## Integrations

### Q: How do I use Pynagent with GitHub Actions?

See [github-actions-guide.md](github-actions-guide.md).

### Q: How do I use Pynagent with pre-commit?

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: Pynagent-check
        name: Pynagent Check
        entry: Pynagent check
        language: system
        types: [python]
```

### Q: Can I use Pynagent in my IDE?

- VSCode: Use the Pynagent extension
- PyCharm: Use the command line tool
- Cursor: Use with pre-commit or command line

## Export & Reports

### Q: How do I export to SARIF format?

```bash
Pynagent report ./src -f sarif -o results.sarif
```

Or via Python API:

```python
from Pynagent.core.manifest import export_to_sarif
sarif = export_to_sarif(markers, source_file=Path("app.py"))
```

### Q: How do I integrate with SonarQube?

```bash
Pynagent report ./src -f sonarqube -o sonar-report.json
```

Or via Python API:

```python
from Pynagent.core.manifest import export_to_sonarqube
issues = export_to_sonarqube(markers, source_file=Path("app.py"))
```

### Q: How do I create a HTML report?

```python
from Pynagent.core.manifest import export_to_html_report

html = export_to_html_report(markers, title="My Report")
with open("report.html", "w") as f:
    f.write(html)
```

## Troubleshooting

### Q: "command not found: Pynagent" after installation

```bash
# Check installation
pip show Pynagent

# Try running as module
python -m Pynagent check file.py

# Reinstall if needed
pip uninstall Pynagent
pip install Pynagent
```

### Q: Pynagent hangs or crashes

- Check available memory
- Try running on smaller files
- Report the issue with the file causing the crash

### Q: False positives on legitimate code

- Use `--package safe` for fewer aggressive rules
- Configure specific rules in `Pynagent.yaml`
- Use inline ignores: `# Pynagent: ignore-line`

## Contributing

### Q: How do I contribute to Pynagent?

See [CONTRIBUTING.md](../CONTRIBUTING.md).

### Q: How do I report a bug?

Open an issue on GitHub with:
- Pynagent version
- Python version
- Sample code that triggers the bug
- Expected vs actual behavior

### Q: How do I request a new feature?

Open a feature request on GitHub with:
- Description of the feature
- Use case
- Example code patterns to detect

## License

Pynagent is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**. See [LICENSE](LICENSE) for details.
