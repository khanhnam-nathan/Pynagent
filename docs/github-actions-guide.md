# GitHub Actions Integration Guide

Guide for integrating Pynagent with GitHub Actions for CI/CD workflows.

## Basic Security Scan

```yaml
name: Pynagent Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Pynagent
        run: pip install Pynagent

      - name: Run security scan
        run: Pynagent check . -f sarif -o results.sarif

      - name: Upload results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## SARIF Integration with Code Scanning

GitHub's Code Scanning integrates with Pynagent through SARIF format.

### Full Example

```yaml
name: Pynagent Security

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  Pynagent-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Pynagent
        run: |
          pip install Pynagent

      - name: Run Pynagent scan
        run: |
          Pynagent check . \
            -f sarif \
            -o Pynagent-results.sarif \
            --fail-on critical

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: Pynagent-results.sarif
          category: Pynagent/security-scan

      - name: Fail on critical issues
        if: failure()
        run: |
          echo "Critical security issues found!"
          exit 1
```

## Code Quality Check

```yaml
name: Code Quality

on: [pull_request]

jobs:
  quality-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Pynagent
        run: pip install Pynagent

      - name: Check code quality
        run: Pynagent clean . --check --diff

      - name: Show changes
        if: always()
        run: Pynagent clean . --dry-run --diff || true
```

## Pre-commit Style Checks

```yaml
name: Pre-commit

on:
  pull_request:
  push:
    branches: [main]

jobs:
  pre-commit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install pre-commit
        run: pip install pre-commit

      - name: Install Pynagent hooks
        run: pre-commit install-hooks

      - name: Run pre-commit
        run: pre-commit run --all-files
```

## Scheduled Security Scans

Run security scans on a schedule (weekly):

```yaml
name: Weekly Security Scan

on:
  schedule:
    # Every Sunday at midnight
    - cron: '0 0 * * 0'
  workflow_dispatch:  # Manual trigger

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      issues: write

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Pynagent
        run: pip install Pynagent

      - name: Run scan
        run: Pynagent check . -f sarif -o scan.sarif

      - name: Upload results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scan.sarif
          category: Pynagent-weekly-scan

      - name: Create issue for critical issues
        if: contains(steps.scan.outputs.critical_issues, 'true')
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.create({
              title: 'Weekly Scan: Critical Issues Found',
              body: 'Automated scan found critical issues.',
              labels: ['security']
            })
```

## Multi-Language Scan

Scan multiple language repositories:

```yaml
name: Multi-language Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        language: [python, javascript, typescript, go, java]

    steps:
      - uses: actions/checkout@v4

      - name: Set up language
        uses: actions/setup-python@v5  # or setup-java, etc.
        with:
          python-version: '3.12'

      - name: Install Pynagent
        run: pip install Pynagent

      - name: Scan ${{ matrix.language }}
        run: |
          Pynagent check . \
            --lang ${{ matrix.language }} \
            -f sarif \
            -o results-${{ matrix.language }}.sarif

      - name: Upload ${{ matrix.language }} results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results-${{ matrix.language }}.sarif
          category: Pynagent/${{ matrix.language }}
```

## Performance Benchmarks

Track performance over time:

```yaml
name: Performance Benchmark

on:
  push:
    branches: [main]
  pull_request:

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Pynagent
        run: pip install -e .

      - name: Run benchmarks
        run: |
          cd pynagent
          python benchmark.py --files 200 --iterations 5

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: benchmark-results.json
```

## Matrix Build with Multiple Python Versions

```yaml
name: Test Multiple Python Versions

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.10', '3.11', '3.12', '3.13']

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install Pynagent
        run: pip install -e .

      - name: Run tests
        run: pytest

      - name: Run Pynagent scan
        run: Pynagent clean . --check
```

## GitLab SAST Export

For GitLab CI integration, use the SARIF format which GitLab SAST natively supports:

```yaml
# .gitlab-ci.yml
Pynagent-sast:
  image: python:3.12
  before_script:
    - pip install Pynagent
  script:
    - Pynagent report . -f sarif -o gl-sast-report.sarif
  artifacts:
    reports:
      sast: gl-sast-report.sarif
```

Alternatively, export directly via Python API for full control:

```python
from Pynagent.core.manifest import export_to_gitlab_sast

gitlab = export_to_gitlab_sast(markers, project="my-project")
```

## SonarQube Integration

```yaml
name: SonarQube Scan

on: [push, pull_request]

jobs:
  sonar:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          pip install Pynagent
          pip install sonar-scanner

      - name: Run Pynagent scan
        run: Pynagent check . --format sonarqube --output sonarqube-results.json

      - name: SonarQube analysis
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        run: |
          sonar-scanner \
            -Dsonar.projectKey=Pynagent-scan \
            -Dsonar.python.sources=. \
            -Dsonar.externalIssuesReportPaths=sonarqube-results.json
```

## Best Practices

1. **Always use `--fail-on critical`** for security scans in production
2. **Upload SARIF results** to GitHub Security tab for visibility
3. **Run scheduled scans** weekly to catch new vulnerabilities
4. **Use caching** for dependencies to speed up workflows
5. **Set appropriate permissions** (minimum required)
6. **Handle failures gracefully** with `if: always()` where appropriate
7. **Use matrix builds** to test across Python versions and languages

## Environment Variables

| Variable | Description |
|----------|-------------|
| `Pynagent_PACKAGE` | Package level (safe/conservative/destructive) |
| `Pynagent_LANG` | Default language to scan |
| `Pynagent_CONFIG` | Path to config file |

## Secrets

| Secret | Description |
|--------|-------------|
| `SONAR_TOKEN` | SonarQube authentication token |
| `PYPI_TOKEN` | PyPI API token for publishing |
