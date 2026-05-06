# Pynagent VS Code Extension

Real-time AI-powered security scanner for VS Code using the Pynagent Language Server Protocol (LSP) server.

## Features

- **Real-time diagnostics** - Security issues appear as you code with squiggly underlines
- **Multi-language support** - Python, JavaScript, TypeScript, Go, Java, Rust, Ruby, PHP, C#
- **200+ security rules** - OWASP Top 10, prompt injection, AI-specific risks, secrets, etc.
- **Hover tooltips** - Get rule explanations on hover
- **Quick-fix actions** - Add ignore comments directly from the editor
- **Debounced scanning** - Configurable delay to avoid performance impact
- **Severity filtering** - Focus on what matters (critical, high, medium, low, info)
- **Scan on save / scan on type** - Choose your preferred scanning mode

## Installation

### Prerequisites

**You must have `Pynagent.exe` installed.** The extension requires the Rust binary from `pynagent`.

#### Install pynagent (once)

```bash
# Build from source
git clone https://github.com/khanhnam-nathan/Pynagent.git
cd Pynagent/pynagent
cargo build --release

# Add to PATH (Windows)
copy target\release\Pynagent.exe %USERPROFILE%\.cargo\bin\Pynagent.exe

# Verify
Pynagent --version
# pynagent 3.1.0
```

### Install Extension

#### Option 1: From VSIX file (recommended for testing)

1. Open VS Code
2. Press `Ctrl+Shift+P` → type **"Extensions: Install from VSIX"**
3. Browse to `Pynagent-vscode-1.0.1.vsix`
4. Click **Install**

#### Option 2: From Terminal

```bash
code --install-extension Pynagent-vscode-1.0.1.vsix
```

#### Option 3: Development Mode

```bash
cd .vscode-extension
npm install
code .
# Press F5 to launch extension in debug mode
```

## Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `Pynagent.binaryPath` | `string` | `""` | Path to Pynagent binary (leave empty to auto-detect) |
| `Pynagent.debounceMs` | `number` | `500` | Delay in ms before scanning after keystroke |
| `Pynagent.severityThreshold` | `string` | `"medium"` | Minimum severity to show (critical/high/medium/low/info) |
| `Pynagent.scanOnSave` | `boolean` | `true` | Scan automatically when file is saved |
| `Pynagent.scanOnType` | `boolean` | `true` | Scan as you type (real-time) |
| `Pynagent.enabledRules` | `array` | `[]` | Specific rule IDs to enable (empty = all rules) |

Example in `.vscode/settings.json`:

```json
{
  "Pynagent.debounceMs": 500,
  "Pynagent.severityThreshold": "medium",
  "Pynagent.scanOnSave": true,
  "Pynagent.scanOnType": true
}
```

## Commands

| Command | Description |
|---------|-------------|
| `Pynagent: Scan Active File` | Run a scan on the currently open file |
| `Pynagent: Explain Rule` | Show detailed explanation for a security rule |
| `Pynagent: Disable Rule for Line` | Add an ignore comment at the cursor |
| `Pynagent: Open Settings` | Open Pynagent extension settings |

Right-click context menu also provides "Explain Rule" and "Disable Rule" options.

## Troubleshooting

### "Pynagent binary not found in PATH"

1. Make sure `Pynagent.exe` is installed (see Prerequisites above)
2. Verify it works in terminal:

```bash
Pynagent --version
# Should output: pynagent 3.1.0

Pynagent lsp --help
# Should show LSP options
```

3. If not in PATH, set the full path in settings:

```json
{
  "Pynagent.binaryPath": "D:\\Pynagent-final\\pynagent\\target\\release\\Pynagent.exe"
}
```

### "Server crashed 5 times"

- Check the **Output** panel (`View` → `Output` → select **Pynagent** channel)
- Verify `Pynagent.exe` supports the `lsp` subcommand: `Pynagent.exe lsp --help`
- Make sure the binary is executable and in your PATH

### Extension not activating

- Press `Ctrl+Shift+P` → type "Developer: Reload Window"
- Check **Extensions** panel for any error messages
- Open the **Pynagent** output channel for logs

## Requirements

- VS Code 1.75.0 or higher
- `Pynagent.exe` (Rust binary from `pynagent`) installed and in PATH

## Extension Architecture

```
.vscode-extension/
  src/
    extension.ts      # Main extension entry point (LanguageClient setup)
  out/
    extension.js      # Compiled JavaScript
  package.json        # Extension manifest
  tsconfig.json       # TypeScript configuration
```

The extension spawns `Pynagent lsp` as a subprocess and communicates via the Language Server Protocol over stdio. The LSP server handles all security scanning and reports findings as diagnostics back to VS Code.

## Publishing

### VS Code Marketplace (requires publisher account)

```bash
cd .vscode-extension
npx vsce publish
```

Requires a Personal Access Token (PAT) from https://dev.azure.com.

### Open VSX Registry (free)

```bash
npx ovsx publish Pynagent-vscode-1.0.1.vsix
```

---

**Support**: https://github.com/khanhnam-nathan/Pynagent
