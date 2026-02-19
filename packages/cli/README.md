# @usekova/cli

Command-line interface for the Kova covenant protocol. Provides commands for key generation, covenant creation, verification, evaluation, inspection, CCL parsing, shell completions, diagnostics, and diff.

## Installation

```bash
npm install @usekova/cli
```

## Commands

| Command | Description |
|---------|-------------|
| `kova init` | Generate an Ed25519 key pair and config file |
| `kova create` | Create and sign a covenant document |
| `kova verify <json>` | Verify a covenant document |
| `kova evaluate <json> <action> <resource>` | Evaluate an action against a covenant |
| `kova inspect <json>` | Pretty-print covenant details |
| `kova parse <ccl>` | Parse CCL and output AST as JSON |
| `kova completions <shell>` | Generate shell completion script (bash/zsh/fish) |
| `kova doctor` | Check Kova installation health |
| `kova diff <doc1> <doc2>` | Show differences between two covenant documents |
| `kova version` | Print version information |

## Key APIs

- **run(args, configDir?)**: Programmatic entry point -- runs a CLI command and returns `{ stdout, stderr, exitCode }`
- **loadConfig / saveConfig**: Read and write `kova.config.json`
- **bashCompletions / zshCompletions / fishCompletions**: Generate shell completion scripts
- **runDoctor**: Run diagnostic checks on the Kova installation

## Usage

```bash
# Generate a new key pair
kova init

# Create a covenant
kova create --issuer alice --beneficiary bob --constraints "permit read /data/**"

# Verify a covenant document
kova verify '{"id":"...","version":"1.0",...}'

# Evaluate an action
kova evaluate '{"id":"..."}' read /data/reports

# Parse CCL
kova parse "permit read /data/**"

# Check installation health
kova doctor
```

### Global Flags

- `--json` -- Machine-readable JSON output (no colors)
- `--no-color` -- Disable colored output
- `--config <path>` -- Path to config file

## Docs

See the [Kova SDK root documentation](../../README.md) for the full API reference.
