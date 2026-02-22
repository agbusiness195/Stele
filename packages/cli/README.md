# @kervyx/cli

Command-line interface for the Kervyx covenant protocol. Provides commands for key generation, covenant creation, verification, evaluation, inspection, CCL parsing, shell completions, diagnostics, and diff.

## Installation

```bash
npm install @kervyx/cli
```

## Commands

| Command | Description |
|---------|-------------|
| `kervyx init` | Generate an Ed25519 key pair and config file |
| `kervyx create` | Create and sign a covenant document |
| `kervyx verify <json>` | Verify a covenant document |
| `kervyx evaluate <json> <action> <resource>` | Evaluate an action against a covenant |
| `kervyx inspect <json>` | Pretty-print covenant details |
| `kervyx parse <ccl>` | Parse CCL and output AST as JSON |
| `kervyx completions <shell>` | Generate shell completion script (bash/zsh/fish) |
| `kervyx doctor` | Check Kervyx installation health |
| `kervyx diff <doc1> <doc2>` | Show differences between two covenant documents |
| `kervyx version` | Print version information |

## Key APIs

- **run(args, configDir?)**: Programmatic entry point -- runs a CLI command and returns `{ stdout, stderr, exitCode }`
- **loadConfig / saveConfig**: Read and write `kervyx.config.json`
- **bashCompletions / zshCompletions / fishCompletions**: Generate shell completion scripts
- **runDoctor**: Run diagnostic checks on the Kervyx installation

## Usage

```bash
# Generate a new key pair
kervyx init

# Create a covenant
kervyx create --issuer alice --beneficiary bob --constraints "permit read /data/**"

# Verify a covenant document
kervyx verify '{"id":"...","version":"1.0",...}'

# Evaluate an action
kervyx evaluate '{"id":"..."}' read /data/reports

# Parse CCL
kervyx parse "permit read /data/**"

# Check installation health
kervyx doctor
```

### Global Flags

- `--json` -- Machine-readable JSON output (no colors)
- `--no-color` -- Disable colored output
- `--config <path>` -- Path to config file

## Docs

See the [Kervyx SDK root documentation](../../README.md) for the full API reference.
