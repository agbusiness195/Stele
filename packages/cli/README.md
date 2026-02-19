# @usekova/cli

Command-line interface for the Stele covenant protocol. Provides commands for key generation, covenant creation, verification, evaluation, inspection, CCL parsing, shell completions, diagnostics, and diff.

## Installation

```bash
npm install @usekova/cli
```

## Commands

| Command | Description |
|---------|-------------|
| `stele init` | Generate an Ed25519 key pair and config file |
| `stele create` | Create and sign a covenant document |
| `stele verify <json>` | Verify a covenant document |
| `stele evaluate <json> <action> <resource>` | Evaluate an action against a covenant |
| `stele inspect <json>` | Pretty-print covenant details |
| `stele parse <ccl>` | Parse CCL and output AST as JSON |
| `stele completions <shell>` | Generate shell completion script (bash/zsh/fish) |
| `stele doctor` | Check Stele installation health |
| `stele diff <doc1> <doc2>` | Show differences between two covenant documents |
| `stele version` | Print version information |

## Key APIs

- **run(args, configDir?)**: Programmatic entry point -- runs a CLI command and returns `{ stdout, stderr, exitCode }`
- **loadConfig / saveConfig**: Read and write `stele.config.json`
- **bashCompletions / zshCompletions / fishCompletions**: Generate shell completion scripts
- **runDoctor**: Run diagnostic checks on the Stele installation

## Usage

```bash
# Generate a new key pair
stele init

# Create a covenant
stele create --issuer alice --beneficiary bob --constraints "permit read /data/**"

# Verify a covenant document
stele verify '{"id":"...","version":"1.0",...}'

# Evaluate an action
stele evaluate '{"id":"..."}' read /data/reports

# Parse CCL
stele parse "permit read /data/**"

# Check installation health
stele doctor
```

### Global Flags

- `--json` -- Machine-readable JSON output (no colors)
- `--no-color` -- Disable colored output
- `--config <path>` -- Path to config file

## Docs

See the [Stele SDK root documentation](../../README.md) for the full API reference.
