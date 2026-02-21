# @grith/cli

Command-line interface for the Grith covenant protocol. Provides commands for key generation, covenant creation, verification, evaluation, inspection, CCL parsing, shell completions, diagnostics, and diff.

## Installation

```bash
npm install @grith/cli
```

## Commands

| Command | Description |
|---------|-------------|
| `grith init` | Generate an Ed25519 key pair and config file |
| `grith create` | Create and sign a covenant document |
| `grith verify <json>` | Verify a covenant document |
| `grith evaluate <json> <action> <resource>` | Evaluate an action against a covenant |
| `grith inspect <json>` | Pretty-print covenant details |
| `grith parse <ccl>` | Parse CCL and output AST as JSON |
| `grith completions <shell>` | Generate shell completion script (bash/zsh/fish) |
| `grith doctor` | Check Grith installation health |
| `grith diff <doc1> <doc2>` | Show differences between two covenant documents |
| `grith version` | Print version information |

## Key APIs

- **run(args, configDir?)**: Programmatic entry point -- runs a CLI command and returns `{ stdout, stderr, exitCode }`
- **loadConfig / saveConfig**: Read and write `grith.config.json`
- **bashCompletions / zshCompletions / fishCompletions**: Generate shell completion scripts
- **runDoctor**: Run diagnostic checks on the Grith installation

## Usage

```bash
# Generate a new key pair
grith init

# Create a covenant
grith create --issuer alice --beneficiary bob --constraints "permit read /data/**"

# Verify a covenant document
grith verify '{"id":"...","version":"1.0",...}'

# Evaluate an action
grith evaluate '{"id":"..."}' read /data/reports

# Parse CCL
grith parse "permit read /data/**"

# Check installation health
grith doctor
```

### Global Flags

- `--json` -- Machine-readable JSON output (no colors)
- `--no-color` -- Disable colored output
- `--config <path>` -- Path to config file

## Docs

See the [Grith SDK root documentation](../../README.md) for the full API reference.
