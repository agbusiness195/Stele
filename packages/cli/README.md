# @nobulex/cli

Command-line interface for the Nobulex covenant protocol. Provides commands for key generation, covenant creation, verification, evaluation, inspection, CCL parsing, shell completions, diagnostics, and diff.

## Installation

```bash
npm install @nobulex/cli
```

## Commands

| Command | Description |
|---------|-------------|
| `nobulex init` | Generate an Ed25519 key pair and config file |
| `nobulex create` | Create and sign a covenant document |
| `nobulex verify <json>` | Verify a covenant document |
| `nobulex evaluate <json> <action> <resource>` | Evaluate an action against a covenant |
| `nobulex inspect <json>` | Pretty-print covenant details |
| `nobulex parse <ccl>` | Parse CCL and output AST as JSON |
| `nobulex completions <shell>` | Generate shell completion script (bash/zsh/fish) |
| `nobulex doctor` | Check Nobulex installation health |
| `nobulex diff <doc1> <doc2>` | Show differences between two covenant documents |
| `nobulex version` | Print version information |

## Key APIs

- **run(args, configDir?)**: Programmatic entry point -- runs a CLI command and returns `{ stdout, stderr, exitCode }`
- **loadConfig / saveConfig**: Read and write `nobulex.config.json`
- **bashCompletions / zshCompletions / fishCompletions**: Generate shell completion scripts
- **runDoctor**: Run diagnostic checks on the Nobulex installation

## Usage

```bash
# Generate a new key pair
nobulex init

# Create a covenant
nobulex create --issuer alice --beneficiary bob --constraints "permit read /data/**"

# Verify a covenant document
nobulex verify '{"id":"...","version":"1.0",...}'

# Evaluate an action
nobulex evaluate '{"id":"..."}' read /data/reports

# Parse CCL
nobulex parse "permit read /data/**"

# Check installation health
nobulex doctor
```

### Global Flags

- `--json` -- Machine-readable JSON output (no colors)
- `--no-color` -- Disable colored output
- `--config <path>` -- Path to config file

## Docs

See the [Nobulex SDK root documentation](../../README.md) for the full API reference.
