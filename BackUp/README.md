# ShipCheck

**ShipCheck asks one question: _is this repository ready to ship?_**

ShipCheck is a zero-runtime-dependency repository preflight tool for security, dependency, repository, and Python code-health analysis. It uses Python's standard library, including `ast`, `argparse`, `json`, `pathlib`, `tomllib`, and `subprocess`.

The project is designed for the **Zero Dependency 2026** hackathon: the production runtime contains no third-party Python packages.

## Why ShipCheck?

Repository health is usually fragmented across several tools. ShipCheck combines a focused subset of those checks into one deterministic CLI while keeping the runtime dependency-free.

It is deliberately **not** a complete vulnerability scanner, package manager, or replacement for established security tools.

## Requirements

- Python **3.11+**
- Git is optional; it is only required for `--diff`
- No `pip install` is required

Python 3.11+ is required because ShipCheck uses the standard-library `tomllib` module for TOML manifests.

## Quick start

From the repository root:

```bash
python3 shipcheck.py .
```

Show help:

```bash
python3 shipcheck.py --help
```

JSON:

```bash
python3 shipcheck.py . --format json
```

SARIF:

```bash
python3 shipcheck.py . --format sarif
```

Only medium-and-higher findings:

```bash
python3 shipcheck.py . --severity medium
```

Fail CI when a high-or-critical finding is present:

```bash
python3 shipcheck.py . --fail-on high
```

Show only the score and counts:

```bash
python3 shipcheck.py . --summary
```

Git changed-file analysis:

```bash
python3 shipcheck.py . --diff
```

## Example

```text
ShipCheck 0.4.0
Project: ./example

SHIP SCORE: 82/100
Verdict: NEEDS ATTENTION

Category Scores
---------------
Security:       70
Dependencies:   100
Code Health:    94
Repository:     100

Findings
--------
Total: 2
HIGH: 1
MEDIUM: 0
LOW: 1

[HIGH] SC001 (security) app.py:12
app.py:12 uses eval(), which executes dynamically supplied code.
Recommendation: Avoid dynamic code execution; use safer parsing or explicit dispatch.

[LOW] SC009 (code_health) app.py:20
app.py:20 uses a bare except clause.
Recommendation: Catch specific exception types instead of catching every exception.
```

The numbers above are illustrative; ShipCheck does not fabricate benchmark claims.

## Analysis

### Security

Current Python AST security rules include:

| ID | Rule | Severity |
|---|---|---|
| SC001 | `eval()` / `exec()` | HIGH |
| SC002 | `os.system()` | HIGH |
| SC003 | `subprocess(..., shell=True)` | HIGH |
| SC004 | unsafe `pickle` loading | HIGH |
| SC005 | `tempfile.mktemp()` | HIGH |
| SC006 | MD5 / SHA-1 | MEDIUM |
| SC007 | HTTP `verify=False` | HIGH |
| SC008 | likely hardcoded secrets | HIGH |

The rules intentionally use lightweight AST analysis. They do not execute analyzed source.

### Code health

- Bare exception handlers
- Python syntax errors
- Python source metrics
- Function/method counts
- Python LOC

### Repository

- Repository path validation
- README presence
- Binary-file accounting
- Excluded/generated directories

### Dependency analysis

Supported manifest formats:

- `requirements.txt`
- `package.json`
- `Cargo.toml`
- `pyproject.toml`

Where applicable, ShipCheck checks:

- dependency count
- exact-version pinning
- corresponding lockfiles
- malformed manifests

This is manifest inspection, not a complete package-resolution engine.

## Rule IDs

Every analyzer finding has a stable rule identifier.

Rule IDs are intended to remain stable as the implementation evolves. They are exposed in:

- text output
- JSON
- SARIF
- tests
- documentation

The catalog is defined in `shipcheck.py`.

## Ship Score

ShipCheck calculates a deterministic score from four category scores:

- Security
- Dependencies
- Code Health
- Repository

Each category starts at 100. Findings apply fixed severity penalties:

| Severity | Penalty |
|---|---:|
| LOW | 2 |
| MEDIUM | 6 |
| HIGH | 15 |
| CRITICAL | 25 |

A category cannot fall below zero. The overall score is the rounded average of the four category scores.

Verdicts:

- **READY TO SHIP** — score ≥ 90 and no HIGH/CRITICAL findings
- **NEEDS ATTENTION** — score ≥ 70
- **NOT READY** — score < 70

This score is intentionally simple and explainable. It should be treated as a preflight signal, not a security certification.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Scan completed and the configured threshold was not exceeded |
| 1 | A finding reached the configured threshold |
| 2 | Invalid invocation or repository path |
| 3 | Reserved for internal/scanner errors |

With no `--fail-on` argument, HIGH and CRITICAL findings return exit code 1 for CI-friendly behavior.

## JSON

JSON uses schema version `1`.

The top-level structure contains:

```json
{
  "version": "1",
  "metadata": {},
  "repository": {},
  "score": {},
  "summary": {},
  "metrics": {},
  "findings": []
}
```

Each finding contains:

```json
{
  "id": "SC001",
  "severity": "HIGH",
  "category": "security",
  "file": "app.py",
  "line": 12,
  "column": null,
  "message": "...",
  "recommendation": "..."
}
```

Consumers should use the schema version when integrating with ShipCheck.

## SARIF

ShipCheck can emit SARIF 2.1.0 without a SARIF library:

```bash
python3 shipcheck.py . --format sarif
```

The implementation intentionally covers the useful static-analysis subset rather than attempting to model every SARIF feature.

## Git diff mode

`--diff` uses the system Git executable through Python's standard-library `subprocess` module.

It is designed to answer:

> Which findings occur in changed files?

It gracefully handles repositories with no usable Git diff and does not attempt to implement Git itself.

## Architecture

The current implementation stays intentionally compact:

```text
CLI
 │
 ├── RepositoryAnalyzer
 ├── DependencyAnalyzer
 └── StaticAnalyzer
          │
          ▼
       Findings
          │
          ▼
       Scoring
          │
          ├── Text
          ├── JSON
          └── SARIF
```

The analyzer interface makes future language analyzers possible without requiring a framework.

## Zero-dependency design

Runtime functionality uses only the Python standard library.

Examples of stdlib primitives used by ShipCheck:

- `argparse` — CLI parsing
- `ast` — Python static analysis
- `json` — JSON/SARIF serialization
- `pathlib` — repository traversal
- `re` — lightweight matching
- `tomllib` — TOML parsing
- `subprocess` — optional Git integration
- `unittest` — test suite

See [`STDLIB.md`](STDLIB.md) for the project's dependency-replacement rationale.

Verify the source-level import boundary:

```bash
python3 verify_stdlib.py
```

## Testing

Run the full test suite:

```bash
python3 -m unittest discover -v
```

The tests cover:

- dependency manifests
- security rules
- safe/non-triggering cases
- syntax errors
- ignored files/directories
- metrics
- scoring
- JSON
- SARIF
- CLI behavior
- exit codes

The project also includes fixture-style tests created with temporary repositories, so the tests do not require third-party testing frameworks.

## Security considerations

ShipCheck analyzes source; it does not execute the analyzed Python code.

The analyzer should still be treated as a program processing untrusted input. Its file handling and subprocess usage are intentionally limited:

- Git is invoked with an argument list rather than a shell command string.
- Python source is parsed with `ast.parse`.
- Analyzed source is never imported or executed.
- Generated/common dependency directories are excluded from Python AST scanning.
- Binary files are identified before repository metrics count them.

No static analyzer can detect every vulnerability. A clean ShipCheck report is not a guarantee that a repository is secure.

## Limitations

ShipCheck intentionally has a narrow scope.

It does not currently provide:

- complete vulnerability detection
- complete language support
- dependency resolution against package registries
- semantic type analysis
- full interprocedural data-flow analysis
- complete Git history analysis
- a complete replacement for Bandit, Semgrep, dependency scanners, or package managers

The goal is useful, explainable preflight analysis with zero runtime dependencies.

## Hackathon track

Zero Dependency 2026 priorities:

- Functionality and usefulness
- Zero-dependency craft
- Code quality and idiom
- Innovation

Relevant bonus work:

- **STDLIB Log** — documented in `STDLIB.md`
- **Package Killer** — a narrowly defined subset of security-analysis functionality is implemented with Python AST instead of a security-analysis package
- **Reproducible Build** — considered only where a meaningful generated artifact exists
- **Single File** — architecture is kept compact rather than forcing a single-file implementation at the expense of maintainability

## License

No license file is currently included in the repository. Add the license required by the project owner or hackathon before public redistribution.
