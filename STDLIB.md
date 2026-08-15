# ShipCheck Standard-Library Log

Zero Dependency 2026 requires the runtime to contain no third-party packages. This document records the engineering choices that make that possible.

The comparisons below are intentionally scoped. ShipCheck does **not** claim to reproduce entire third-party projects.

## 1. Click / Typer → argparse

**Used for:** command-line parsing.

**Why:** `argparse` is included with Python and provides positional arguments, options, choices, help text, and version handling.

**ShipCheck scope:** CLI argument parsing.

---

## 2. Rich → ANSI terminal output / plain text

**Used for:** human-readable CLI reports.

**Why:** ShipCheck does not require a terminal-rendering framework. Plain text is deterministic and portable; if future presentation needs ANSI styling, escape sequences can be emitted directly.

**ShipCheck scope:** structured text reporting.

---

## 3. Requests → urllib / standard networking APIs

**Used for:** HTTP functionality when a future feature genuinely needs it.

**Why:** Python provides HTTP primitives in the standard library.

**ShipCheck scope:** no external HTTP dependency is currently required.

---

## 4. Pytest → unittest

**Used for:** automated tests.

**Why:** `unittest` is part of Python and supports test discovery, assertions, fixtures through temporary directories, and subprocess-based integration tests.

**ShipCheck scope:** complete current test suite.

---

## 5. Toml / tomli → tomllib

**Used for:** `pyproject.toml` and `Cargo.toml` parsing.

**Why:** Python 3.11 introduced `tomllib` in the standard library.

**ShipCheck scope:** manifest parsing required by the dependency analyzer.

---

## 6. Pathspec → pathlib + explicit directory rules

**Used for:** repository traversal and excluded-directory handling.

**Why:** ShipCheck has a deliberately small set of directories that should not be analyzed, such as `.git`, virtual environments, build directories, and `node_modules`.

**ShipCheck scope:** repository traversal and analyzer exclusions.

---

## 7. GitPython → subprocess + Git CLI

**Used for:** optional `--diff` mode.

**Why:** ShipCheck only needs a narrow Git operation: obtain changed paths. Python's `subprocess` module can invoke the existing Git executable without adding a Python dependency.

**ShipCheck scope:** changed-file discovery, not Git implementation.

---

## 8. Packaging → manifest parsing

**Used for:** dependency inspection.

**Why:** ShipCheck does not need to build, install, or resolve Python distributions. It only needs to inspect supported dependency manifests.

**ShipCheck scope:** dependency names, version pinning, and lockfile presence.

---

## 9. Radon → ast-based metrics

**Used for:** lightweight Python code-health metrics.

**Why:** Python's `ast` module exposes functions, async functions, classes, and source structure. ShipCheck can calculate basic metrics directly without a complexity-analysis package.

**ShipCheck scope:** Python LOC, function counts, method counts, and AST-based rule checks.

---

## 10. Bandit → custom AST security rules

**Used for:** a focused subset of Python security checks.

**Why:** Python's `ast` module is sufficient for straightforward syntactic checks such as `eval()`, `exec()`, `os.system()`, unsafe pickle loading, `shell=True`, weak hashes, and hardcoded secret patterns.

**ShipCheck scope:** a small, explicitly documented subset.

**Important:** ShipCheck does **not** replace Bandit and does not claim complete vulnerability detection.

---

## 11. Pipdeptree → manifest inspection

**Used for:** dependency visibility.

**Why:** ShipCheck can inspect declared dependency manifests directly. This avoids package metadata resolution when the goal is repository preflight analysis.

**ShipCheck scope:** declared dependencies, counts, pinning, and lockfile presence.

---

## 12. SARIF libraries → json

**Used for:** SARIF serialization.

**Why:** SARIF is JSON-based. ShipCheck only emits the subset of SARIF needed to represent its static-analysis findings, so Python's `json` module is sufficient.

**ShipCheck scope:** SARIF 2.1.0-style results and rule metadata.

---

## Development-only tools

A developer may use external tools locally for editing, profiling, formatting, or reviewing the repository. Those tools are not runtime dependencies of ShipCheck.

The zero-dependency claim applies to the final production/runtime implementation.
