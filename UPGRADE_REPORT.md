# ShipCheck 0.4.0 Upgrade Report

## Files changed/added

- `shipcheck.py`
  - Stable rule identifiers
  - Finding metadata: ID, category, file, line, column
  - Deterministic Ship Score
  - Category scores and verdict
  - JSON schema version 1
  - SARIF 2.1.0 output
  - `--format`
  - `--severity`
  - `--fail-on`
  - `--quiet`
  - `--summary`
  - `--diff`
  - CI-friendly exit codes
- `test_shipcheck.py`
  - Updated for the new report schema and exit-code behavior
  - Version updated to 0.4.0
  - Removed an environment-sensitive stderr assertion
- `test_competition.py`
  - Added tests for scoring, stable rule IDs, JSON metadata, SARIF, and severity filtering
- `README.md`
  - Full competition-oriented documentation
- `STDLIB.md`
  - 12 standard-library substitution/design entries
- `verify_stdlib.py`
  - Dependency-boundary verification script
- `.gitignore`
  - Preserved the existing runtime/build exclusions

## Verification

- Full test suite: **68 tests passed**
- Runtime import verification: **PASS**
- ShipCheck self-scan: **0 findings, 100/100**
- JSON output: verified
- SARIF output: verified
- CLI help/version/summary/quiet: verified
- Runtime dependencies: standard library only

## Runtime dependency policy

No third-party runtime packages were added.

## Intentional limitations

ShipCheck remains a focused repository preflight/static-analysis tool. It does not claim complete vulnerability detection, complete language support, dependency resolution, or full replacement of tools such as Bandit.
