# ShipCheck

ShipCheck is a zero-dependency Python repository health, static analysis, security, and dependency analysis tool.

It scans a repository and reports common issues that can make a project difficult to ship safely.

## Features

ShipCheck currently analyzes:

- Repository structure
- README presence
- Python source code
- Dangerous dynamic code execution
- Shell command execution
- Unsafe subprocess usage
- Unsafe deserialization
- Weak cryptographic algorithms
- Hardcoded secrets
- TLS verification settings
- Bare exception handlers
- Dependency pinning
- Missing dependency lockfiles
- Dependency count
- Python code metrics
- JSON reports
- Severity-based exit codes

## Requirements

- Python 3.9+
- No external Python dependencies

ShipCheck uses Python's standard library.

## Installation

Clone the repository:

```bash
git clone https://github.com/epoch-nexus/shipcheck.git
cd shipcheck