from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import time
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


VERSION = "0.3.0"


@dataclass
class AnalysisContext:
    root: Path


@dataclass
class Finding:
    severity: str
    message: str
    recommendation: str


@dataclass
class ScanMetrics:
    files_discovered: int
    bytes_considered: int
    binary_files: int
    python_files: int
    python_loc: int
    functions: int
    methods: int


class Analyzer:
    name = "Analyzer"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        raise NotImplementedError


class AnalyzerRunner:
    def __init__(self, analyzers: list[Analyzer]) -> None:
        self.analyzers = analyzers

    def run(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []

        for analyzer in self.analyzers:
            findings.extend(analyzer.analyze(context))

        return findings


class RepositoryAnalyzer(Analyzer):
    name = "RepositoryAnalyzer"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []

        if not context.root.exists():
            findings.append(
                Finding(
                    "HIGH",
                    "Repository path does not exist.",
                    "Provide a valid repository path.",
                )
            )
            return findings

        if not context.root.is_dir():
            findings.append(
                Finding(
                    "HIGH",
                    "Repository path is not a directory.",
                    "Provide a repository directory.",
                )
            )
            return findings

        readme_files = [
            "README",
            "README.md",
            "README.txt",
            "README.rst",
        ]

        if not any((context.root / name).exists() for name in readme_files):
            findings.append(
                Finding(
                    "MEDIUM",
                    "Repository does not contain a README file.",
                    "Add a README.md describing the project.",
                )
            )

        return findings


class DependencyAnalyzer(Analyzer):
    name = "DependencyAnalyzer"

    MAX_DEPENDENCIES = 20

    REQUIREMENTS_FILES = {
        "requirements.txt": {
            "lockfiles": [
                "requirements.lock",
                "pip-lock.txt",
                "Pipfile.lock",
            ],
        },
        "package.json": {
            "lockfiles": [
                "package-lock.json",
                "yarn.lock",
                "pnpm-lock.yaml",
            ],
        },
        "Cargo.toml": {
            "lockfiles": [
                "Cargo.lock",
            ],
        },
        "pyproject.toml": {
            "lockfiles": [
                "poetry.lock",
                "uv.lock",
                "Pipfile.lock",
            ],
        },
    }

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []

        root = context.root

        if not root.exists() or not root.is_dir():
            return findings

        for filename in self.REQUIREMENTS_FILES:
            manifest = root / filename

            if not manifest.is_file():
                continue

            try:
                dependencies, unpinned = self._parse_manifest(
                    filename,
                    manifest,
                )
            except (
                OSError,
                UnicodeDecodeError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                findings.append(
                    Finding(
                        "MEDIUM",
                        f"Could not parse dependency manifest {filename}: {exc}",
                        f"Fix the syntax of {filename} so dependency analysis can continue.",
                    )
                )
                continue

            dependency_count = len(dependencies)

            if dependency_count > self.MAX_DEPENDENCIES:
                findings.append(
                    Finding(
                        "MEDIUM",
                        (
                            f"{filename} contains {dependency_count} dependencies, "
                            f"which exceeds the recommended limit of "
                            f"{self.MAX_DEPENDENCIES}."
                        ),
                        "Review whether all declared dependencies are necessary.",
                    )
                )

            if unpinned:
                displayed = ", ".join(sorted(unpinned))

                findings.append(
                    Finding(
                        "MEDIUM",
                        f"{filename} contains unpinned dependencies: {displayed}.",
                        "Pin dependencies to exact versions where reproducible builds are required.",
                    )
                )

            lockfile = self._find_lockfile(root, filename)

            if lockfile is None:
                findings.append(
                    Finding(
                        "MEDIUM",
                        f"{filename} does not have a corresponding lockfile.",
                        self._lockfile_recommendation(filename),
                    )
                )

        return findings

    def _parse_manifest(
        self,
        filename: str,
        path: Path,
    ) -> tuple[list[str], set[str]]:
        if filename == "requirements.txt":
            return self._parse_requirements_txt(path)

        if filename == "package.json":
            return self._parse_package_json(path)

        if filename == "Cargo.toml":
            return self._parse_cargo_toml(path)

        if filename == "pyproject.toml":
            return self._parse_pyproject_toml(path)

        return [], set()

    def _parse_requirements_txt(
        self,
        path: Path,
    ) -> tuple[list[str], set[str]]:
        dependencies: list[str] = []
        unpinned: set[str] = set()

        lines = path.read_text(encoding="utf-8").splitlines()

        for raw_line in lines:
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            if line.startswith(
                (
                    "-r ",
                    "--requirement ",
                    "-c ",
                    "--constraint ",
                )
            ):
                continue

            if line.startswith(("-", "--")):
                continue

            line = line.split(" #", 1)[0].strip()

            match = re.match(
                r"^([A-Za-z0-9_.-]+)(.*)$",
                line,
            )

            if not match:
                continue

            name = match.group(1)
            specifier = match.group(2).strip()

            dependencies.append(name)

            if not self._is_exact_python_pin(specifier):
                unpinned.add(name)

        return dependencies, unpinned

    def _parse_package_json(
        self,
        path: Path,
    ) -> tuple[list[str], set[str]]:
        data = json.loads(
            path.read_text(encoding="utf-8")
        )

        dependencies: list[str] = []
        unpinned: set[str] = set()

        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
        ):
            values = data.get(section, {})

            if not isinstance(values, dict):
                continue

            for name, version in values.items():
                dependencies.append(name)

                if not self._is_exact_npm_pin(str(version)):
                    unpinned.add(name)

        return dependencies, unpinned

    def _parse_cargo_toml(
        self,
        path: Path,
    ) -> tuple[list[str], set[str]]:
        data = tomllib.loads(
            path.read_text(encoding="utf-8")
        )

        dependencies: list[str] = []
        unpinned: set[str] = set()

        for section_name in (
            "dependencies",
            "dev-dependencies",
            "build-dependencies",
        ):
            section = data.get(section_name, {})

            if not isinstance(section, dict):
                continue

            for name, specification in section.items():
                dependencies.append(name)

                if not self._is_exact_cargo_pin(specification):
                    unpinned.add(name)

        target = data.get("target", {})

        if isinstance(target, dict):
            for target_data in target.values():
                if not isinstance(target_data, dict):
                    continue

                for section_name in (
                    "dependencies",
                    "dev-dependencies",
                    "build-dependencies",
                ):
                    section = target_data.get(section_name, {})

                    if not isinstance(section, dict):
                        continue

                    for name, specification in section.items():
                        dependencies.append(name)

                        if not self._is_exact_cargo_pin(specification):
                            unpinned.add(name)

        return dependencies, unpinned

    def _parse_pyproject_toml(
        self,
        path: Path,
    ) -> tuple[list[str], set[str]]:
        data = tomllib.loads(
            path.read_text(encoding="utf-8")
        )

        dependencies: list[str] = []
        unpinned: set[str] = set()

        project = data.get("project", {})

        if isinstance(project, dict):
            project_dependencies = project.get(
                "dependencies",
                [],
            )

            if isinstance(project_dependencies, list):
                for dependency in project_dependencies:
                    if not isinstance(dependency, str):
                        continue

                    name, specifier = self._split_python_requirement(
                        dependency
                    )

                    if name:
                        dependencies.append(name)

                        if not self._is_exact_python_pin(
                            specifier
                        ):
                            unpinned.add(name)

            optional = project.get(
                "optional-dependencies",
                {},
            )

            if isinstance(optional, dict):
                for values in optional.values():
                    if not isinstance(values, list):
                        continue

                    for dependency in values:
                        if not isinstance(dependency, str):
                            continue

                        name, specifier = self._split_python_requirement(
                            dependency
                        )

                        if name:
                            dependencies.append(name)

                            if not self._is_exact_python_pin(
                                specifier
                            ):
                                unpinned.add(name)

        tool = data.get("tool", {})

        if isinstance(tool, dict):
            poetry = tool.get("poetry", {})

            if isinstance(poetry, dict):
                poetry_dependencies = poetry.get(
                    "dependencies",
                    {},
                )

                if isinstance(poetry_dependencies, dict):
                    for name, specification in poetry_dependencies.items():
                        if name.lower() == "python":
                            continue

                        dependencies.append(name)

                        if not self._is_exact_poetry_pin(
                            specification
                        ):
                            unpinned.add(name)

                poetry_groups = poetry.get(
                    "group",
                    {},
                )

                if isinstance(poetry_groups, dict):
                    for group in poetry_groups.values():
                        if not isinstance(group, dict):
                            continue

                        group_dependencies = group.get(
                            "dependencies",
                            {},
                        )

                        if not isinstance(
                            group_dependencies,
                            dict,
                        ):
                            continue

                        for name, specification in group_dependencies.items():
                            dependencies.append(name)

                            if not self._is_exact_poetry_pin(
                                specification
                            ):
                                unpinned.add(name)

        return dependencies, unpinned

    def _split_python_requirement(
        self,
        requirement: str,
    ) -> tuple[str, str]:
        requirement = requirement.split(
            ";",
            1,
        )[0].strip()

        match = re.match(
            r"^([A-Za-z0-9_.-]+)(.*)$",
            requirement,
        )

        if not match:
            return "", ""

        return (
            match.group(1),
            match.group(2).strip(),
        )

    def _is_exact_python_pin(
        self,
        specifier: str,
    ) -> bool:
        return bool(
            re.fullmatch(
                r"==\s*[0-9]+(?:\.[0-9]+)*(?:[A-Za-z0-9.+-]+)?",
                specifier,
            )
        )

    def _is_exact_npm_pin(
        self,
        version: str,
    ) -> bool:
        version = version.strip()

        return bool(
            re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?",
                version,
            )
        )

    def _is_exact_cargo_pin(
        self,
        specification: Any,
    ) -> bool:
        if isinstance(specification, str):
            return bool(
                re.fullmatch(
                    r"=\s*[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?",
                    specification.strip(),
                )
            )

        if isinstance(specification, dict):
            version = specification.get("version")

            if not isinstance(version, str):
                return False

            return bool(
                re.fullmatch(
                    r"=\s*[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?",
                    version.strip(),
                )
            )

        return False

    def _is_exact_poetry_pin(
        self,
        specification: Any,
    ) -> bool:
        if isinstance(specification, str):
            return bool(
                re.fullmatch(
                    r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?",
                    specification.strip(),
                )
            )

        if isinstance(specification, dict):
            version = specification.get("version")

            if not isinstance(version, str):
                return False

            return bool(
                re.fullmatch(
                    r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?",
                    version.strip(),
                )
            )

        return False

    def _find_lockfile(
        self,
        root: Path,
        manifest_name: str,
    ) -> Path | None:
        lockfiles = self.REQUIREMENTS_FILES[
            manifest_name
        ]["lockfiles"]

        for lockfile_name in lockfiles:
            lockfile = root / lockfile_name

            if lockfile.is_file():
                return lockfile

        return None

    def _lockfile_recommendation(
        self,
        filename: str,
    ) -> str:
        recommendations = {
            "requirements.txt": (
                "Add a requirements.lock, pip-lock.txt, or equivalent "
                "lockfile to make dependency resolution reproducible."
            ),
            "package.json": (
                "Commit package-lock.json, yarn.lock, or pnpm-lock.yaml "
                "to make dependency resolution reproducible."
            ),
            "Cargo.toml": (
                "Commit Cargo.lock to make dependency resolution reproducible."
            ),
            "pyproject.toml": (
                "Commit an appropriate lockfile such as poetry.lock or uv.lock "
                "when reproducible dependency resolution is required."
            ),
        }

        return recommendations[filename]


class StaticAnalyzer(Analyzer):
    name = "StaticAnalyzer"

    EXCLUDED_DIRECTORIES = {
        ".git",
        ".venv",
        "venv",
        "env",
        ".env",
        "__pycache__",
        "node_modules",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }

    SECRET_NAME_PATTERN = re.compile(
        r"(password|passwd|secret|api[_-]?key|access[_-]?key|"
        r"auth[_-]?token|token|private[_-]?key)",
        re.IGNORECASE,
    )

    PLACEHOLDER_VALUES = {
        "password",
        "passwd",
        "secret",
        "your_password",
        "your-secret",
        "your_secret",
        "your-api-key",
        "your_api_key",
        "changeme",
        "change_me",
        "example",
        "test",
        "dummy",
        "placeholder",
        "none",
        "null",
        "",
    }

    HTTP_METHODS = {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "request",
        "head",
        "options",
    }

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:
        findings: list[Finding] = []

        root = context.root

        if not root.exists() or not root.is_dir():
            return findings

        for path in self._python_files(root):
            findings.extend(
                self._analyze_python_file(
                    root,
                    path,
                )
            )

        return findings

    def _python_files(
        self,
        root: Path,
    ) -> list[Path]:
        files: list[Path] = []

        for path in root.rglob("*.py"):
            relative_parts = path.relative_to(root).parts

            if any(
                part in self.EXCLUDED_DIRECTORIES
                for part in relative_parts
            ):
                continue

            if path.name.startswith("test_"):
                continue

            if path.name.endswith("_test.py"):
                continue

            files.append(path)

        return sorted(files)

    def _analyze_python_file(
        self,
        root: Path,
        path: Path,
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            source = path.read_text(
                encoding="utf-8"
            )
        except (
            OSError,
            UnicodeDecodeError,
        ) as exc:
            findings.append(
                Finding(
                    "MEDIUM",
                    (
                        f"Could not read Python source "
                        f"{self._display_path(root, path)}: {exc}"
                    ),
                    "Ensure the source file is readable UTF-8 text.",
                )
            )
            return findings

        try:
            tree = ast.parse(
                source,
                filename=str(path),
            )
        except SyntaxError as exc:
            location = self._syntax_location(exc)

            findings.append(
                Finding(
                    "MEDIUM",
                    (
                        f"{self._display_path(root, path)}{location} "
                        "contains a Python syntax error."
                    ),
                    "Fix the syntax error so the source can be parsed and analyzed.",
                )
            )
            return findings

        for node in ast.walk(tree):
            finding = self._check_node(
                node,
                root,
                path,
            )

            if finding is not None:
                findings.append(finding)

        return findings

    def _check_node(
        self,
        node: ast.AST,
        root: Path,
        path: Path,
    ) -> Finding | None:
        location = self._location(
            root,
            path,
            node,
        )

        if isinstance(node, ast.Call):
            dangerous_call = self._check_dangerous_call(
                node,
                location,
            )

            if dangerous_call is not None:
                return dangerous_call

            verify_finding = self._check_verify_false(
                node,
                location,
            )

            if verify_finding is not None:
                return verify_finding

        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                return Finding(
                    "LOW",
                    f"{location} uses a bare except clause.",
                    "Catch specific exception types instead of catching every exception.",
                )

        if isinstance(node, ast.Assign):
            secret_finding = self._check_secret_assignment(
                node,
                location,
            )

            if secret_finding is not None:
                return secret_finding

        if isinstance(node, ast.AnnAssign):
            secret_finding = self._check_annotated_secret_assignment(
                node,
                location,
            )

            if secret_finding is not None:
                return secret_finding

        return None

    def _check_dangerous_call(
        self,
        node: ast.Call,
        location: str,
    ) -> Finding | None:
        function_name = self._call_name(node)

        if function_name in {
            "eval",
            "exec",
        }:
            return Finding(
                "HIGH",
                f"{location} uses {function_name}(), which executes dynamically supplied code.",
                "Avoid dynamic code execution; use safer parsing or explicit dispatch.",
            )

        if function_name == "os.system":
            return Finding(
                "HIGH",
                f"{location} uses os.system(), which executes a command through the system shell.",
                "Use subprocess with shell=False and pass command arguments as a sequence.",
            )

        if function_name in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
        }:
            if self._keyword_is_true(
                node,
                "shell",
            ):
                return Finding(
                    "HIGH",
                    f"{location} invokes {function_name}() with shell=True.",
                    "Avoid shell=True for untrusted input; pass arguments directly with shell=False.",
                )

        if function_name in {
            "pickle.load",
            "pickle.loads",
        }:
            return Finding(
                "HIGH",
                f"{location} uses {function_name}(), which can execute code when loading untrusted pickle data.",
                "Do not deserialize untrusted pickle data; use a safer data format such as JSON.",
            )

        if function_name == "tempfile.mktemp":
            return Finding(
                "HIGH",
                f"{location} uses tempfile.mktemp(), which can introduce a temporary-file race condition.",
                "Use tempfile.NamedTemporaryFile or another secure temporary-file API.",
            )

        if function_name in {
            "hashlib.md5",
            "hashlib.sha1",
        }:
            algorithm = function_name.rsplit(
                ".",
                1,
            )[1]

            return Finding(
                "MEDIUM",
                f"{location} uses the weak {algorithm.upper()} hash algorithm.",
                "Use SHA-256 or a stronger algorithm when the hash is used for security purposes.",
            )

        return None

    def _check_verify_false(
        self,
        node: ast.Call,
        location: str,
    ) -> Finding | None:
        function_name = self._call_name(node)

        if function_name is None:
            return None

        method_name = function_name.rsplit(
            ".",
            1,
        )[-1]

        if method_name not in self.HTTP_METHODS:
            return None

        if not any(
            keyword.arg == "verify"
            and isinstance(
                keyword.value,
                ast.Constant,
            )
            and keyword.value.value is False
            for keyword in node.keywords
        ):
            return None

        return Finding(
            "HIGH",
            f"{location} disables TLS certificate verification with verify=False.",
            "Keep TLS certificate verification enabled unless there is a documented, controlled reason to disable it.",
        )

    def _check_secret_assignment(
        self,
        node: ast.Assign,
        location: str,
    ) -> Finding | None:
        value = node.value

        if not isinstance(
            value,
            ast.Constant,
        ):
            return None

        if not isinstance(
            value.value,
            str,
        ):
            return None

        secret_value = value.value.strip()

        for target in node.targets:
            if not isinstance(
                target,
                ast.Name,
            ):
                continue

            if not self.SECRET_NAME_PATTERN.search(
                target.id
            ):
                continue

            if self._looks_like_placeholder(
                secret_value
            ):
                continue

            if len(secret_value) < 8:
                continue

            return Finding(
                "HIGH",
                (
                    f"{location} appears to contain a hardcoded secret "
                    f"in variable '{target.id}'."
                ),
                "Move secrets to environment variables or a dedicated secret manager and keep them out of source control.",
            )

        return None

    def _check_annotated_secret_assignment(
        self,
        node: ast.AnnAssign,
        location: str,
    ) -> Finding | None:
        if not isinstance(
            node.target,
            ast.Name,
        ):
            return None

        if not self.SECRET_NAME_PATTERN.search(
            node.target.id
        ):
            return None

        if not isinstance(
            node.value,
            ast.Constant,
        ):
            return None

        if not isinstance(
            node.value.value,
            str,
        ):
            return None

        secret_value = node.value.value.strip()

        if self._looks_like_placeholder(
            secret_value
        ):
            return None

        if len(secret_value) < 8:
            return None

        return Finding(
            "HIGH",
            (
                f"{location} appears to contain a hardcoded secret "
                f"in variable '{node.target.id}'."
            ),
            "Move secrets to environment variables or a dedicated secret manager and keep them out of source control.",
        )

    def _looks_like_placeholder(
        self,
        value: str,
    ) -> bool:
        normalized = value.strip().lower()

        if normalized in self.PLACEHOLDER_VALUES:
            return True

        if normalized.startswith(
            (
                "your_",
                "your-",
                "<your",
                "${",
                "$(",
            )
        ):
            return True

        if "example.com" in normalized:
            return True

        if normalized in {
            "localhost",
            "127.0.0.1",
        }:
            return True

        return False

    def _call_name(
        self,
        node: ast.Call,
    ) -> str | None:
        parts: list[str] = []
        current: ast.AST = node.func

        while isinstance(
            current,
            ast.Attribute,
        ):
            parts.append(current.attr)
            current = current.value

        if isinstance(
            current,
            ast.Name,
        ):
            parts.append(current.id)
            return ".".join(reversed(parts))

        return None

    def _keyword_is_true(
        self,
        node: ast.Call,
        keyword_name: str,
    ) -> bool:
        for keyword in node.keywords:
            if keyword.arg != keyword_name:
                continue

            if isinstance(
                keyword.value,
                ast.Constant,
            ):
                return keyword.value.value is True

        return False

    def _display_path(
        self,
        root: Path,
        path: Path,
    ) -> str:
        return str(
            path.relative_to(root)
        )

    def _location(
        self,
        root: Path,
        path: Path,
        node: ast.AST,
    ) -> str:
        relative = self._display_path(
            root,
            path,
        )

        line = getattr(
            node,
            "lineno",
            1,
        )

        return f"{relative}:{line}"

    def _syntax_location(
        self,
        error: SyntaxError,
    ) -> str:
        if error.lineno is None:
            return ""

        return f":{error.lineno}"


def _is_binary(data: bytes) -> bool:
    if not data:
        return False

    if b"\x00" in data:
        return True

    sample = data[:8192]

    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return True

    return False


def _calculate_python_metrics(
    root: Path,
) -> tuple[int, int, int]:
    python_files = 0
    python_loc = 0
    functions = 0
    methods = 0

    excluded_directories = StaticAnalyzer.EXCLUDED_DIRECTORIES

    for path in root.rglob("*.py"):
        relative_parts = path.relative_to(root).parts

        if any(
            part in excluded_directories
            for part in relative_parts
        ):
            continue

        if path.name.startswith("test_"):
            continue

        if path.name.endswith("_test.py"):
            continue

        python_files += 1

        try:
            source = path.read_text(encoding="utf-8")
        except (
            OSError,
            UnicodeDecodeError,
        ):
            continue

        python_loc += sum(
            1
            for line in source.splitlines()
            if line.strip()
            and not line.lstrip().startswith("#")
        )

        try:
            tree = ast.parse(
                source,
                filename=str(path),
            )
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions += 1

                if node.col_offset > 0:
                    methods += 1

    return (
        python_files,
        python_loc,
        functions,
        methods,
    )


def collect_metrics(root: Path) -> ScanMetrics:
    if not root.exists() or not root.is_dir():
        return ScanMetrics(
            files_discovered=0,
            bytes_considered=0,
            binary_files=0,
            python_files=0,
            python_loc=0,
            functions=0,
            methods=0,
        )

    files_discovered = 0
    bytes_considered = 0
    binary_files = 0

    excluded_directories = StaticAnalyzer.EXCLUDED_DIRECTORIES

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        relative_parts = path.relative_to(root).parts

        if any(
            part in excluded_directories
            for part in relative_parts
        ):
            continue

        try:
            data = path.read_bytes()
        except OSError:
            continue

        files_discovered += 1
        bytes_considered += len(data)

        if _is_binary(data):
            binary_files += 1

    (
        python_files,
        python_loc,
        functions,
        methods,
    ) = _calculate_python_metrics(root)

    return ScanMetrics(
        files_discovered=files_discovered,
        bytes_considered=bytes_considered,
        binary_files=binary_files,
        python_files=python_files,
        python_loc=python_loc,
        functions=functions,
        methods=methods,
    )


def severity_counts(
    findings: list[Finding],
) -> dict[str, int]:
    counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = finding.severity.upper()

        if severity not in counts:
            counts[severity] = 0

        counts[severity] += 1

    return counts


def has_high_severity(
    findings: list[Finding],
) -> bool:
    return any(
        finding.severity.upper() == "HIGH"
        for finding in findings
    )


def build_report(
    root: Path,
    findings: list[Finding],
    metrics: ScanMetrics,
    duration_seconds: float,
) -> dict[str, Any]:
    return {
        "metadata": {
            "tool": "ShipCheck",
            "version": VERSION,
            "project": str(root),
            "duration_seconds": round(
                duration_seconds,
                6,
            ),
        },
        "summary": {
            "findings": len(findings),
            "severity_counts": severity_counts(findings),
            "exit_code": 1 if has_high_severity(findings) else 0,
        },
        "metrics": asdict(metrics),
        "findings": [
            {
                "severity": finding.severity,
                "message": finding.message,
                "recommendation": finding.recommendation,
            }
            for finding in findings
        ],
    }


def format_report(
    root: Path,
    findings: list[Finding],
    metrics: ScanMetrics | None = None,
    duration_seconds: float | None = None,
) -> str:
    lines: list[str] = []

    if metrics is None:
        metrics = collect_metrics(root)

    if duration_seconds is None:
        duration_seconds = 0.0

    counts = severity_counts(findings)

    lines.append(f"ShipCheck {VERSION}")
    lines.append(f"Project: {root}")
    lines.append("")

    lines.append("Scan Summary")
    lines.append("------------")
    lines.append(f"Files scanned: {metrics.files_discovered}")
    lines.append(f"Bytes considered: {metrics.bytes_considered}")
    lines.append(f"Binary files: {metrics.binary_files}")
    lines.append(f"Python files: {metrics.python_files}")
    lines.append(f"Python LOC: {metrics.python_loc}")
    lines.append(f"Functions: {metrics.functions}")
    lines.append(f"Methods: {metrics.methods}")
    lines.append(f"Duration: {duration_seconds:.3f}s")
    lines.append("")

    lines.append("Findings")
    lines.append("--------")
    lines.append(f"Total: {len(findings)}")
    lines.append(f"HIGH: {counts.get('HIGH', 0)}")
    lines.append(f"MEDIUM: {counts.get('MEDIUM', 0)}")
    lines.append(f"LOW: {counts.get('LOW', 0)}")
    lines.append("")

    if not findings:
        lines.append("No issues found.")
        return "\n".join(lines)

    for finding in findings:
        lines.append(f"[{finding.severity}]")
        lines.append(finding.message)
        lines.append(
            f"Recommendation: {finding.recommendation}"
        )
        lines.append("")

    return "\n".join(lines).rstrip()


def format_json_report(
    root: Path,
    findings: list[Finding],
    metrics: ScanMetrics,
    duration_seconds: float,
) -> str:
    report = build_report(
        root,
        findings,
        metrics,
        duration_seconds,
    )

    return json.dumps(
        report,
        indent=2,
        sort_keys=False,
    )


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shipcheck",
        description=(
            "Zero-dependency repository preflight auditing CLI."
        ),
    )

    parser.add_argument(
        "repository",
        nargs="?",
        type=Path,
        help="Path to the repository to audit.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output the complete report as JSON.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"ShipCheck {VERSION}",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()

    args = parser.parse_args(argv)

    if args.repository is None:
        parser.error(
            "the following arguments are required: repository"
        )

    root = args.repository.expanduser()

    context = AnalysisContext(
        root=root
    )

    start = time.perf_counter()

    runner = AnalyzerRunner(
        analyzers=[
            RepositoryAnalyzer(),
            DependencyAnalyzer(),
            StaticAnalyzer(),
        ]
    )

    findings = runner.run(
        context
    )

    metrics = collect_metrics(root)

    duration_seconds = time.perf_counter() - start

    if args.json_output:
        print(
            format_json_report(
                root,
                findings,
                metrics,
                duration_seconds,
            )
        )
    else:
        print(
            format_report(
                root,
                findings,
                metrics,
                duration_seconds,
            )
        )

    return 1 if has_high_severity(findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())