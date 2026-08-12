from __future__ import annotations

import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class AnalysisContext:
    root: Path


@dataclass
class Finding:
    severity: str
    message: str
    recommendation: str


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

        found_manifests = False

        for filename in self.REQUIREMENTS_FILES:
            manifest = root / filename

            if not manifest.is_file():
                continue

            found_manifests = True

            try:
                dependencies, unpinned = self._parse_manifest(
                    filename,
                    manifest,
                )
            except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
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

        if not found_manifests:
            return findings

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

            if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
                continue

            if line.startswith(("-", "--")):
                continue

            line = line.split(" #", 1)[0].strip()

            match = re.match(
                r"^([A-Za-z0-9_.-]+)\s*(.*)$",
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
        data = json.loads(path.read_text(encoding="utf-8"))

        dependencies: list[str] = []
        unpinned: set[str] = set()

        for section in ("dependencies", "devDependencies", "optionalDependencies"):
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
        data = tomllib.loads(path.read_text(encoding="utf-8"))

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
        data = tomllib.loads(path.read_text(encoding="utf-8"))

        dependencies: list[str] = []
        unpinned: set[str] = set()

        project = data.get("project", {})

        if isinstance(project, dict):
            project_dependencies = project.get("dependencies", [])

            if isinstance(project_dependencies, list):
                for dependency in project_dependencies:
                    if not isinstance(dependency, str):
                        continue

                    name, specifier = self._split_python_requirement(dependency)

                    if name:
                        dependencies.append(name)

                        if not self._is_exact_python_pin(specifier):
                            unpinned.add(name)

            optional = project.get("optional-dependencies", {})

            if isinstance(optional, dict):
                for values in optional.values():
                    if not isinstance(values, list):
                        continue

                    for dependency in values:
                        if not isinstance(dependency, str):
                            continue

                        name, specifier = self._split_python_requirement(dependency)

                        if name:
                            dependencies.append(name)

                            if not self._is_exact_python_pin(specifier):
                                unpinned.add(name)

        poetry = data.get("tool", {}).get("poetry", {})

        if isinstance(poetry, dict):
            poetry_dependencies = poetry.get("dependencies", {})

            if isinstance(poetry_dependencies, dict):
                for name, specification in poetry_dependencies.items():
                    if name.lower() == "python":
                        continue

                    dependencies.append(name)

                    if not self._is_exact_poetry_pin(specification):
                        unpinned.add(name)

            poetry_groups = poetry.get("group", {})

            if isinstance(poetry_groups, dict):
                for group in poetry_groups.values():
                    if not isinstance(group, dict):
                        continue

                    group_dependencies = group.get("dependencies", {})

                    if not isinstance(group_dependencies, dict):
                        continue

                    for name, specification in group_dependencies.items():
                        dependencies.append(name)

                        if not self._is_exact_poetry_pin(specification):
                            unpinned.add(name)

        return dependencies, unpinned

    def _split_python_requirement(
        self,
        requirement: str,
    ) -> tuple[str, str]:
        requirement = requirement.split(";", 1)[0].strip()

        match = re.match(
            r"^([A-Za-z0-9_.-]+)(.*)$",
            requirement,
        )

        if not match:
            return "", ""

        return match.group(1), match.group(2).strip()

    def _is_exact_python_pin(self, specifier: str) -> bool:
        return bool(
            re.fullmatch(
                r"==\s*[0-9]+(?:\.[0-9]+)*(?:[A-Za-z0-9.+-]*)",
                specifier,
            )
        )

    def _is_exact_npm_pin(self, version: str) -> bool:
        version = version.strip()

        return bool(
            re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?",
                version,
            )
        )

    def _is_exact_cargo_pin(self, specification: Any) -> bool:
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

            if not re.fullmatch(
                r"=\s*[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?",
                version.strip(),
            ):
                return False

            return True

        return False

    def _is_exact_poetry_pin(self, specification: Any) -> bool:
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
        lockfiles = self.REQUIREMENTS_FILES[manifest_name]["lockfiles"]

        for lockfile_name in lockfiles:
            lockfile = root / lockfile_name

            if lockfile.is_file():
                return lockfile

        return None

    def _lockfile_recommendation(self, filename: str) -> str:
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


def format_report(
    root: Path,
    findings: list[Finding],
) -> str:
    lines: list[str] = []

    lines.append("ShipCheck 0.2.0")
    lines.append(f"Project: {root}")
    lines.append("")

    if not findings:
        lines.append("Findings: 0")
        lines.append("")
        lines.append("No issues found.")
        return "\n".join(lines)

    lines.append(f"Findings: {len(findings)}")
    lines.append("")

    for finding in findings:
        lines.append(f"[{finding.severity}]")
        lines.append(f"{finding.message}")
        lines.append(f"Recommendation: {finding.recommendation}")
        lines.append("")

    return "\n".join(lines).rstrip()


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python shipcheck.py <repository-path>")
        return 2

    root = Path(sys.argv[1]).expanduser()

    context = AnalysisContext(root=root)

    runner = AnalyzerRunner(
        analyzers=[
            RepositoryAnalyzer(),
            DependencyAnalyzer(),
        ]
    )

    findings = runner.run(context)

    print(format_report(root, findings))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())