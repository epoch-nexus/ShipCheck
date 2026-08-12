import json
import tempfile
import unittest
from pathlib import Path

from shipcheck import (
    AnalysisContext,
    AnalyzerRunner,
    DependencyAnalyzer,
    Finding,
    RepositoryAnalyzer,
)


class DependencyAnalyzerTests(unittest.TestCase):
    def run_analyzer(self, files: dict[str, str]) -> list[Finding]:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            for filename, content in files.items():
                path = root / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            context = AnalysisContext(root=root)
            analyzer = DependencyAnalyzer()

            return analyzer.analyze(context)

    def messages(self, findings: list[Finding]) -> list[str]:
        return [finding.message for finding in findings]

    def test_requirements_txt_pinned_dependency(self) -> None:
        findings = self.run_analyzer(
            {
                "requirements.txt": "requests==2.32.3\n",
                "requirements.lock": "",
            }
        )

        self.assertEqual(findings, [])

    def test_requirements_txt_unpinned_dependency(self) -> None:
        findings = self.run_analyzer(
            {
                "requirements.txt": "requests\n",
                "requirements.lock": "",
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any("unpinned dependencies" in message for message in messages)
        )

        self.assertFalse(
            any("does not have a corresponding lockfile" in message for message in messages)
        )

    def test_requirements_txt_missing_lockfile(self) -> None:
        findings = self.run_analyzer(
            {
                "requirements.txt": "requests==2.32.3\n",
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any("does not have a corresponding lockfile" in message for message in messages)
        )

    def test_package_json_pinned_dependencies(self) -> None:
        package_json = {
            "dependencies": {
                "react": "18.3.1",
                "express": "4.21.1",
            }
        }

        findings = self.run_analyzer(
            {
                "package.json": json.dumps(package_json),
                "package-lock.json": "{}",
            }
        )

        self.assertEqual(findings, [])

    def test_package_json_unpinned_dependency(self) -> None:
        package_json = {
            "dependencies": {
                "react": "^18.3.1",
            }
        }

        findings = self.run_analyzer(
            {
                "package.json": json.dumps(package_json),
                "package-lock.json": "{}",
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any("unpinned dependencies" in message for message in messages)
        )

    def test_package_json_missing_lockfile(self) -> None:
        package_json = {
            "dependencies": {
                "react": "18.3.1",
            }
        }

        findings = self.run_analyzer(
            {
                "package.json": json.dumps(package_json),
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any("does not have a corresponding lockfile" in message for message in messages)
        )

    def test_cargo_toml_exact_dependencies(self) -> None:
        cargo_toml = """
[package]
name = "example"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "=1.0.210"
tokio = { version = "=1.41.0", features = ["full"] }
"""

        findings = self.run_analyzer(
            {
                "Cargo.toml": cargo_toml,
                "Cargo.lock": "",
            }
        )

        self.assertEqual(findings, [])

    def test_cargo_toml_unpinned_dependency(self) -> None:
        cargo_toml = """
[package]
name = "example"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
"""

        findings = self.run_analyzer(
            {
                "Cargo.toml": cargo_toml,
                "Cargo.lock": "",
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any("unpinned dependencies" in message for message in messages)
        )

    def test_cargo_toml_missing_lockfile(self) -> None:
        cargo_toml = """
[package]
name = "example"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "=1.0.210"
"""

        findings = self.run_analyzer(
            {
                "Cargo.toml": cargo_toml,
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any("does not have a corresponding lockfile" in message for message in messages)
        )

    def test_pyproject_project_dependencies(self) -> None:
        pyproject = """
[project]
name = "example"
version = "0.1.0"
dependencies = [
    "requests==2.32.3",
    "click==8.1.7",
]
"""

        findings = self.run_analyzer(
            {
                "pyproject.toml": pyproject,
                "uv.lock": "",
            }
        )

        self.assertEqual(findings, [])

    def test_pyproject_unpinned_dependency(self) -> None:
        pyproject = """
[project]
name = "example"
version = "0.1.0"
dependencies = [
    "requests>=2.0",
]
"""

        findings = self.run_analyzer(
            {
                "pyproject.toml": pyproject,
                "uv.lock": "",
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any("unpinned dependencies" in message for message in messages)
        )

    def test_pyproject_missing_lockfile(self) -> None:
        pyproject = """
[project]
name = "example"
version = "0.1.0"
dependencies = [
    "requests==2.32.3",
]
"""

        findings = self.run_analyzer(
            {
                "pyproject.toml": pyproject,
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any("does not have a corresponding lockfile" in message for message in messages)
        )

    def test_pyproject_poetry_dependencies(self) -> None:
        pyproject = """
[tool.poetry]
name = "example"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
requests = "2.32.3"
"""

        findings = self.run_analyzer(
            {
                "pyproject.toml": pyproject,
                "poetry.lock": "",
            }
        )

        messages = self.messages(findings)

        self.assertFalse(
            any("python" in message.lower() for message in messages)
        )

        self.assertFalse(
            any("requests" in message and "unpinned" in message for message in messages)
        )

    def test_high_package_count(self) -> None:
        dependencies = "\n".join(
            f"package{i}==1.0.0"
            for i in range(21)
        )

        findings = self.run_analyzer(
            {
                "requirements.txt": dependencies,
                "requirements.lock": "",
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any("21 dependencies" in message for message in messages)
        )

    def test_comments_and_blank_lines_are_ignored(self) -> None:
        requirements = """
# Main dependencies

requests==2.32.3
# Another comment
flask==3.0.3

"""

        findings = self.run_analyzer(
            {
                "requirements.txt": requirements,
                "requirements.lock": "",
            }
        )

        self.assertEqual(findings, [])

    def test_invalid_package_json_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "package.json": "{ invalid json",
            }
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertIn("Could not parse dependency manifest", findings[0].message)

    def test_invalid_pyproject_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "pyproject.toml": "[project\ninvalid",
            }
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertIn("Could not parse dependency manifest", findings[0].message)


class RepositoryAnalyzerTests(unittest.TestCase):
    def test_missing_readme_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            findings = RepositoryAnalyzer().analyze(
                AnalysisContext(root=root)
            )

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "MEDIUM")
            self.assertIn("README", findings[0].message)

    def test_readme_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "README.md").write_text(
                "# Example\n",
                encoding="utf-8",
            )

            findings = RepositoryAnalyzer().analyze(
                AnalysisContext(root=root)
            )

            self.assertEqual(findings, [])


class AnalyzerRunnerTests(unittest.TestCase):
    def test_runner_executes_all_analyzers(self) -> None:
        class FirstAnalyzer:
            name = "FirstAnalyzer"

            def analyze(self, context: AnalysisContext) -> list[Finding]:
                return [
                    Finding(
                        "LOW",
                        "First finding",
                        "First recommendation",
                    )
                ]

        class SecondAnalyzer:
            name = "SecondAnalyzer"

            def analyze(self, context: AnalysisContext) -> list[Finding]:
                return [
                    Finding(
                        "MEDIUM",
                        "Second finding",
                        "Second recommendation",
                    )
                ]

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            runner = AnalyzerRunner(
                [
                    FirstAnalyzer(),
                    SecondAnalyzer(),
                ]
            )

            findings = runner.run(
                AnalysisContext(root=root)
            )

            self.assertEqual(len(findings), 2)
            self.assertEqual(findings[0].message, "First finding")
            self.assertEqual(findings[1].message, "Second finding")


if __name__ == "__main__":
    unittest.main(verbosity=2)