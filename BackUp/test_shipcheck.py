import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from shipcheck import (
    AnalysisContext,
    AnalyzerRunner,
    DependencyAnalyzer,
    Finding,
    RepositoryAnalyzer,
    ScanMetrics,
    StaticAnalyzer,
    build_report,
    format_json_report,
    format_report,
    main,
    severity_counts,
)


class DependencyAnalyzerTests(unittest.TestCase):
    def run_analyzer(
        self,
        files: dict[str, str],
    ) -> list[Finding]:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            for filename, content in files.items():
                path = root / filename
                path.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )
                path.write_text(
                    content,
                    encoding="utf-8",
                )

            context = AnalysisContext(
                root=root
            )

            analyzer = DependencyAnalyzer()

            return analyzer.analyze(
                context
            )

    def messages(
        self,
        findings: list[Finding],
    ) -> list[str]:
        return [
            finding.message
            for finding in findings
        ]

    def test_requirements_txt_pinned_dependency(self) -> None:
        findings = self.run_analyzer(
            {
                "requirements.txt": "requests==2.32.3\n",
                "requirements.lock": "",
            }
        )

        self.assertEqual(
            findings,
            [],
        )

    def test_requirements_txt_unpinned_dependency(self) -> None:
        findings = self.run_analyzer(
            {
                "requirements.txt": "requests\n",
                "requirements.lock": "",
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any(
                "unpinned dependencies" in message
                for message in messages
            )
        )

        self.assertFalse(
            any(
                "does not have a corresponding lockfile"
                in message
                for message in messages
            )
        )

    def test_requirements_txt_missing_lockfile(self) -> None:
        findings = self.run_analyzer(
            {
                "requirements.txt": "requests==2.32.3\n",
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any(
                "does not have a corresponding lockfile"
                in message
                for message in messages
            )
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
                "package.json": json.dumps(
                    package_json
                ),
                "package-lock.json": "{}",
            }
        )

        self.assertEqual(
            findings,
            [],
        )

    def test_package_json_unpinned_dependency(self) -> None:
        package_json = {
            "dependencies": {
                "react": "^18.3.1",
            }
        }

        findings = self.run_analyzer(
            {
                "package.json": json.dumps(
                    package_json
                ),
                "package-lock.json": "{}",
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any(
                "unpinned dependencies" in message
                for message in messages
            )
        )

    def test_package_json_missing_lockfile(self) -> None:
        package_json = {
            "dependencies": {
                "react": "18.3.1",
            }
        }

        findings = self.run_analyzer(
            {
                "package.json": json.dumps(
                    package_json
                ),
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any(
                "does not have a corresponding lockfile"
                in message
                for message in messages
            )
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

        self.assertEqual(
            findings,
            [],
        )

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
            any(
                "unpinned dependencies" in message
                for message in messages
            )
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
            any(
                "does not have a corresponding lockfile"
                in message
                for message in messages
            )
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

        self.assertEqual(
            findings,
            [],
        )

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
            any(
                "unpinned dependencies" in message
                for message in messages
            )
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
            any(
                "does not have a corresponding lockfile"
                in message
                for message in messages
            )
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
            any(
                "python" in message.lower()
                for message in messages
            )
        )

        self.assertFalse(
            any(
                "requests" in message
                and "unpinned" in message
                for message in messages
            )
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
            any(
                "21 dependencies" in message
                for message in messages
            )
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

        self.assertEqual(
            findings,
            [],
        )

    def test_invalid_package_json_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "package.json": "{ invalid json",
            }
        )

        self.assertEqual(
            len(findings),
            1,
        )

        self.assertEqual(
            findings[0].severity,
            "MEDIUM",
        )

        self.assertIn(
            "Could not parse dependency manifest",
            findings[0].message,
        )

    def test_invalid_pyproject_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "pyproject.toml": "[project\ninvalid",
            }
        )

        self.assertEqual(
            len(findings),
            1,
        )

        self.assertEqual(
            findings[0].severity,
            "MEDIUM",
        )

        self.assertIn(
            "Could not parse dependency manifest",
            findings[0].message,
        )


class RepositoryAnalyzerTests(unittest.TestCase):
    def test_missing_readme_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            findings = RepositoryAnalyzer().analyze(
                AnalysisContext(
                    root=root
                )
            )

            self.assertEqual(
                len(findings),
                1,
            )

            self.assertEqual(
                findings[0].severity,
                "MEDIUM",
            )

            self.assertIn(
                "README",
                findings[0].message,
            )

    def test_readme_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            (
                root / "README.md"
            ).write_text(
                "# Example\n",
                encoding="utf-8",
            )

            findings = RepositoryAnalyzer().analyze(
                AnalysisContext(
                    root=root
                )
            )

            self.assertEqual(
                findings,
                [],
            )


class StaticAnalyzerTests(unittest.TestCase):
    def run_analyzer(
        self,
        files: dict[str, str],
    ) -> list[Finding]:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            for filename, content in files.items():
                path = root / filename

                path.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                path.write_text(
                    content,
                    encoding="utf-8",
                )

            analyzer = StaticAnalyzer()

            return analyzer.analyze(
                AnalysisContext(
                    root=root
                )
            )

    def messages(
        self,
        findings: list[Finding],
    ) -> list[str]:
        return [
            finding.message
            for finding in findings
        ]

    def test_eval_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
value = eval(user_input)
"""
            }
        )

        self.assertTrue(
            any(
                "eval()" in message
                for message in self.messages(findings)
            )
        )

        self.assertTrue(
            any(
                finding.severity == "HIGH"
                for finding in findings
            )
        )

    def test_exec_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
exec(user_input)
"""
            }
        )

        self.assertTrue(
            any(
                "exec()" in message
                for message in self.messages(findings)
            )
        )

    def test_os_system_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
import os

os.system(command)
"""
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any(
                "os.system()" in message
                for message in messages
            )
        )

    def test_subprocess_shell_true_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
import subprocess

subprocess.run(command, shell=True)
"""
            }
        )

        messages = self.messages(findings)

        self.assertTrue(
            any(
                "shell=True" in message
                for message in messages
            )
        )

    def test_subprocess_shell_false_is_accepted(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
import subprocess

subprocess.run(
    ["echo", "hello"],
    shell=False,
)
"""
            }
        )

        self.assertEqual(
            findings,
            [],
        )

    def test_pickle_load_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
import pickle

value = pickle.loads(data)
"""
            }
        )

        self.assertTrue(
            any(
                "pickle.loads()" in message
                for message in self.messages(findings)
            )
        )

    def test_tempfile_mktemp_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
import tempfile

path = tempfile.mktemp()
"""
            }
        )

        self.assertTrue(
            any(
                "tempfile.mktemp()" in message
                for message in self.messages(findings)
            )
        )

    def test_md5_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
import hashlib

digest = hashlib.md5(data)
"""
            }
        )

        self.assertTrue(
            any(
                "MD5" in message
                for message in self.messages(findings)
            )
        )

    def test_sha1_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
import hashlib

digest = hashlib.sha1(data)
"""
            }
        )

        self.assertTrue(
            any(
                "SHA1" in message
                for message in self.messages(findings)
            )
        )

    def test_bare_except_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
try:
    do_work()
except:
    pass
"""
            }
        )

        self.assertTrue(
            any(
                "bare except" in message
                for message in self.messages(findings)
            )
        )

    def test_specific_except_is_accepted(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
try:
    do_work()
except ValueError:
    pass
"""
            }
        )

        self.assertEqual(
            findings,
            [],
        )

    def test_hardcoded_api_key_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
api_key = "sk_live_123456789abcdef"
"""
            }
        )

        self.assertTrue(
            any(
                "hardcoded secret" in message
                for message in self.messages(findings)
            )
        )

    def test_hardcoded_password_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
database_password = "supersecret123"
"""
            }
        )

        self.assertTrue(
            any(
                "hardcoded secret" in message
                for message in self.messages(findings)
            )
        )

    def test_placeholder_secret_is_accepted(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
api_key = "your-api-key"
"""
            }
        )

        self.assertEqual(
            findings,
            [],
        )

    def test_environment_secret_is_accepted(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
import os

api_key = os.environ["API_KEY"]
"""
            }
        )

        self.assertEqual(
            findings,
            [],
        )

    def test_annotated_secret_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
api_key: str = "secret-value-12345"
"""
            }
        )

        self.assertTrue(
            any(
                "hardcoded secret" in message
                for message in self.messages(findings)
            )
        )

    def test_verify_false_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
import requests

requests.get(
    url,
    verify=False,
)
"""
            }
        )

        self.assertTrue(
            any(
                "verify=False" in message
                for message in self.messages(findings)
            )
        )

    def test_verify_true_is_accepted(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
import requests

requests.get(
    url,
    verify=True,
)
"""
            }
        )

        self.assertEqual(
            findings,
            [],
        )

    def test_syntax_error_is_reported(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
def broken(
"""
            }
        )

        self.assertEqual(
            len(findings),
            1,
        )

        self.assertEqual(
            findings[0].severity,
            "MEDIUM",
        )

        self.assertIn(
            "syntax error",
            findings[0].message,
        )

    def test_non_python_files_are_ignored(self) -> None:
        findings = self.run_analyzer(
            {
                "notes.txt": """
eval(user_input)
password = "secret12345"
"""
            }
        )

        self.assertEqual(
            findings,
            [],
        )

    def test_test_files_are_ignored(self) -> None:
        findings = self.run_analyzer(
            {
                "test_example.py": """
eval(user_input)
"""
            }
        )

        self.assertEqual(
            findings,
            [],
        )

    def test_excluded_directories_are_ignored(self) -> None:
        findings = self.run_analyzer(
            {
                ".venv/app.py": """
eval(user_input)
""",
                "node_modules/app.py": """
eval(user_input)
""",
            }
        )

        self.assertEqual(
            findings,
            [],
        )

    def test_clean_python_file_has_no_findings(self) -> None:
        findings = self.run_analyzer(
            {
                "app.py": """
import os

api_key = os.environ.get("API_KEY")

try:
    value = int("10")
except ValueError:
    value = 0

print(value)
"""
            }
        )

        self.assertEqual(
            findings,
            [],
        )


class AnalyzerRunnerTests(unittest.TestCase):
    def test_runner_executes_all_analyzers(self) -> None:
        class FirstAnalyzer:
            name = "FirstAnalyzer"

            def analyze(
                self,
                context: AnalysisContext,
            ) -> list[Finding]:
                return [
                    Finding(
                        "LOW",
                        "First finding",
                        "First recommendation",
                    )
                ]

        class SecondAnalyzer:
            name = "SecondAnalyzer"

            def analyze(
                self,
                context: AnalysisContext,
            ) -> list[Finding]:
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
                AnalysisContext(
                    root=root
                )
            )

            self.assertEqual(
                len(findings),
                2,
            )

            self.assertEqual(
                findings[0].message,
                "First finding",
            )

            self.assertEqual(
                findings[1].message,
                "Second finding",
            )


class FormatReportTests(unittest.TestCase):
    def test_empty_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            report = format_report(
                root,
                [],
            )

            self.assertIn(
                "ShipCheck 0.4.0",
                report,
            )

            self.assertIn(
                "Total: 0",
                report,
            )

            self.assertIn(
                "No issues found.",
                report,
            )

    def test_report_contains_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            findings = [
                Finding(
                    "HIGH",
                    "Test finding",
                    "Test recommendation",
                )
            ]

            report = format_report(
                root,
                findings,
            )

            self.assertIn(
                "Total: 1",
                report,
            )

            self.assertIn(
                "[HIGH]",
                report,
            )

            self.assertIn(
                "Test finding",
                report,
            )

            self.assertIn(
                "Recommendation: Test recommendation",
                report,
            )

    def test_report_contains_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            metrics = ScanMetrics(
                files_discovered=5,
                bytes_considered=1000,
                binary_files=1,
                python_files=2,
                python_loc=50,
                functions=4,
                methods=2,
            )

            report = format_report(
                root,
                [],
                metrics=metrics,
                duration_seconds=0.125,
            )

            self.assertIn(
                "Files scanned: 5",
                report,
            )

            self.assertIn(
                "Bytes considered: 1000",
                report,
            )

            self.assertIn(
                "Binary files: 1",
                report,
            )

            self.assertIn(
                "Python files: 2",
                report,
            )

            self.assertIn(
                "Python LOC: 50",
                report,
            )

            self.assertIn(
                "Functions: 4",
                report,
            )

            self.assertIn(
                "Methods: 2",
                report,
            )

            self.assertIn(
                "Duration: 0.125s",
                report,
            )


class SeverityTests(unittest.TestCase):
    def test_severity_counts(self) -> None:
        findings = [
            Finding(
                "HIGH",
                "High finding",
                "Fix high",
            ),
            Finding(
                "HIGH",
                "Another high finding",
                "Fix high",
            ),
            Finding(
                "MEDIUM",
                "Medium finding",
                "Fix medium",
            ),
            Finding(
                "LOW",
                "Low finding",
                "Fix low",
            ),
        ]

        self.assertEqual(
            severity_counts(findings),
            {
                "HIGH": 2,
                "MEDIUM": 1,
                "LOW": 1,
            },
        )


class JsonReportTests(unittest.TestCase):
    def test_json_report_contains_metadata_summary_metrics_and_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            findings = [
                Finding(
                    "HIGH",
                    "Test finding",
                    "Test recommendation",
                )
            ]

            metrics = ScanMetrics(
                files_discovered=3,
                bytes_considered=500,
                binary_files=0,
                python_files=1,
                python_loc=10,
                functions=2,
                methods=1,
            )

            output = format_json_report(
                root,
                findings,
                metrics,
                0.25,
            )

            data = json.loads(output)

            self.assertIn(
                "metadata",
                data,
            )

            self.assertIn(
                "summary",
                data,
            )

            self.assertIn(
                "metrics",
                data,
            )

            self.assertIn(
                "findings",
                data,
            )

            self.assertEqual(
                data["metadata"]["tool"],
                "ShipCheck",
            )

            self.assertEqual(
                data["metadata"]["version"],
                "0.4.0",
            )

            self.assertEqual(
                data["summary"]["findings"],
                1,
            )

            self.assertEqual(
                data["summary"]["severity_counts"]["HIGH"],
                1,
            )

            self.assertEqual(
                data["summary"]["exit_code"],
                1,
            )

            self.assertEqual(
                data["metrics"]["files_discovered"],
                3,
            )

            self.assertEqual(
                len(data["findings"]),
                1,
            )

            self.assertEqual(
                data["findings"][0]["severity"],
                "HIGH",
            )

            self.assertIn(
                "id",
                data["findings"][0],
            )

            self.assertIn(
                "category",
                data["findings"][0],
            )

            self.assertIn(
                "score",
                data,
            )

            self.assertEqual(
                data["findings"][0]["message"],
                "Test finding",
            )

    def test_clean_json_report_has_zero_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            metrics = ScanMetrics(
                files_discovered=1,
                bytes_considered=10,
                binary_files=0,
                python_files=0,
                python_loc=0,
                functions=0,
                methods=0,
            )

            output = format_json_report(
                root,
                [],
                metrics,
                0.01,
            )

            data = json.loads(output)

            self.assertEqual(
                data["summary"]["findings"],
                0,
            )

            self.assertEqual(
                data["summary"]["severity_counts"],
                {
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                },
            )

            self.assertEqual(
                data["summary"]["exit_code"],
                0,
            )

            self.assertEqual(
                data["findings"],
                [],
            )


class BuildReportTests(unittest.TestCase):
    def test_build_report_returns_complete_structure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            findings = [
                Finding(
                    "MEDIUM",
                    "Medium issue",
                    "Fix it",
                )
            ]

            metrics = ScanMetrics(
                files_discovered=2,
                bytes_considered=100,
                binary_files=0,
                python_files=1,
                python_loc=5,
                functions=1,
                methods=0,
            )

            report = build_report(
                root,
                findings,
                metrics,
                0.5,
            )

            self.assertEqual(
                set(report.keys()),
                {
                    "version",
                    "metadata",
                    "repository",
                    "score",
                    "summary",
                    "metrics",
                    "findings",
                },
            )

            self.assertEqual(
                report["summary"]["exit_code"],
                0,
            )


class CliVersionTests(unittest.TestCase):
    def test_version_flag(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).with_name("shipcheck.py")),
                "--version",
            ],
            capture_output=True,
            text=True,
        )

        self.assertEqual(
            result.returncode,
            0,
        )

        self.assertEqual(
            result.stdout.strip(),
            "ShipCheck 0.4.0",
        )

    def test_version_flag_can_be_invoked_directly(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            main(["--version"])

        self.assertEqual(
            raised.exception.code,
            0,
        )


class CliJsonTests(unittest.TestCase):
    def test_json_flag_outputs_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            (
                root / "README.md"
            ).write_text(
                "# Clean repository\n",
                encoding="utf-8",
            )

            (
                root / "app.py"
            ).write_text(
                "print('hello')\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("shipcheck.py")),
                    "--json",
                    str(root),
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(
                result.returncode,
                0,
            )

            data = json.loads(
                result.stdout
            )

            self.assertEqual(
                data["metadata"]["tool"],
                "ShipCheck",
            )

            self.assertEqual(
                data["metadata"]["version"],
                "0.4.0",
            )

            self.assertEqual(
                data["summary"]["exit_code"],
                0,
            )

            self.assertIsInstance(
                data["findings"],
                list,
            )

            self.assertIn(
                "metrics",
                data,
            )

    def test_json_flag_does_not_mix_human_output_into_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            (
                root / "README.md"
            ).write_text(
                "# Clean repository\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("shipcheck.py")),
                    str(root),
                    "--json",
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(
                result.returncode,
                0,
            )

            data = json.loads(
                result.stdout
            )

            self.assertIn(
                "metadata",
                data,
            )

            self.assertNotIn(
                "ShipCheck 0.4.0",
                data["findings"],
            )


class CliExitCodeTests(unittest.TestCase):
    def test_clean_repository_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            (
                root / "README.md"
            ).write_text(
                "# Clean repository\n",
                encoding="utf-8",
            )

            (
                root / "app.py"
            ).write_text(
                "print('hello')\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("shipcheck.py")),
                    str(root),
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(
                result.returncode,
                0,
            )

            self.assertIn(
                "No issues found.",
                result.stdout,
            )

    def test_medium_warning_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("shipcheck.py")),
                    str(root),
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(
                result.returncode,
                0,
            )

            self.assertIn(
                "[MEDIUM]",
                result.stdout,
            )

    def test_high_finding_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            (
                root / "README.md"
            ).write_text(
                "# Repository\n",
                encoding="utf-8",
            )

            (
                root / "app.py"
            ).write_text(
                "value = eval(user_input)\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("shipcheck.py")),
                    str(root),
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(
                result.returncode,
                1,
            )

            self.assertIn(
                "[HIGH]",
                result.stdout,
            )

    def test_high_json_report_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            (
                root / "README.md"
            ).write_text(
                "# Repository\n",
                encoding="utf-8",
            )

            (
                root / "app.py"
            ).write_text(
                "value = eval(user_input)\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("shipcheck.py")),
                    "--json",
                    str(root),
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(
                result.returncode,
                1,
            )

            data = json.loads(
                result.stdout
            )

            self.assertEqual(
                data["summary"]["exit_code"],
                1,
            )

            self.assertEqual(
                data["summary"]["severity_counts"]["HIGH"],
                1,
            )


class CliArgumentTests(unittest.TestCase):
    def test_missing_repository_is_rejected(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).with_name("shipcheck.py")),
            ],
            capture_output=True,
            text=True,
        )

        self.assertEqual(
            result.returncode,
            2,
        )

        self.assertIn(
            "repository",
            result.stderr,
        )

    def test_nonexistent_repository_returns_high_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = (
                Path(temp_dir)
                / "does-not-exist"
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("shipcheck.py")),
                    str(missing),
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(
                result.returncode,
                2,
            )

            self.assertIn(
                "repository does not exist",
                result.stderr,
            )


if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )