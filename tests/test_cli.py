"""Tests for the CLI interface."""

from __future__ import annotations

from click.testing import CliRunner

from quantum_iot_security.cli import cli


class TestCLI:
    def test_version(self):
        """--version should print the version."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_status(self):
        """status command should show operational status."""
        runner = CliRunner()
        result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0
        assert "Operational" in result.output

    def test_analyze_firmware(self, tmp_path):
        """analyze-firmware should analyze a file."""
        fw_file = tmp_path / "test.bin"
        fw_file.write_bytes(b"password=test telnetd" + bytes(200))
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze-firmware", str(fw_file)])
        assert result.exit_code == 0
        assert "Risk Score" in result.output

    def test_pqc_test(self):
        """pqc-test command should perform key exchange."""
        runner = CliRunner()
        result = runner.invoke(cli, ["pqc-test", "--dimension", "64"])
        assert result.exit_code == 0
        assert "Post-Quantum Key Exchange" in result.output

    def test_demo(self):
        """demo command should run all capabilities."""
        runner = CliRunner()
        result = runner.invoke(cli, ["demo"])
        assert result.exit_code == 0
        assert "Demo Complete" in result.output
