import json
from pathlib import Path
import pytest
import vba_insight


def test_version():
    assert isinstance(vba_insight.__version__, str)
    assert len(vba_insight.__version__) > 0


def test_analyze_sources():
    sources = [
        ("Module1.bas", "Public Sub Hello()\n    MsgBox \"Hello from Python\"\nEnd Sub\n")
    ]
    report = vba_insight.analyze_sources(sources)
    assert isinstance(report, dict)
    assert "modules" in report
    assert len(report["modules"]) == 1
    assert report["modules"][0]["name"] == "Module1"


def test_analyze_sources_json_and_structure_only():
    sources = [
        ("ModSecret.bas", "Public Sub RunPayload()\n    MsgBox \"SecretString\"\nEnd Sub\n")
    ]
    # With include_source=True, raw source text and expressions are retained
    raw_full = vba_insight.analyze_sources_json(sources, include_source=True)
    assert "SecretString" in raw_full

    # With include_source=False, source expressions and string literals are redacted
    raw_redacted = vba_insight.analyze_sources_json(sources, include_source=False)
    assert "SecretString" not in raw_redacted
    parsed = json.loads(raw_redacted)
    assert len(parsed["modules"]) == 1


def test_inspect_file_rejects_invalid():
    with pytest.raises(ValueError, match="failed"):
        vba_insight.inspect_file(b"not a valid zip or cfb file")

    with pytest.raises(ValueError, match="failed"):
        vba_insight.inspect_file(b"")


def test_inspect_file_json_and_markdown_and_sarif_rejects_invalid():
    with pytest.raises(ValueError, match="failed"):
        vba_insight.inspect_file_json(b"invalid data")

    with pytest.raises(ValueError, match="failed"):
        vba_insight.inspect_file_markdown(b"invalid data")

    with pytest.raises(ValueError, match="failed"):
        vba_insight.inspect_file_sarif(b"invalid data", file_uri="custom_test.xlsm")


def test_inspect_file_nonexistent_path(tmp_path):
    missing_file = tmp_path / "does_not_exist.xlsm"
    with pytest.raises(IOError):
        vba_insight.inspect_file(missing_file)

    with pytest.raises(IOError):
        vba_insight.inspect_file(str(missing_file))


def test_inspect_file_type_error():
    with pytest.raises(ValueError, match="expected bytes"):
        vba_insight.inspect_file(12345)  # type: ignore
