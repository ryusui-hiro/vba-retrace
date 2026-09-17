import json
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

def test_inspect_file_rejects_invalid():
    with pytest.raises(ValueError, match="failed"):
        vba_insight.inspect_file(b"not a valid zip or cfb file")
