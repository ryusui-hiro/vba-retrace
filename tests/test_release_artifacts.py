"""Regression checks for release identity, ABI, and artifact packaging rules."""
import importlib.util
import json
from pathlib import Path
import zipfile
import pytest

SPEC = importlib.util.spec_from_file_location(
    "release_artifacts", Path(__file__).resolve().parents[1] / "scripts/release-artifacts.py"
)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def test_versions_are_aligned():
    ver = release.version()
    assert isinstance(ver, str)
    assert len(ver) > 0


def create_fake_wheel(tmp_path, *, version="0.1.0", tag="cp310-abi3-manylinux_2_28_x86_64", license_line="License: MIT\n", extra=None):
    path = tmp_path / "test.whl"
    path.parent.mkdir(parents=True, exist_ok=True)
    root = f"vba_insight-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{root}/METADATA", f"Name: vba-insight\nVersion: {version}\n{license_line}")
        archive.writestr(f"{root}/WHEEL", f"Wheel-Version: 1.0\nTag: {tag}\n")
        archive.writestr(f"{root}/licenses/LICENSE", "test license")
        archive.writestr("vba_insight/_native.abi3.so", b"dummy")
        if extra:
            archive.writestr(extra, b"unexpected")
    return path


def test_check_wheel_accepts_valid_wheel(tmp_path):
    whl = create_fake_wheel(tmp_path, version="0.1.0")
    release.check_wheel(whl, "0.1.0")

    whl_pep639 = create_fake_wheel(tmp_path / "pep639", version="0.1.0", license_line="License-Expression: MIT\n")
    release.check_wheel(whl_pep639, "0.1.0")


def test_check_wheel_rejects_version_mismatch(tmp_path):
    whl = create_fake_wheel(tmp_path, version="0.2.0")
    with pytest.raises(ValueError, match="unexpected wheel metadata"):
        release.check_wheel(whl, "0.1.0")


def test_check_wheel_rejects_non_abi3_tag(tmp_path):
    whl = create_fake_wheel(tmp_path, version="0.1.0", tag="cp313-cp313-linux_x86_64")
    with pytest.raises(ValueError, match="unexpected wheel metadata"):
        release.check_wheel(whl, "0.1.0")


def test_check_wheel_rejects_extra_native_library(tmp_path):
    whl = create_fake_wheel(tmp_path, version="0.1.0", extra="vba_insight/libextra.so")
    with pytest.raises(ValueError, match="unexpected bundled native library"):
        release.check_wheel(whl, "0.1.0")


def test_assemble_refuses_mismatched_commit_or_version(tmp_path, monkeypatch):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    tag = release.TARGETS[0]["tag"]
    (artifacts / "build-info.json").write_text(json.dumps({
        "tag": tag, "version": "0.1.0", "commit": "wrong_commit", "files": {},
    }))
    monkeypatch.setattr(release, "version", lambda: "0.1.0")
    with pytest.raises(ValueError, match="source revision/version mismatch"):
        release.assemble(artifacts, tmp_path / "output", "expected_commit")
