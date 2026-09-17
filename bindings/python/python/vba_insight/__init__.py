"""vba-insight: Pure Rust static analysis, P-code disassembly, and stomping detection for VBA & Office macros."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Union

from . import _native

__version__: str = _native.version()

InputType = Union[str, Path, bytes, bytearray]


def inspect_file(
    target: InputType,
    *,
    include_source: bool = True,
) -> dict[str, Any]:
    """Inspect an Office macro container (.xlsm, .xlsb, .docm, .pptm, .xls, or vbaProject.bin).

    Args:
        target: File path (str or Path) or file contents (bytes/bytearray).
        include_source: Whether to include decompressed VBA source code in the output.

    Returns:
        dict containing 'analysis', 'stomping', and 'pcode' reports.
    """
    arg = str(target) if isinstance(target, Path) else target
    raw_json = _native.inspect_macro_file_json(arg, include_source)
    return json.loads(raw_json)


def inspect_file_markdown(target: InputType) -> str:
    """Generate a GitHub-flavored Markdown inspection report for an Office macro container.

    Args:
        target: File path (str or Path) or file contents (bytes/bytearray).

    Returns:
        Markdown report string.
    """
    arg = str(target) if isinstance(target, Path) else target
    return _native.inspect_macro_file_markdown(arg)


def inspect_file_sarif(target: InputType) -> str:
    """Generate an OASIS SARIF v2.1.0 security report for VBA Stomping and container threats.

    Args:
        target: File path (str or Path) or file contents (bytes/bytearray).

    Returns:
        SARIF JSON string.
    """
    arg = str(target) if isinstance(target, Path) else target
    return _native.inspect_macro_file_sarif(arg)


def analyze_sources(
    sources: list[tuple[str, str]],
    *,
    include_source: bool = True,
) -> dict[str, Any]:
    """Perform pure static analysis (tokenization, AST, control flow, type checking) on VBA source units.

    Args:
        sources: List of (module_name, source_code) tuples.
        include_source: Whether to include source text in the result.

    Returns:
        dict containing parsed AST, procedures, diagnostics, and call graph.
    """
    raw_json = _native.analyze_sources_json(sources, include_source)
    return json.loads(raw_json)


__all__ = [
    "__version__",
    "analyze_sources",
    "inspect_file",
    "inspect_file_markdown",
    "inspect_file_sarif",
]
