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
    raw_json = inspect_file_json(target, include_source=include_source)
    return json.loads(raw_json)


def inspect_file_json(
    target: InputType,
    *,
    include_source: bool = True,
) -> str:
    """Inspect an Office macro container and return the complete report as raw JSON.

    Args:
        target: File path (str or Path) or file contents (bytes/bytearray).
        include_source: Whether to include decompressed VBA source code in the output.

    Returns:
        JSON string report.
    """
    arg = str(target) if isinstance(target, Path) else target
    return _native.inspect_macro_file_json(arg, include_source)


def inspect_file_markdown(target: InputType) -> str:
    """Generate a GitHub-flavored Markdown inspection report for an Office macro container.

    Args:
        target: File path (str or Path) or file contents (bytes/bytearray).

    Returns:
        Markdown report string.
    """
    arg = str(target) if isinstance(target, Path) else target
    return _native.inspect_macro_file_markdown(arg)


def inspect_file_sarif(
    target: InputType,
    *,
    file_uri: str | None = None,
) -> str:
    """Generate an OASIS SARIF v2.1.0 security report for VBA Stomping and container threats.

    Args:
        target: File path (str or Path) or file contents (bytes/bytearray).
        file_uri: Optional artifact URI reported in SARIF findings (defaults to filename or 'macro_container').

    Returns:
        SARIF JSON string.
    """
    arg = str(target) if isinstance(target, Path) else target
    uri = file_uri or (str(target) if isinstance(target, (str, Path)) else "macro_container")
    return _native.inspect_macro_file_sarif(arg, uri)


def disasm_file(target: InputType) -> list[dict[str, Any]]:
    """Disassemble VBA P-code instructions from an Office macro container into Python dictionaries.

    Args:
        target: File path (str or Path) or file contents (bytes/bytearray).

    Returns:
        list of module disassembly dictionaries with instruction mnemonic, opcode, and operands.
    """
    raw_json = disasm_file_json(target)
    return json.loads(raw_json)


def disasm_file_json(target: InputType) -> str:
    """Disassemble VBA P-code instructions from an Office macro container and return as JSON.

    Args:
        target: File path (str or Path) or file contents (bytes/bytearray).

    Returns:
        JSON string containing disassembled P-code modules.
    """
    arg = str(target) if isinstance(target, Path) else target
    return _native.disasm_macro_file_json(arg)


def disasm_file_markdown(target: InputType) -> str:
    """Generate a formatted Markdown disassembly report of VBA P-code for an Office macro container.

    Args:
        target: File path (str or Path) or file contents (bytes/bytearray).

    Returns:
        Markdown disassembly report string.
    """
    arg = str(target) if isinstance(target, Path) else target
    return _native.disasm_macro_file_markdown(arg)


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
    raw_json = analyze_sources_json(sources, include_source=include_source)
    return json.loads(raw_json)


def analyze_sources_json(
    sources: list[tuple[str, str]],
    *,
    include_source: bool = True,
) -> str:
    """Perform pure static analysis on VBA source units and return the report as raw JSON.

    Args:
        sources: List of (module_name, source_code) tuples.
        include_source: Whether to include source text in the result.

    Returns:
        JSON string report.
    """
    return _native.analyze_sources_json(sources, include_source)


__all__ = [
    "__version__",
    "analyze_sources",
    "analyze_sources_json",
    "disasm_file",
    "disasm_file_json",
    "disasm_file_markdown",
    "inspect_file",
    "inspect_file_json",
    "inspect_file_markdown",
    "inspect_file_sarif",
]
