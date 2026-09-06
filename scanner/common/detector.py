"""Deterministic crypto detector: extension + regex + optional lightweight AST cues."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from scanner.common.catalog import LIBRARY_NAMES
from scanner.common.patterns import COMPILED, CURVE_PATTERNS, KEY_SIZE_PATTERNS, MODE_PATTERNS
from scanner.common.types import Detection, language_for


def _int_or_none(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _infer_key_size(algorithm: str, text: str, match_groups: dict[str, str]) -> int | None:
    for key in ("key_size", "key_size2"):
        size = _int_or_none(match_groups.get(key))
        if size:
            return size
    for pattern in KEY_SIZE_PATTERNS:
        found = pattern.search(text)
        if found:
            return int(found.group(1))
    if algorithm == "Ed25519":
        return 256
    if algorithm == "Ed448":
        return 448
    return None


def _infer_curve(text: str, groups: dict[str, str]) -> str:
    if groups.get("curve"):
        return groups["curve"]
    for pattern in CURVE_PATTERNS:
        found = pattern.search(text)
        if found:
            return found.group(1)
    return ""


def _infer_mode(text: str) -> str:
    for pattern in MODE_PATTERNS:
        found = pattern.search(text)
        if found:
            return found.group(1).upper()
    return ""


def _libraries_in(text: str) -> str:
    lower = text.lower()
    found = [name for needle, name in LIBRARY_NAMES.items() if needle in lower]
    return found[0] if found else ""


def _python_ast_detections(path: Path, source: str) -> list[Detection]:
    detections: list[Detection] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return detections
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
            lineno = getattr(node, "lineno", 1)
            snippet = ast.unparse(node) if hasattr(ast, "unparse") else func
            mapping = {
                "hashlib.md5": "MD5",
                "hashlib.sha1": "SHA-1",
                "hashlib.sha256": "SHA-256",
                "hashlib.sha384": "SHA-384",
                "hashlib.sha512": "SHA-512",
                "RSA.generate": "RSA",
            }
            for needle, algo in mapping.items():
                if needle in func:
                    key_size = None
                    if node.args:
                        arg0 = node.args[0]
                        if isinstance(arg0, ast.Constant) and isinstance(arg0.value, int):
                            key_size = arg0.value
                    detections.append(
                        Detection(
                            algorithm=algo,
                            file=str(path),
                            line=lineno,
                            evidence=snippet[:240],
                            language="python",
                            key_size=key_size,
                            source_type="source",
                        )
                    )
    return detections


def detect_in_text(path: Path, text: str) -> list[Detection]:
    language = language_for(path)
    detections: list[Detection] = []
    seen: set[tuple[str, int, str]] = set()
    lines = text.splitlines() or [text]
    for pattern, compiled in COMPILED:
        if language not in pattern.languages and language not in {"unknown", "config"}:
            # still allow generic config-like files
            if pattern.languages and language not in pattern.languages and "config" not in pattern.languages:
                if language not in {"yaml", "json", "xml", "dockerfile"}:
                    continue
        for match in compiled.finditer(text):
            line_no = text[: match.start()].count("\n") + 1
            line_text = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else match.group(0)
            groups = {k: v for k, v in match.groupdict().items() if v}
            key = (pattern.algorithm, line_no, line_text[:80])
            if key in seen:
                continue
            seen.add(key)
            detections.append(
                Detection(
                    algorithm=pattern.algorithm,
                    file=str(path),
                    line=line_no,
                    evidence=line_text[:240],
                    language=language,
                    library=pattern.library or _libraries_in(text),
                    key_size=_infer_key_size(pattern.algorithm, line_text + " " + text[:400], groups),
                    curve=_infer_curve(line_text, groups),
                    mode=_infer_mode(line_text),
                    protocol=pattern.protocol,
                    source_type="certificate" if language == "certificate" else "source",
                )
            )
    if language == "python":
        detections.extend(_python_ast_detections(path, text))
    # de-dupe after AST
    unique: dict[tuple[str, int, str], Detection] = {}
    for item in detections:
        unique[(item.algorithm, item.line, item.evidence[:80])] = item
    return list(unique.values())


PRIVATE_KEY_RE = re.compile(r"BEGIN [A-Z ]*PRIVATE KEY")


def detect_private_key_marker(path: Path, text: str) -> Detection | None:
    if PRIVATE_KEY_RE.search(text):
        return Detection(
            algorithm="PrivateKeyMaterial",
            file=str(path),
            line=1,
            evidence="[redacted: private key material omitted]",
            language=language_for(path),
            source_type="secret",
        )
    return None
