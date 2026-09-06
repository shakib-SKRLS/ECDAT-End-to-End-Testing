from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from scanner.common.base import BaseScanner
from scanner.common.detector import detect_in_text, detect_private_key_marker
from scanner.common.types import SKIP_DIRS, Detection, language_for


class SourceCodeScanner(BaseScanner):
    name = "source"

    def __init__(self, max_files: int = 20_000, max_file_bytes: int = 1_048_576, workers: int = 8) -> None:
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.workers = max(1, workers)

    def _iter_files(self, root: Path) -> list[Path]:
        files: list[Path] = []
        for path in root.rglob("*"):
            if len(files) >= self.max_files:
                break
            if not path.is_file():
                continue
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.stat().st_size > self.max_file_bytes:
                continue
            if language_for(path) == "unknown" and path.suffix.lower() not in {".txt", ".md"}:
                continue
            files.append(path)
        return files

    def _scan_file(self, path: Path, root: Path) -> list[Detection]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        detections = detect_in_text(path, text)
        marker = detect_private_key_marker(path, text)
        if marker:
            detections.append(marker)
        rel = str(path.relative_to(root)).replace("\\", "/")
        for item in detections:
            item.file = rel
        return detections

    def scan(self, root: Path) -> list[Detection]:
        files = self._iter_files(root)
        results: list[Detection] = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._scan_file, path, root): path for path in files}
            for future in as_completed(futures):
                results.extend(future.result())
        return results
