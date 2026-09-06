from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from scanner.common.types import Detection


class BaseScanner(ABC):
    name = "base"

    @abstractmethod
    def scan(self, root: Path) -> list[Detection]:
        raise NotImplementedError
