from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "target",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
    "coverage",
    ".next",
    "out",
}

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".jsx": "javascript",
    ".java": "java",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cc": "c",
    ".cpp": "c",
    ".cxx": "c",
    ".hpp": "c",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".properties": "config",
    ".conf": "config",
    ".cnf": "config",
    ".cfg": "config",
    ".ini": "config",
    ".toml": "config",
    ".pem": "certificate",
    ".crt": "certificate",
    ".cer": "certificate",
    ".der": "certificate",
    ".dockerfile": "dockerfile",
}

CONFIG_NAMES = {
    "dockerfile": "dockerfile",
    "docker-compose.yml": "yaml",
    "docker-compose.yaml": "yaml",
    "sshd_config": "config",
    "nginx.conf": "config",
    "requirements.txt": "python",
    "go.mod": "go",
    "package.json": "json",
    "pom.xml": "xml",
    "build.gradle": "config",
}


def language_for(path: Path) -> str:
    name = path.name.lower()
    if name in CONFIG_NAMES:
        return CONFIG_NAMES[name]
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "unknown")


@dataclass
class Detection:
    algorithm: str
    file: str
    line: int
    evidence: str
    language: str
    library: str = ""
    key_size: int | None = None
    curve: str = ""
    mode: str = ""
    protocol: str = ""
    source_type: str = "source"
    extra: dict[str, str] = field(default_factory=dict)
