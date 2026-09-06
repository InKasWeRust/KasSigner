"""Shared helpers for firmware source contracts."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")

def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)
