"""Architecture contract for platform-native Make dispatch targets."""
from __future__ import annotations

import ast
from pathlib import Path

PLATFORMS = (("linux", ".sh"), ("windows", ".ps1"))


def _mapping(path: Path) -> dict[str, str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == "ENTRYPOINTS" for target in node.targets):
                value = ast.literal_eval(node.value)
                if isinstance(value, dict) and all(
                    isinstance(key, str) and isinstance(item, str) for key, item in value.items()
                ):
                    return value
                raise ValueError(f"{path}: ENTRYPOINTS must be a literal str->str mapping")
    raise ValueError(f"{path}: ENTRYPOINTS mapping is missing")


def check(root: Path) -> list[str]:
    errors: list[str] = []
    dispatcher = root / "scripts/common/lib/make_tasks.py"
    if not dispatcher.is_file():
        return [f"shared Make dispatcher is missing: {dispatcher.relative_to(root)}"]
    try:
        mapping = _mapping(dispatcher)
    except (SyntaxError, ValueError) as error:
        return [str(error)]
    for platform, suffix in PLATFORMS:
        for entry, relative in sorted(mapping.items()):
            target = root / f"scripts/{platform}/{relative}{suffix}"
            if not target.is_file():
                errors.append(
                    f"native Make entrypoint {entry!r} resolves to missing source file "
                    f"{target.relative_to(root)}"
                )
    return errors
