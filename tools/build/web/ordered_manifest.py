"""Pure ordered-manifest validation and rendering for generated web assets."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class OrderedManifest:
    manifest: Path
    source_root: Path
    output: Path
    suffix: str
    label: str
    separator: str = ""
    strip_trailing: bool = False
    trailing_newline: bool = False

    def entries(self, repository_root: Path) -> list[Path]:
        if not self.manifest.is_file():
            raise ValueError(
                f"missing {self.label} manifest: {self.manifest.relative_to(repository_root)}"
            )
        names = [
            line.strip()
            for line in self.manifest.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if not names:
            raise ValueError(f"{self.label} manifest must contain at least one source")
        if len(names) != len(set(names)):
            raise ValueError(f"{self.label} manifest contains duplicate sources")

        entries: list[Path] = []
        for name in names:
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts or relative.suffix != self.suffix:
                raise ValueError(f"invalid {self.label} manifest entry: {name}")
            source = self.source_root / relative
            if not source.is_file():
                raise ValueError(
                    f"missing {self.label} source: {source.relative_to(repository_root)}"
                )
            entries.append(source)
        return entries

    def render(self, repository_root: Path) -> str:
        modules = [source.read_text(encoding="utf-8") for source in self.entries(repository_root)]
        if self.strip_trailing:
            modules = [module.rstrip() for module in modules]
        rendered = self.separator.join(modules)
        return rendered + "\n" if self.trailing_newline else rendered

    def is_current(self, content: str) -> bool:
        return self.output.is_file() and self.output.read_text(encoding="utf-8") == content

    def write(self, content: str) -> None:
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_text(content, encoding="utf-8")


def render_all(
    manifests: Iterable[OrderedManifest], repository_root: Path
) -> list[tuple[OrderedManifest, str]]:
    return [(manifest, manifest.render(repository_root)) for manifest in manifests]


def run_manifest_builder(
    manifests: Iterable[OrderedManifest],
    repository_root: Path,
    *,
    check_message: str,
    stale_message: str | None = None,
) -> int:
    """Run the common check-or-write workflow for generated web assets."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    try:
        rendered = render_all(tuple(manifests), repository_root)
    except ValueError as error:
        print(f"ERROR: {error}")
        return 1

    if args.check:
        stale = [manifest for manifest, content in rendered if not manifest.is_current(content)]
        if stale:
            if stale_message is not None and len(stale) == 1:
                print(f"ERROR: {stale_message}")
            else:
                for manifest in stale:
                    relative = manifest.output.relative_to(repository_root)
                    print(f"ERROR: stale generated asset: {relative}")
            return 1
        print(check_message)
        return 0

    for manifest, content in rendered:
        manifest.write(content)
        print(f"Wrote {manifest.output.relative_to(repository_root)}")
    return 0
