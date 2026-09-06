"""Policy helpers enforcing generated KasSee runtime ownership."""

from __future__ import annotations

from pathlib import Path


def check_web_pkg_policy(root: Path) -> list[str]:
    """Keep target/ canonical while permitting an ignored local web/pkg mirror."""
    errors: list[str] = []
    builder = (root / "tools/build/web/build_kassee_runtime.py").read_text(errors="ignore")
    if "target/kassee-web/site" not in builder:
        errors.append("Canonical KasSee runtime builder must stage the deployable site under target/kassee-web/site")
    if 'shutil.rmtree(authored / "pkg"' not in builder:
        errors.append("Canonical KasSee runtime builder must remove stale local web/pkg before staging")
    if "sync_local_web_package(site)" not in builder:
        errors.append("Canonical KasSee runtime builder must mirror fresh bindings into local web/pkg")

    inventory = (root / "qa/checks/architecture/core/inventory/repository_inventory.py").read_text(errors="ignore")
    common = (root / "qa/checks/architecture/core/common.py").read_text(errors="ignore")
    generated_prefix = 'Path("apps/kassee-web/web/pkg")'
    if generated_prefix not in inventory:
        errors.append("Generated local KasSee web/pkg must be excluded from repository inventory/source archives")
    if generated_prefix not in common:
        errors.append("Generated local KasSee web/pkg must be excluded from authored source-quality scans")

    for facade in (root / "apps/kassee-web/build.sh", root / "apps/kassee-web/build.ps1"):
        if "build_kassee_runtime.py" not in facade.read_text(errors="ignore"):
            errors.append(f"KasSee build facade must delegate to canonical builder: {facade.relative_to(root)}")
    return errors
