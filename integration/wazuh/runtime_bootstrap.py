"""Run Ansible from one sealed package tree, without Python site processing.

The canonical release launchers execute this file with ``python3 -I -S -B``.
Only the operating system's standard library and the release's Python tree
may satisfy imports. This file is copied, not imported, into each release.
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import importlib.metadata
from pathlib import Path
import re
import sys
import sysconfig


REQUIRED_CORE = "2.21.2"
REQUIRED = ("ansible", "yaml", "jinja2", "cryptography", "packaging", "resolvelib")


def within(path: str, root: Path) -> bool:
    return Path(path).resolve().is_relative_to(root)


def global_site_within_stdlib(path: str, standard: Path) -> bool:
    resolved = Path(path).resolve()
    if not resolved.is_relative_to(standard):
        return False
    return any(part in ("site-packages", "dist-packages")
               for part in resolved.relative_to(standard).parts)


class SealedPathFinder(importlib.abc.MetaPathFinder):
    def __init__(self, roots: tuple[Path, ...], standard: Path):
        self.roots = roots
        self.standard = standard

    def allowed(self, path: str) -> bool:
        return (not global_site_within_stdlib(path, self.standard)
                and any(within(path, root) for root in self.roots))

    def find_spec(self, fullname, path=None, target=None):
        spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
        if spec is None:
            return None
        if spec.origin not in (None, "built-in", "frozen") and not self.allowed(spec.origin):
            raise ImportError("module outside sealed Python runtime")
        locations = spec.submodule_search_locations or ()
        if any(not self.allowed(location) for location in locations):
            raise ImportError("package outside sealed Python runtime")
        return spec


class SealedDistributionFinder(importlib.metadata.DistributionFinder):
    """Expose release-local distribution metadata without consulting sys.path."""

    def __init__(self, package_root: Path):
        self.package_root = package_root.resolve()

    def find_spec(self, fullname, path=None, target=None):
        return None

    def find_distributions(self, context=importlib.metadata.DistributionFinder.Context()):
        requested = context.name
        normalized = (re.sub(r"[-_.]+", "-", requested).lower()
                      if requested is not None else None)
        for candidate in self.package_root.iterdir():
            if not candidate.name.endswith((".dist-info", ".egg-info")):
                continue
            if not candidate.is_dir() or not within(candidate, self.package_root):
                continue
            distribution = importlib.metadata.PathDistribution(candidate)
            name = distribution.metadata.get("Name")
            if name is None:
                continue
            if normalized is None or re.sub(r"[-_.]+", "-", name).lower() == normalized:
                yield distribution


def configure_runtime(package_root: Path) -> None:
    if not sys.flags.isolated or not sys.flags.no_site:
        raise RuntimeError("isolated Python without site processing required")
    if not package_root.is_absolute() or not package_root.is_dir():
        raise RuntimeError("release Python packages unavailable")
    standard = Path(sysconfig.get_paths()["stdlib"]).resolve()
    payload = package_root.parent.parent
    roots = (package_root.resolve(), (payload / "collections").resolve(),
             (payload / "plugins").resolve(), (payload / "ansible").resolve(), standard)
    # -I excludes cwd and PYTHONPATH; -S prevents global site/dist-packages
    # and .pth hooks. Explicitly keep only trusted stdlib import locations.
    sys.path[:] = [str(package_root)] + [entry for entry in sys.path
                                          if entry and within(entry, standard)
                                          and not global_site_within_stdlib(entry, standard)]
    sys.meta_path[:] = [importlib.machinery.BuiltinImporter,
                        importlib.machinery.FrozenImporter, SealedPathFinder(roots, standard),
                        SealedDistributionFinder(package_root)]


def verify_packages() -> None:
    package_root = Path(__file__).resolve().parent / "python"
    for name in REQUIRED:
        module = importlib.import_module(name)
        if not isinstance(getattr(module, "__file__", None), str) or not within(module.__file__, package_root):
            raise RuntimeError("required package outside sealed runtime")
    release = importlib.import_module("ansible.release")
    if not isinstance(getattr(release, "__file__", None), str) or not within(release.__file__, package_root):
        raise RuntimeError("Ansible release metadata outside sealed runtime")
    version = getattr(release, "__version__", "")
    if version != REQUIRED_CORE:
        raise RuntimeError("Ansible Core 2.21.2 required for this release")


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("playbook", "inventory"):
        raise RuntimeError("invalid sealed Ansible command")
    command = sys.argv.pop(1)
    package_root = Path(__file__).resolve().parent / "python"
    configure_runtime(package_root)
    verify_packages()
    if sys.argv[1:] == ["--preflight"]:
        return 0
    sys.argv[0] = "ansible-" + command
    module = importlib.import_module("ansible.cli." + command)
    return module.main()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ImportError, OSError, RuntimeError) as exc:
        print("sealed Ansible runtime rejected: " + str(exc), file=sys.stderr)
        raise SystemExit(2) from None
