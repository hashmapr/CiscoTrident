"""Ghost app: a background-agent copy of Packet Tracer.

The stock installation registers a Dock icon and can take focus when it opens a
file. Neither is acceptable for unattended operation, so this module builds a
*separate* copy of the bundle with ``LSUIElement`` set. macOS then treats it as a
background agent (``type="UIElement"``): no Dock icon, no Cmd-Tab entry, no
window, and no focus stealing.

Measured on Packet Tracer 9.0.1.0858:

  stock bundle, --no-gui                    0 windows, but a Dock icon exists
  stock bundle, fileOpen                    0 windows, focus moves to PacketTracer
  ghost bundle, fileOpen after setVisible    0 windows, focus unchanged
                                            type="UIElement", lab still loads

Design rules:

* The original installation is **never modified**. It is only read.
* The copy is made with ``clonefile`` where the filesystem supports it, so a
  1.2 GB bundle costs almost no disk.
* The copy is ad-hoc signed after editing ``Info.plist``. Editing the plist
  invalidates Cisco's signature and macOS refuses to launch an app whose
  signature no longer matches, so re-signing is required for the copy to run at
  all. This is re-signing *our own copy*; it does not touch or bypass Cisco's
  protection on the installed product.
* Nothing here disables Gatekeeper, quarantine, or any OS protection.
"""

from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_GHOST_DIR = Path.home() / ".local" / "share" / "trident" / "ghost-app"
GHOST_NAME = "PTGhost.app"


class GhostError(RuntimeError):
    """The ghost copy could not be created or validated."""


@dataclass(frozen=True)
class GhostApp:
    """A prepared background-agent copy of Packet Tracer."""

    path: Path
    source: Path
    version: str
    re_signed: bool
    cloned: bool

    @property
    def executable(self) -> Path:
        return self.path / "Contents" / "MacOS" / "PacketTracer"

    def is_usable(self) -> bool:
        return self.executable.is_file() and _has_lsui_element(self.path)


def _has_lsui_element(bundle: Path) -> bool:
    plist = bundle / "Contents" / "Info.plist"
    try:
        with open(plist, "rb") as handle:
            data = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException):
        return False
    return data.get("LSUIElement") is True


def _bundle_version(bundle: Path, source: Path | None = None) -> str:
    """Version of the bundle, preferring the source name over the copy's.

    The ghost copy is named ``PTGhost.app``, so the version has to come from the
    original bundle's directory name or its plist.
    """
    import re

    for candidate in (source, bundle):
        if candidate is None:
            continue
        match = re.search(r"(\d+\.\d+\.\d+)", candidate.name)
        if match:
            return match.group(1)
    try:
        with open(bundle / "Contents" / "Info.plist", "rb") as handle:
            data = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException):
        return "unknown"
    for key in ("CFBundleShortVersionString", "CFBundleVersion"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown"


def _clone_or_copy(source: Path, target: Path) -> bool:
    """Copy the bundle, using an APFS clone when possible.

    Returns ``True`` when a clone was made (near-zero additional disk).
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise GhostError(f"refusing to overwrite an existing ghost app at {target}")

    # clonefile keeps the copy on the same volume and shares blocks.
    try:
        result = subprocess.run(
            ["cp", "-Rc", str(source), str(target)],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GhostError(f"copy failed: {exc}") from exc
    if result.returncode == 0 and target.is_dir():
        return True

    # Fall back to a plain copy. This costs real disk, so make it explicit.
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    try:
        shutil.copytree(source, target, symlinks=True)
    except (OSError, shutil.Error) as exc:
        raise GhostError(f"copy failed: {exc}") from exc
    return False


def _set_background_agent(bundle: Path) -> None:
    plist = bundle / "Contents" / "Info.plist"
    try:
        with open(plist, "rb") as handle:
            data = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException) as exc:
        raise GhostError(f"cannot read {plist}: {exc}") from exc
    data["LSUIElement"] = True
    data["LSBackgroundOnly"] = False
    try:
        with open(plist, "wb") as handle:
            plistlib.dump(data, handle)
    except OSError as exc:
        raise GhostError(f"cannot write {plist}: {exc}") from exc


def _ad_hoc_sign(bundle: Path) -> bool:
    """Re-sign the copy so macOS will launch it.

    Editing Info.plist invalidates the original signature and macOS then refuses
    to run the bundle. Re-signing our copy restores a valid local signature.
    """
    try:
        result = subprocess.run(
            ["codesign", "--force", "--deep", "--sign", "-", str(bundle)],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def install_extensions(source: Path, target: Path) -> int:
    """Copy any ExApp meta files so the ghost copy can authenticate."""
    source_dir = source / "Contents" / "extensions"
    target_dir = target / "Contents" / "extensions"
    if not source_dir.is_dir():
        return 0
    target_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    for entry in source_dir.iterdir():
        if entry.suffix.lower() != ".pta":
            continue
        destination = target_dir / entry.name
        shutil.copyfile(entry, destination)
        os.chmod(destination, 0o644)
        copied += 1
    return copied


def build(
    source: Path,
    ghost_dir: Path | None = None,
    force: bool = False,
) -> GhostApp:
    """Create the background-agent copy, or return an existing usable one."""
    if not (source / "Contents" / "MacOS" / "PacketTracer").is_file():
        raise GhostError(f"{source} is not a usable Packet Tracer bundle")

    base = (ghost_dir or DEFAULT_GHOST_DIR).expanduser()
    target = base / GHOST_NAME

    if target.exists():
        if force:
            shutil.rmtree(target, ignore_errors=True)
        elif _has_lsui_element(target) and (target / "Contents/MacOS/PacketTracer").is_file():
            return GhostApp(
                path=target,
                source=source,
                version=_bundle_version(target, source),
                re_signed=False,
                cloned=False,
            )
        else:
            raise GhostError(
                f"a ghost app already exists at {target} but is not a background "
                "agent; pass force=True to rebuild it"
            )

    cloned = _clone_or_copy(source, target)
    # Record where the copy came from. The copy's own name (PTGhost.app) carries
    # no version, so without this every observation's provenance would say
    # "unknown" instead of the real Packet Tracer version.
    try:
        (target / ".trident-source").write_text(str(source))
    except OSError:
        pass
    _set_background_agent(target)
    re_signed = _ad_hoc_sign(target)
    install_extensions(source, target)

    if not (target / "Contents/MacOS/PacketTracer").is_file():
        raise GhostError(f"ghost app is incomplete at {target}")
    if not _has_lsui_element(target):
        raise GhostError("LSUIElement was not applied; the copy would show a Dock icon")

    return GhostApp(
        path=target,
        source=source,
        version=_bundle_version(target, source),
        re_signed=re_signed,
        cloned=cloned,
    )


def remove(ghost_dir: Path | None = None) -> str:
    """Delete the ghost copy. The original installation is untouched."""
    target = (ghost_dir or DEFAULT_GHOST_DIR).expanduser() / GHOST_NAME
    if not target.exists():
        return "ALREADY_GONE"
    shutil.rmtree(target, ignore_errors=True)
    return "REMOVED" if not target.exists() else "FAILED"


def main(argv: list[str] | None = None) -> int:
    import argparse

    from .backends import find_packet_tracer, live_allowed

    parser = argparse.ArgumentParser(
        prog="trident.simulator.ghost",
        description=(
            "Build a background-agent copy of Packet Tracer: no Dock icon, no "
            "window, no focus stealing. The original installation is never modified."
        ),
    )
    parser.add_argument("--source", default=None, help="Packet Tracer bundle to copy")
    parser.add_argument("--dir", default=None, help="where to build the ghost copy")
    parser.add_argument("--force", action="store_true", help="rebuild an existing copy")
    parser.add_argument("--remove", action="store_true", help="delete the ghost copy")
    parser.add_argument("--status", action="store_true", help="report the current copy")
    args = parser.parse_args(argv)

    if args.remove:
        print(f"ghost app: {remove(Path(args.dir) if args.dir else None)}")
        return 0

    base = Path(args.dir).expanduser() if args.dir else DEFAULT_GHOST_DIR
    existing = base / GHOST_NAME
    if args.status:
        if not existing.exists():
            print(f"no ghost app at {existing}")
            return 1
        usable = _has_lsui_element(existing) and (
            existing / "Contents/MacOS/PacketTracer"
        ).is_file()
        print(
            f"{existing}\n  background agent: {_has_lsui_element(existing)}\n"
            f"  executable present: {(existing / 'Contents/MacOS/PacketTracer').is_file()}\n"
            f"  usable: {usable}"
        )
        return 0 if usable else 1

    source = Path(args.source).expanduser() if args.source else find_packet_tracer()
    if source is None:
        print("Packet Tracer not found; pass --source")
        return 2

    try:
        ghost = build(source, base, force=args.force)
    except GhostError as exc:
        print(f"ghost build failed: {exc}")
        return 3

    print(f"ghost app ready: {ghost.path}")
    print(f"  source:      {ghost.source}")
    print(f"  version:     {ghost.version}")
    print(f"  cloned:      {ghost.cloned}")
    print(f"  re-signed:   {ghost.re_signed}")
    print(f"  background:  {_has_lsui_element(ghost.path)}")
    if not live_allowed():
        print(
            "\nnote: TRIDENT_ALLOW_LIVE_SIMULATOR is not set, so TRIDENT will not "
            "start it automatically. The copy is ready either way."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
