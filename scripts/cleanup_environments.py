from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable


try:
    import psutil  # type: ignore
except Exception:
    psutil = None


VENV_DIR_NAMES = {"venv", ".venv", "env"}
SKIP_DIR_NAMES = {
    ".git",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".next",
    "dist",
    "build",
}


@dataclass
class EnvEntry:
    kind: str
    name: str
    path: Path
    last_used: datetime
    size_bytes: int
    current_project: bool
    active_process: bool


@dataclass
class DeletionResult:
    path: Path
    success: bool
    freed_bytes: int
    message: str


def run_command(cmd: list[str]) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"


def format_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.1f}{unit}"
        value /= 1024.0
    return f"{size}B"


def format_dt(value: datetime) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M")


def dir_size(path: Path) -> int:
    total = 0
    try:
        for root, dirs, files in os.walk(path, topdown=True):
            dirs[:] = [d for d in dirs if d not in SKIP_DIR_NAMES]
            for filename in files:
                file_path = Path(root) / filename
                try:
                    total += file_path.stat().st_size
                except OSError:
                    continue
    except OSError:
        return 0
    return total


def dir_last_used(path: Path) -> datetime:
    latest = datetime.fromtimestamp(path.stat().st_atime, tz=timezone.utc)
    try:
        for root, dirs, files in os.walk(path, topdown=True):
            dirs[:] = [d for d in dirs if d not in SKIP_DIR_NAMES]
            for name in dirs + files:
                item = Path(root) / name
                try:
                    ts = max(item.stat().st_atime, item.stat().st_mtime)
                    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                    if dt > latest:
                        latest = dt
                except OSError:
                    continue
    except OSError:
        pass
    return latest


def is_under(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except Exception:
        return False


def process_uses_path(target: Path) -> bool:
    if psutil is None:
        return False
    target_resolved = target.resolve()
    for proc in psutil.process_iter(["pid", "name", "cwd", "exe"]):
        try:
            info = proc.info
            for key in ("cwd", "exe"):
                p = info.get(key)
                if not p:
                    continue
                if is_under(Path(p), target_resolved):
                    return True
            for opened in proc.open_files() or []:
                if is_under(Path(opened.path), target_resolved):
                    return True
        except Exception:
            continue
    return False


def find_node_modules(roots: Iterable[Path], cwd: Path, active_env_paths: set[Path]) -> list[EnvEntry]:
    entries: list[EnvEntry] = []
    for root in roots:
        if not root.exists():
            continue
        for current_root, dirs, _files in os.walk(root, topdown=True):
            if Path(current_root).name in SKIP_DIR_NAMES:
                dirs[:] = []
                continue
            if "node_modules" in dirs:
                nm_path = Path(current_root) / "node_modules"
                dirs.remove("node_modules")
                current_project = is_under(nm_path, cwd) or nm_path in active_env_paths
                active_process = process_uses_path(nm_path)
                entries.append(
                    EnvEntry(
                        kind="node_modules",
                        name=nm_path.parent.name,
                        path=nm_path,
                        last_used=dir_last_used(nm_path),
                        size_bytes=dir_size(nm_path),
                        current_project=current_project,
                        active_process=active_process,
                    )
                )
            dirs[:] = [d for d in dirs if d not in SKIP_DIR_NAMES]
    return entries


def looks_like_venv(path: Path) -> bool:
    if (path / "pyvenv.cfg").exists():
        return True
    if (path / "Scripts" / "python.exe").exists():
        return True
    if (path / "bin" / "python").exists():
        return True
    return False


def find_python_venvs(roots: Iterable[Path], cwd: Path, active_env_paths: set[Path]) -> list[EnvEntry]:
    entries: list[EnvEntry] = []
    for root in roots:
        if not root.exists():
            continue
        for current_root, dirs, _files in os.walk(root, topdown=True):
            cur = Path(current_root)
            for dirname in list(dirs):
                if dirname in VENV_DIR_NAMES:
                    candidate = cur / dirname
                    if looks_like_venv(candidate):
                        current_project = is_under(candidate, cwd) or candidate in active_env_paths
                        active_process = process_uses_path(candidate)
                        entries.append(
                            EnvEntry(
                                kind="python_venv",
                                name=candidate.parent.name,
                                path=candidate,
                                last_used=dir_last_used(candidate),
                                size_bytes=dir_size(candidate),
                                current_project=current_project,
                                active_process=active_process,
                            )
                        )
                    dirs.remove(dirname)
            dirs[:] = [d for d in dirs if d not in SKIP_DIR_NAMES]
    return entries


def find_conda_envs(cwd: Path, active_env_paths: set[Path]) -> list[EnvEntry]:
    entries: list[EnvEntry] = []
    code, out, _err = run_command(["conda", "env", "list", "--json"])
    if code != 0:
        return entries
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        return entries

    for env_path_raw in payload.get("envs", []):
        env_path = Path(env_path_raw)
        if not env_path.exists():
            continue
        current_project = is_under(env_path, cwd) or env_path in active_env_paths
        active_process = process_uses_path(env_path)
        entries.append(
            EnvEntry(
                kind="conda_env",
                name=env_path.name,
                path=env_path,
                last_used=dir_last_used(env_path),
                size_bytes=dir_size(env_path),
                current_project=current_project,
                active_process=active_process,
            )
        )
    return entries


def find_global_npm_packages() -> list[tuple[str, str]]:
    code, out, _err = run_command(["npm", "ls", "-g", "--depth=0", "--json"])
    if code != 0 or not out:
        return []
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        return []
    deps = payload.get("dependencies", {}) or {}
    return sorted((name, meta.get("version", "?")) for name, meta in deps.items())


def eligible_for_deletion(entry: EnvEntry, cutoff: datetime, cwd: Path) -> tuple[bool, str]:
    if entry.current_project or is_under(entry.path, cwd):
        return False, "Used by current project"
    if entry.active_process:
        return False, "Active process is using it"
    if entry.last_used > cutoff:
        return False, "Recently used"
    return True, "Unused > 30 days"


def ask_yes_no(prompt: str, default_no: bool = True) -> bool:
    suffix = " [y/N]: " if default_no else " [Y/n]: "
    value = input(prompt + suffix).strip().lower()
    if not value:
        return not default_no
    return value in {"y", "yes"}


def delete_entry(entry: EnvEntry) -> DeletionResult:
    size = entry.size_bytes
    if entry.kind == "conda_env":
        code, _out, err = run_command(["conda", "env", "remove", "-p", str(entry.path), "-y"])
        if code == 0:
            return DeletionResult(entry.path, True, size, "Removed with conda")
        return DeletionResult(entry.path, False, 0, f"Conda remove failed: {err}")

    try:
        shutil.rmtree(entry.path)
        return DeletionResult(entry.path, True, size, "Removed directory")
    except Exception as exc:
        return DeletionResult(entry.path, False, 0, f"Delete failed: {exc}")


def print_report(entries: list[EnvEntry], cutoff: datetime, cwd: Path) -> list[EnvEntry]:
    print("\nDetected environments:\n")
    if not entries:
        print("No environments found in scanned roots.")
        return []

    removable: list[EnvEntry] = []
    for idx, entry in enumerate(sorted(entries, key=lambda e: e.path.as_posix()), start=1):
        eligible, reason = eligible_for_deletion(entry, cutoff, cwd)
        if eligible:
            removable.append(entry)
        status = "UNUSED" if eligible else "KEEP"
        print(
            f"[{idx}] {entry.kind} | {entry.path}\n"
            f"    Last used: {format_dt(entry.last_used)} | Size: {format_bytes(entry.size_bytes)} | {status} ({reason})"
        )
    return removable


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely clean unused local Node/Python environments.")
    parser.add_argument(
        "--roots",
        nargs="*",
        help="Directories to scan. Default: user home directory.",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Unused threshold in days. Default: 30",
    )
    args = parser.parse_args()

    cwd = Path.cwd().resolve()
    home = Path.home().resolve()
    roots = [Path(p).resolve() for p in args.roots] if args.roots else [home]

    active_env_paths: set[Path] = set()
    for env_var in ("VIRTUAL_ENV", "CONDA_PREFIX"):
        val = os.environ.get(env_var)
        if val:
            active_env_paths.add(Path(val).resolve())

    cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)

    print("Scanning environments...")
    entries: list[EnvEntry] = []
    entries.extend(find_node_modules(roots, cwd, active_env_paths))
    entries.extend(find_python_venvs(roots, cwd, active_env_paths))
    entries.extend(find_conda_envs(cwd, active_env_paths))

    removable = print_report(entries, cutoff, cwd)

    npm_globals = find_global_npm_packages()
    if npm_globals:
        print("\nGlobal npm packages detected:")
        for name, version in npm_globals:
            print(f"- {name}@{version}")

    if psutil is None:
        print("\nNote: psutil not installed, active process detection is limited.")

    if not removable:
        print("\nNo removable environments matched the unused criteria.")
    else:
        print(f"\nRemovable environments: {len(removable)}")
        if ask_yes_no("Proceed with interactive deletion prompts?", default_no=True):
            results: list[DeletionResult] = []
            for entry in removable:
                if ask_yes_no(f"Delete {entry.path}?", default_no=True):
                    results.append(delete_entry(entry))
                else:
                    results.append(DeletionResult(entry.path, False, 0, "Skipped by user"))

            total_freed = sum(r.freed_bytes for r in results if r.success)
            removed = [r for r in results if r.success]
            kept = [r for r in results if not r.success]

            print("\nDeletion summary:")
            print(f"- Environments removed: {len(removed)}")
            print(f"- Remaining/skipped: {len(kept)}")
            print(f"- Total space freed: {format_bytes(total_freed)}")
            for result in results:
                status = "REMOVED" if result.success else "KEPT"
                print(f"  - {status}: {result.path} ({result.message})")

    if ask_yes_no("Run optional global npm prune? (npm prune -g)", default_no=True):
        code, out, err = run_command(["npm", "prune", "-g"])
        print(out if code == 0 else err)

    if ask_yes_no("Run optional npm cache clean? (npm cache clean --force)", default_no=True):
        code, out, err = run_command(["npm", "cache", "clean", "--force"])
        print(out if code == 0 else err)

    if ask_yes_no("Run optional pip cache purge? (pip cache purge)", default_no=True):
        code, out, err = run_command(["pip", "cache", "purge"])
        print(out if code == 0 else err)

    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
