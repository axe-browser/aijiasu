#!/usr/bin/env python3
"""Build standalone macOS, Linux and Windows release binaries on macOS."""

from __future__ import annotations

import argparse
import ctypes
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import uuid


ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = (
    ("darwin", "amd64", "macos"),
    ("darwin", "arm64", "macos"),
    ("linux", "amd64", "linux"),
    ("linux", "arm64", "linux"),
    ("windows", "amd64", "windows"),
    ("windows", "arm64", "windows"),
)
RENAME_EXCL = 0x00000004
RELEASE_TOOLCHAIN = "go1.26.10"


def publish_directory(staging: Path, output: Path) -> None:
    """Atomically publish on macOS without replacing any concurrent destination."""
    library = ctypes.CDLL(None, use_errno=True)
    try:
        rename = library.renamex_np
    except AttributeError:
        raise RuntimeError("当前 macOS 环境不支持排他发布目录。") from None
    rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    # os.rename may replace an existing empty directory. RENAME_EXCL makes the
    # final absence check and rename one operation, including concurrent builds.
    if rename(os.fsencode(staging), os.fsencode(output), RENAME_EXCL) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(output))


def build(version: str, output: Path | None = None) -> Path:
    if not re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("版本号应为 1.0.0 或 v1.0.0 格式。")
    version = version.removeprefix("v")
    if platform.system() != "Darwin":
        raise RuntimeError("构建完整发布产物需要 macOS 代码签名环境。")
    if output is None:
        output = Path(tempfile.gettempdir()) / f"aijiasu-native-release-{version}-{uuid.uuid4().hex[:8]}"
    output = output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"发布目录已存在，拒绝覆盖: {output}")
    with tempfile.TemporaryDirectory(prefix="aijiasu-native-release-build-") as temporary:
        staging = Path(temporary)
        assets: list[tuple[Path, bool]] = []
        for goos, goarch, asset_os in PLATFORMS:
            extension = ".exe" if goos == "windows" else ""
            executable = staging / f"aijiasu-native-{asset_os}-{goarch}{extension}"
            environment = {
                **os.environ, "CGO_ENABLED": "0", "GOOS": goos, "GOARCH": goarch,
                "GOTOOLCHAIN": RELEASE_TOOLCHAIN, "GOAMD64": "v1", "GOARM64": "v8.0",
                "GOFLAGS": "", "GOEXPERIMENT": "", "GOWORK": "off",
            }
            subprocess.run(
                ["go", "build", "-buildvcs=false", "-trimpath", f"-ldflags=-s -w -X main.version={version}",
                 "-o", str(executable), "./cmd/aijiasu-native"],
                cwd=ROOT, env=environment, check=True, timeout=300,
            )
            signed = goos == "darwin"
            if signed:
                subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(executable)],
                               check=True, timeout=30)
                subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(executable)],
                               check=True, timeout=30)
            assets.append((executable, signed))

        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".aijiasu-native-publish-", dir=output.parent) as temporary:
            publication = Path(temporary) / "release"
            publication.mkdir()
            for path, signed in assets:
                copied = publication / path.name
                shutil.copy2(path, copied)
                if signed:
                    subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(copied)],
                                   check=True, timeout=30)
            publish_directory(publication, output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="发布版本，如 1.0.0")
    parser.add_argument("--output", type=Path, help="新发布目录，默认创建在系统临时目录")
    args = parser.parse_args()
    try:
        result = build(args.version, args.output)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Release build failed: {error}\n")
    print(f"Release assets: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
