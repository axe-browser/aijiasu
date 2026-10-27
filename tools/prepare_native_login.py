#!/usr/bin/env python3
"""Prepare a private login compatibility profile without running the reference client."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import stat
import struct
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
SUPPORTED_SHA256 = "08fcd8668f7aaf6660277778e67fd2afd622c3f1c8fb634e57f31605bf01c8f6"
SEED_ADDRESS = 0x693080
MODULUS_ADDRESS = 0x68F548
EXPONENT_ADDRESS = 0x68F67E
CORE_VERSION_ADDRESS = 0x692860
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_SEED_BYTES = 4096


def verified_reference(artifact: Path) -> bytes:
    """Bind every extracted field to the analyzed reference, without executing it."""
    if not artifact.is_file() or artifact.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ValueError("参考文件必须是支持版本的普通 Linux amd64 客户端。")
    with artifact.open("rb") as source:
        data = source.read(MAX_ARTIFACT_BYTES + 1)
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("参考文件必须是支持版本的普通 Linux amd64 客户端。")
    if hashlib.sha256(data).hexdigest() != SUPPORTED_SHA256:
        raise ValueError("参考文件与已分析的 Linux amd64 4.3.0.1 不匹配，拒绝提取。")
    if data[:6] != b"\x7fELF\x02\x01" or len(data) < 64:
        raise ValueError("参考文件的 ELF 格式不受支持。")
    return data


def read_reference_string(data: bytes, target_address: int) -> str:
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if size < 56 or offset + size * count > len(data):
        raise ValueError("参考文件的 ELF 映射无效。")
    for index in range(count):
        kind, _, file_offset, address, _, file_size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, offset + index * size
        )
        if kind != 1 or not address <= target_address < address + file_size:
            continue
        start = file_offset + target_address - address
        limit = min(file_offset + file_size, start + MAX_SEED_BYTES + 1, len(data))
        end = data.find(b"\0", start, limit)
        if end <= start or end - start > MAX_SEED_BYTES:
            raise ValueError("参考版本的兼容参数边界无效。")
        try:
            return data[start:end].decode("utf-8")
        except UnicodeError:
            raise ValueError("参考版本的兼容参数编码不受支持。") from None
    raise ValueError("未找到参考版本的兼容参数映射。")


def extract_seed(artifact: Path) -> str:
    return read_reference_string(verified_reference(artifact), SEED_ADDRESS)


def checksum(value: str) -> str:
    a, b = 0xDEADBEEF, 0xCAFEBABE
    for character in value.encode("ascii"):
        a = (a ^ ((a << 5) + character + (a >> 2))) & 0xFFFFFFFF
        b = (character + (b << 6) + (b << 16) - b) & 0xFFFFFFFF
    return bytes(
        byte for shift in (24, 16, 8, 0)
        for byte in ((a >> shift) & 0xFF, (b >> shift) & 0xFF)
    ).hex()


def default_directory() -> Path:
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / "aijiasu-native"
    if platform.system() == "Windows":
        configured = os.environ.get("APPDATA")
        if not configured:
            raise ValueError("Windows 未设置 APPDATA；请使用 aijiasu-native init 初始化私密配置。")
        return Path(configured) / "aijiasu-native"
    configured = os.environ.get("XDG_CONFIG_HOME")
    return (Path(configured) if configured else Path.home() / ".config") / "aijiasu-native"


def prepare(artifact: Path, directory: Path, transport_only: bool = False) -> Path:
    if platform.system() == "Windows":
        raise ValueError("Windows 请使用 aijiasu-native init 初始化配置，以验证当前用户的私密访问权限。")
    directory = directory.expanduser().absolute()
    if directory.resolve().is_relative_to(ROOT):
        raise ValueError("私密兼容配置必须保存在仓库目录之外。")
    target = directory / ("transport.json" if transport_only else "compatibility.json")
    if target.exists() or target.is_symlink():
        raise FileExistsError("兼容配置已存在，拒绝覆盖。")
    data = verified_reference(artifact)
    seed = "" if transport_only else read_reference_string(data, SEED_ADDRESS)
    if directory.is_symlink():
        raise ValueError("私密配置目录不能是符号链接。")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.stat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("私密配置目录不能向其他用户开放访问。")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise ValueError("私密配置目录必须属于当前用户。")

    milliseconds = time.monotonic_ns() // 1_000_000
    uid_prefix = (
        f"{(milliseconds // 1000) & 0xFFFFFFFF:08x}{milliseconds & 0xFF:02x}"
        f"{int.from_bytes(secrets.token_bytes(4), 'little'):08x}"
    )
    profile = {
        "version": 1,
        "endpoint": "https://login.ajs-app.com/client.php",
        "client_version": "4.3.0.1",
        "signing_seed": seed,
        "common_parameters": {
            "v": "4.3.0.1", "_site": "ajs", "_lang": "en", "_m": "linux",
            "_os_ver": f"{platform.system()} {platform.release()}",
            "_os_dev": platform.machine(),
            "_os_dim": "lid=" + secrets.token_hex(16),
            "_uid": uid_prefix + checksum(uid_prefix)[:4],
        },
    }
    if transport_only:
        modulus = read_reference_string(data, MODULUS_ADDRESS)
        exponent = read_reference_string(data, EXPONENT_ADDRESS)
        core_version = read_reference_string(data, CORE_VERSION_ADDRESS)
        if (not modulus.isascii() or not modulus.isdecimal() or
                int(modulus).bit_length() != 1024 or int(modulus) % 2 != 1 or
                exponent != "65537" or core_version != "20260525-1"):
            raise ValueError("参考版本的传输公开参数无效。")
        profile = {"version": 1, "core_version": core_version,
                   "rsa_modulus": modulus, "rsa_exponent": exponent}
    descriptor, temporary = tempfile.mkstemp(prefix=".native-profile-", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(profile, output, ensure_ascii=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        # An exclusive hard link publishes the complete file without replacing a
        # concurrently created profile; the temporary file already has mode 0600.
        os.link(temporary, target)
    finally:
        os.unlink(temporary)
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, type=Path,
                        help="已校验的官方 Linux amd64 4.3.0.1 可执行文件；仅用于一次性准备")
    parser.add_argument("--config-dir", type=Path,
                        help="仓库外的私密配置目录，已有配置不会被覆盖")
    parser.add_argument("--transport-only", action="store_true",
                        help="仅准备传输公开参数 transport.json，保留现有登录配置及安装标识")
    args = parser.parse_args()
    try:
        directory = args.config_dir if args.config_dir is not None else default_directory()
        output = prepare(args.reference, directory, args.transport_only)
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f"准备失败：{error}\n")
    print(f"已准备私密兼容配置：{output}")
    print("原生命令运行时无需参考客户端或 Python；配置不包含账号密码。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
