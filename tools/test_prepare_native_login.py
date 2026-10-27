"""Offline tests use a synthetic ELF and public placeholder signing material."""

import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import prepare_native_login as profile


def reference_bytes() -> bytes:
    data = bytearray(256)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 1)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 4, 128,
                     profile.SEED_ADDRESS, 0, 128, 128, 1)
    public_value = b"public-test-profile-material\0"
    data[128:128 + len(public_value)] = public_value
    return bytes(data)


def transport_reference_bytes() -> bytes:
    addresses = {
        profile.MODULUS_ADDRESS: str((1 << 1023) + 1),
        profile.EXPONENT_ADDRESS: "65537",
        profile.CORE_VERSION_ADDRESS: "20260525-1",
    }
    base = min(addresses)
    size = max(addresses) - base + 256
    data = bytearray(128 + size)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 1)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 4, 128,
                     base, 0, size, size, 1)
    for address, value in addresses.items():
        encoded = value.encode("ascii") + b"\0"
        start = 128 + address - base
        data[start:start + len(encoded)] = encoded
    return bytes(data)


class PrepareProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="native-profile-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.reference = self.directory / "reference"
        self.reference.write_bytes(reference_bytes())
        self.digest = hashlib.sha256(reference_bytes()).hexdigest()

    def test_default_directories_follow_native_user_configuration_locations(self) -> None:
        home = self.directory / "home"
        with patch.object(Path, "home", return_value=home):
            with patch.object(profile.platform, "system", return_value="Darwin"):
                self.assertEqual(profile.default_directory(), home / "Library" / "Application Support" / "aijiasu-native")
            with patch.object(profile.platform, "system", return_value="Linux"):
                with patch.dict(os.environ, {"XDG_CONFIG_HOME": ""}):
                    self.assertEqual(profile.default_directory(), home / ".config" / "aijiasu-native")
                with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.directory / "xdg")}):
                    self.assertEqual(profile.default_directory(), self.directory / "xdg" / "aijiasu-native")
            with patch.object(profile.platform, "system", return_value="Windows"):
                with patch.dict(os.environ, {"APPDATA": str(self.directory / "Roaming")}):
                    self.assertEqual(profile.default_directory(), self.directory / "Roaming" / "aijiasu-native")
                with patch.dict(os.environ, {"APPDATA": ""}):
                    with self.assertRaisesRegex(ValueError, "aijiasu-native init"):
                        profile.default_directory()

    def test_windows_preparation_requires_native_acl_initialization_without_writing(self) -> None:
        folder = self.directory / "windows-private"
        with patch.object(profile.platform, "system", return_value="Windows"):
            with patch.object(profile, "verified_reference") as reader:
                for transport_only in (False, True):
                    with self.subTest(transport_only=transport_only):
                        with self.assertRaisesRegex(ValueError, "aijiasu-native init"):
                            profile.prepare(self.reference, folder, transport_only)
                reader.assert_not_called()
        self.assertFalse(folder.exists())

    def test_digest_binding_rejects_unknown_artifact(self) -> None:
        with self.assertRaisesRegex(ValueError, "不匹配"):
            profile.extract_seed(self.reference)

    def test_reference_that_grows_after_inspection_is_read_with_a_bound(self) -> None:
        class GrowingReference(io.BytesIO):
            def read(self, size: int = -1) -> bytes:
                if size < 0 or size > len(reference_bytes()) + 1:
                    raise AssertionError("unbounded reference read after metadata inspection")
                return super().read(size)

        source = GrowingReference(reference_bytes() + b"additional-download-data")
        with patch.object(profile, "MAX_ARTIFACT_BYTES", len(reference_bytes())):
            with patch.object(Path, "open", return_value=source):
                with self.assertRaisesRegex(ValueError, "普通 Linux"):
                    profile.verified_reference(self.reference)

    def test_prepare_publishes_private_profile_without_password(self) -> None:
        with patch.object(profile, "SUPPORTED_SHA256", self.digest):
            target = profile.prepare(self.reference, self.directory / "private")
        data = json.loads(target.read_text())
        self.assertEqual(data["signing_seed"], "public-test-profile-material")
        self.assertEqual(data["common_parameters"]["v"], "4.3.0.1")
        self.assertEqual(len(data["common_parameters"]["_uid"]), 22)
        self.assertRegex(data["common_parameters"]["_os_dim"], r"^lid=[0-9a-f]{32}$")
        self.assertNotIn("password", data)
        self.assertNotIn("username", data)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(target.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(sorted(p.name for p in target.parent.iterdir()), ["compatibility.json"])

    def test_existing_profile_is_not_overwritten(self) -> None:
        folder = self.directory / "private"
        folder.mkdir(mode=0o700)
        target = folder / "compatibility.json"
        target.write_text("keep")
        with self.assertRaises(FileExistsError):
            profile.prepare(self.reference, folder)
        self.assertEqual(target.read_text(), "keep")

    def test_transport_preparation_preserves_login_profile_and_does_not_read_seed(self) -> None:
        data = transport_reference_bytes()
        self.reference.write_bytes(data)
        folder = self.directory / "private"
        folder.mkdir(mode=0o700)
        login = folder / "compatibility.json"
        login.write_text("existing-installation-keep-identifiers")
        with patch.object(profile, "SUPPORTED_SHA256", hashlib.sha256(data).hexdigest()):
            with patch.object(profile, "read_reference_string", wraps=profile.read_reference_string) as reader:
                target = profile.prepare(self.reference, folder, transport_only=True)
        self.assertNotIn(profile.SEED_ADDRESS, [call.args[1] for call in reader.call_args_list])
        public = json.loads(target.read_text())
        self.assertEqual(public, {"version": 1, "core_version": "20260525-1",
                                 "rsa_modulus": str((1 << 1023) + 1), "rsa_exponent": "65537"})
        self.assertEqual(login.read_text(), "existing-installation-keep-identifiers")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("signing_seed", public)
        with self.assertRaises(FileExistsError):
            profile.prepare(self.reference, folder, transport_only=True)

    def test_invalid_transport_metadata_is_not_published(self) -> None:
        data = transport_reference_bytes().replace(b"20260525-1", b"00000000-0")
        self.reference.write_bytes(data)
        folder = self.directory / "private"
        with patch.object(profile, "SUPPORTED_SHA256", hashlib.sha256(data).hexdigest()):
            with self.assertRaisesRegex(ValueError, "传输公开参数"):
                profile.prepare(self.reference, folder, transport_only=True)
        self.assertFalse((folder / "transport.json").exists())

    def test_repository_destination_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "仓库"):
            profile.prepare(self.reference, profile.ROOT / ".native-private-test")

    @unittest.skipIf(os.name == "nt", "Unix private-file permission semantics")
    def test_nonprivate_directory_is_not_chmodded(self) -> None:
        folder = self.directory / "public"
        folder.mkdir(mode=0o755)
        folder.chmod(0o755)
        with patch.object(profile, "SUPPORTED_SHA256", self.digest):
            with self.assertRaisesRegex(ValueError, "其他用户"):
                profile.prepare(self.reference, folder)
        self.assertEqual(folder.stat().st_mode & 0o777, 0o755)
        self.assertFalse((folder / "compatibility.json").exists())

    @unittest.skipIf(os.name == "nt", "Unix symlink semantics")
    def test_symlink_directory_is_rejected(self) -> None:
        original = self.directory / "original"
        original.mkdir(mode=0o700)
        alias = self.directory / "alias"
        alias.symlink_to(original, target_is_directory=True)
        with patch.object(profile, "SUPPORTED_SHA256", self.digest):
            with self.assertRaisesRegex(ValueError, "符号链接"):
                profile.prepare(self.reference, alias)
        self.assertFalse((original / "compatibility.json").exists())

    def test_unterminated_material_is_rejected_without_echo(self) -> None:
        data = bytearray(reference_bytes())
        data[128:] = b"x" * 128
        self.reference.write_bytes(data)
        with patch.object(profile, "SUPPORTED_SHA256", hashlib.sha256(data).hexdigest()):
            with self.assertRaisesRegex(ValueError, "边界") as result:
                profile.extract_seed(self.reference)
        self.assertNotIn("x" * 10, str(result.exception))


if __name__ == "__main__":
    unittest.main()
