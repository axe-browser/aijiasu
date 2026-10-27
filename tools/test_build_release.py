"""Offline release tests replace compilation and code signing with local fixtures."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import build_release as release


class BuildReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="native-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        system = patch.object(release.platform, "system", return_value="Darwin")
        system.start()
        self.addCleanup(system.stop)
        publication = patch.object(release, "publish_directory", side_effect=self.fake_publish)
        publication.start()
        self.addCleanup(publication.stop)

    @staticmethod
    def fake_publish(staging: Path, output: Path) -> None:
        if output.exists() or output.is_symlink():
            raise FileExistsError(str(output))
        staging.rename(output)

    @staticmethod
    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        if args[:2] == ["go", "build"]:
            target = Path(args[args.index("-o") + 1])
            target.write_bytes(b"public-release-test-binary")
            target.chmod(0o755)
        return subprocess.CompletedProcess(args, 0)

    def test_build_publishes_only_six_versioned_native_binaries(self) -> None:
        output = self.directory / "release"
        with patch.object(release.subprocess, "run", side_effect=self.fake_run) as run:
            self.assertEqual(release.build("v1.2.3-beta.4", output), output)
        self.assertEqual(sorted(path.name for path in output.iterdir()), [
            "aijiasu-native-linux-amd64", "aijiasu-native-linux-arm64",
            "aijiasu-native-macos-amd64", "aijiasu-native-macos-arm64",
            "aijiasu-native-windows-amd64.exe", "aijiasu-native-windows-arm64.exe",
        ])
        self.assertEqual(run.call_count, 12)
        builds = [call for call in run.call_args_list if call.args[0][:2] == ["go", "build"]]
        self.assertEqual(len(builds), 6)
        for build, (goos, arch, asset_os) in zip(builds, release.PLATFORMS):
            args = build.args[0]
            self.assertEqual(args[:4], ["go", "build", "-buildvcs=false", "-trimpath"])
            self.assertIn("-ldflags=-s -w -X main.version=1.2.3-beta.4", args)
            self.assertEqual(args[-1], "./cmd/aijiasu-native")
            self.assertEqual(build.kwargs["cwd"], release.ROOT)
            self.assertEqual(build.kwargs["env"]["GOOS"], goos)
            self.assertEqual(build.kwargs["env"]["GOARCH"], arch)
            self.assertEqual(build.kwargs["env"]["CGO_ENABLED"], "0")
            self.assertEqual(build.kwargs["env"]["GOTOOLCHAIN"], release.RELEASE_TOOLCHAIN)
            self.assertEqual(build.kwargs["env"]["GOAMD64"], "v1")
            self.assertEqual(build.kwargs["env"]["GOARM64"], "v8.0")
            self.assertEqual(build.kwargs["env"]["GOFLAGS"], "")
            self.assertEqual(build.kwargs["env"]["GOEXPERIMENT"], "")
            self.assertEqual(build.kwargs["env"]["GOWORK"], "off")
            staged = args[args.index("-o") + 1]
            extension = ".exe" if goos == "windows" else ""
            self.assertEqual(Path(staged).name, f"aijiasu-native-{asset_os}-{arch}{extension}")
            self.assertFalse(Path(staged).exists())
            self.assertEqual((output / Path(staged).name).stat().st_mode & 0o777, 0o755)
        signing = [call for call in run.call_args_list if "--sign" in call.args[0]]
        verification = [call for call in run.call_args_list if "--verify" in call.args[0]]
        self.assertEqual(len(signing), 2)
        self.assertEqual(len(verification), 4)
        for sign in signing:
            self.assertEqual(sign.args[0][:4], ["/usr/bin/codesign", "--force", "--sign", "-"])
        for verify in verification:
            self.assertEqual(verify.args[0][:3], ["/usr/bin/codesign", "--verify", "--strict"])
        for call in signing + verification:
            self.assertIn(Path(call.args[0][-1]).name, {
                "aijiasu-native-macos-amd64", "aijiasu-native-macos-arm64",
            })
        copied_verification = [call for call in verification
                               if Path(call.args[0][-1]).parent.name == "release"]
        self.assertEqual(len(copied_verification), 2)
        for call in run.call_args_list:
            self.assertTrue(call.kwargs["check"])
            self.assertGreater(call.kwargs["timeout"], 0)

    def test_release_overrides_incompatible_parent_build_options(self) -> None:
        environment = {"GOTOOLCHAIN": "local", "GOAMD64": "v4", "GOARM64": "v9.5",
                       "GOFLAGS": "-race", "GOEXPERIMENT": "jsonv2", "GOWORK": "/invalid/workspace"}
        with patch.dict(os.environ, environment):
            with patch.object(release.subprocess, "run", side_effect=self.fake_run) as run:
                release.build("1.0.0", self.directory / "release")
        builds = [call for call in run.call_args_list if call.args[0][:2] == ["go", "build"]]
        for call in builds:
            actual = call.kwargs["env"]
            self.assertEqual(actual["GOTOOLCHAIN"], release.RELEASE_TOOLCHAIN)
            self.assertEqual(actual["GOAMD64"], "v1")
            self.assertEqual(actual["GOARM64"], "v8.0")
            self.assertEqual(actual["GOFLAGS"], "")
            self.assertEqual(actual["GOEXPERIMENT"], "")
            self.assertEqual(actual["GOWORK"], "off")

    def test_copied_asset_is_verified_before_publication(self) -> None:
        output = self.directory / "release"

        def reject_copy(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            if "--verify" in args and Path(args[-1]).parent.name == "release":
                raise subprocess.CalledProcessError(1, args)
            return self.fake_run(args, **kwargs)

        with patch.object(release.subprocess, "run", side_effect=reject_copy):
            with self.assertRaises(subprocess.CalledProcessError):
                release.build("1.0.0", output)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_default_output_uses_native_prefix(self) -> None:
        with patch.object(release.tempfile, "gettempdir", return_value=str(self.directory)):
            with patch.object(release.subprocess, "run", side_effect=self.fake_run):
                output = release.build("1.2.3")
        self.assertEqual(output.parent, self.directory)
        self.assertRegex(output.name, r"^aijiasu-native-release-1\.2\.3-[0-9a-f]{8}$")

    def test_invalid_versions_do_not_run_subprocesses(self) -> None:
        with patch.object(release.subprocess, "run") as run:
            for version in ("", "v1", "1.2", "1.2.3 extra", "1.2.3;echo", "../1.2.3"):
                with self.subTest(version=version), self.assertRaises(ValueError):
                    release.build(version, self.directory / "release")
        run.assert_not_called()

    def test_existing_paths_and_dangling_links_are_not_overwritten(self) -> None:
        existing_directory = self.directory / "existing-directory"
        existing_directory.mkdir()
        existing_file = self.directory / "existing-file"
        existing_file.write_text("keep", encoding="utf-8")
        link = self.directory / "dangling-link"
        link.symlink_to(self.directory / "missing")
        with patch.object(release.subprocess, "run") as run:
            for output in (existing_directory, existing_file, link):
                with self.subTest(output=output.name), self.assertRaises(FileExistsError):
                    release.build("1.2.3", output)
        run.assert_not_called()
        self.assertEqual(existing_file.read_text(encoding="utf-8"), "keep")
        self.assertTrue(link.is_symlink())

    def test_non_macos_host_does_not_build(self) -> None:
        with patch.object(release.platform, "system", return_value="Linux"):
            with patch.object(release.subprocess, "run") as run:
                with self.assertRaises(RuntimeError):
                    release.build("1.2.3", self.directory / "release")
        run.assert_not_called()

    def test_failed_signature_verification_does_not_publish(self) -> None:
        output = self.directory / "release"

        def fail_verification(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            if "--verify" in args:
                raise subprocess.CalledProcessError(1, args)
            return self.fake_run(args, **kwargs)

        with patch.object(release.tempfile, "gettempdir", return_value=str(self.directory)):
            with patch.object(release.subprocess, "run", side_effect=fail_verification):
                with self.assertRaises(subprocess.CalledProcessError):
                    release.build("1.2.3", output)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_failed_second_copy_leaves_no_output_and_allows_retry(self) -> None:
        output = self.directory / "release"
        copy = release.shutil.copy2
        copied = 0

        def fail_second_copy(source: Path, destination: Path) -> Path:
            nonlocal copied
            copied += 1
            self.assertEqual(destination.parent.parent.parent, output.parent)
            self.assertFalse(output.exists())
            if copied == 2:
                raise OSError("simulated copy failure")
            return copy(source, destination)

        with patch.object(release.subprocess, "run", side_effect=self.fake_run):
            with patch.object(release.shutil, "copy2", side_effect=fail_second_copy):
                with self.assertRaisesRegex(OSError, "simulated copy failure"):
                    release.build("1.2.3", output)
            self.assertFalse(output.exists())
            self.assertEqual(list(self.directory.iterdir()), [])
            self.assertEqual(release.build("1.2.3", output), output)
        self.assertEqual(len(list(output.iterdir())), 6)

    def test_failed_publication_cleans_staging_and_allows_retry(self) -> None:
        output = self.directory / "release"
        with patch.object(release.subprocess, "run", side_effect=self.fake_run):
            with patch.object(release, "publish_directory", side_effect=OSError("simulated publication failure")):
                with self.assertRaisesRegex(OSError, "simulated publication failure"):
                    release.build("1.2.3", output)
            self.assertFalse(output.exists())
            self.assertEqual(list(self.directory.iterdir()), [])
            self.assertEqual(release.build("1.2.3", output), output)
        self.assertEqual(len(list(output.iterdir())), 6)

    def test_failed_last_cross_build_does_not_publish_partial_release(self) -> None:
        output = self.directory / "release"

        def fail_windows_arm64(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            if args[:2] == ["go", "build"]:
                environment = kwargs["env"]
                if environment["GOOS"] == "windows" and environment["GOARCH"] == "arm64":
                    raise subprocess.CalledProcessError(1, args)
            return self.fake_run(args, **kwargs)

        with patch.object(release.tempfile, "gettempdir", return_value=str(self.directory)):
            with patch.object(release.subprocess, "run", side_effect=fail_windows_arm64):
                with self.assertRaises(subprocess.CalledProcessError):
                    release.build("1.2.3", output)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_concurrent_destination_is_preserved_when_publication_refuses_it(self) -> None:
        expected_paths = set()
        for kind in ("directory", "file", "link"):
            with self.subTest(kind=kind):
                output = self.directory / kind

                def concurrent_publish(staging: Path, destination: Path) -> None:
                    if kind == "directory":
                        destination.mkdir()
                    elif kind == "file":
                        destination.write_text("keep", encoding="utf-8")
                    else:
                        destination.symlink_to(self.directory / "missing")
                    self.fake_publish(staging, destination)

                with patch.object(release.subprocess, "run", side_effect=self.fake_run):
                    with patch.object(release, "publish_directory", side_effect=concurrent_publish):
                        with self.assertRaises(FileExistsError):
                            release.build("1.2.3", output)
                if kind == "directory":
                    self.assertEqual(list(output.iterdir()), [])
                elif kind == "file":
                    self.assertEqual(output.read_text(encoding="utf-8"), "keep")
                else:
                    self.assertTrue(output.is_symlink())
                expected_paths.add(kind)
                self.assertEqual({path.name for path in self.directory.iterdir()}, expected_paths)


@unittest.skipUnless(sys.platform == "darwin", "exclusive directory publication uses macOS renamex_np")
class NativePublicationTests(unittest.TestCase):
    def test_native_publication_moves_complete_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="native-publication-test-") as temporary:
            directory = Path(temporary)
            staging, output = directory / "staging", directory / "release"
            staging.mkdir()
            (staging / "binary").write_bytes(b"public-test-binary")
            release.publish_directory(staging, output)
            self.assertFalse(staging.exists())
            self.assertEqual((output / "binary").read_bytes(), b"public-test-binary")

    def test_native_publication_never_replaces_concurrent_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="native-publication-test-") as temporary:
            directory = Path(temporary)
            staging = directory / "staging"
            staging.mkdir()
            (staging / "binary").write_bytes(b"public-test-binary")
            for kind in ("empty-directory", "file", "dangling-link"):
                with self.subTest(kind=kind):
                    output = directory / kind
                    if kind == "empty-directory":
                        output.mkdir()
                    elif kind == "file":
                        output.write_text("keep", encoding="utf-8")
                    else:
                        output.symlink_to(directory / "missing")
                    before = output.lstat()
                    with self.assertRaises(FileExistsError):
                        release.publish_directory(staging, output)
                    self.assertEqual((output.lstat().st_dev, output.lstat().st_ino),
                                     (before.st_dev, before.st_ino))
                    self.assertEqual((staging / "binary").read_bytes(), b"public-test-binary")
                    if kind == "empty-directory":
                        self.assertEqual(list(output.iterdir()), [])
                    elif kind == "file":
                        self.assertEqual(output.read_text(encoding="utf-8"), "keep")
                    else:
                        self.assertTrue(output.is_symlink())


if __name__ == "__main__":
    unittest.main()
