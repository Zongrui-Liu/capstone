#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Check VM results paths and Linux permissions without creating a topology."""

import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from evpn_result_storage import (
    _repository_is_mounted, _result_owner, _set_shared_access,
    create_capture_directory, result_root, share_result_permissions,
)


class StorageChecks(unittest.TestCase):
    """Verify public artifacts stay inside the explicitly selected result root."""

    def test_repository_default_supports_both_vm_checkout_locations(self):
        """~/frr and ~/src/frr both create results inside their own checkout."""
        with tempfile.TemporaryDirectory() as temporary:
            for relative_checkout in ("frr", "src/frr"):
                repository = Path(temporary) / relative_checkout
                helper = repository / "tests/topotests/bgp_evpn_capstone/evpn_result_storage.py"
                helper.parent.mkdir(parents=True)
                topogen = repository / "tests/topotests/lib/topogen.py"
                topogen.parent.mkdir()
                topogen.touch()
                with patch.dict(os.environ, {"CAPSTONE_RESULTS_DIR": ""}):
                    with patch("evpn_result_storage.__file__", str(helper)):
                        with patch("evpn_result_storage._repository_is_mounted", return_value=True):
                            expected_root = repository.resolve() / "capstone_results"
                            self.assertEqual(result_root(), expected_root)
                            self.assertFalse(expected_root.exists())
                            directory = create_capture_directory()
                            self.assertEqual(directory.parent, expected_root)
                            self.assertTrue(directory.is_dir())

    def test_new_runs_use_the_configured_vm_result_root(self):
        """Default runs get unique names beneath the configured share."""
        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict(os.environ, {"CAPSTONE_RESULTS_DIR": temporary}):
                directory = create_capture_directory()
                self.assertEqual(directory.parent, Path(temporary))
                self.assertTrue(directory.name.startswith("evpn_capture_"))
                self.assertTrue(directory.is_dir())

    def test_missing_root_is_not_created_in_the_container_layer(self):
        """An absent prepared share gives an actionable error instead of fallback."""
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "not-mounted"
            with patch.dict(os.environ, {"CAPSTONE_RESULTS_DIR": str(missing)}):
                with self.assertRaisesRegex(RuntimeError, "Prepare the VM results folder"):
                    create_capture_directory()
            self.assertFalse(missing.exists())

    def test_existing_runs_are_not_overwritten(self):
        """Selecting an existing directory must preserve its files."""
        with tempfile.TemporaryDirectory() as temporary:
            existing = Path(temporary) / "run"
            existing.mkdir()
            with self.assertRaises(FileExistsError):
                create_capture_directory(existing)

    def test_unmounted_default_inside_docker_is_rejected(self):
        """An unmounted checkout must not silently store results in Docker."""
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            topogen = repository / "tests/topotests/lib/topogen.py"
            topogen.parent.mkdir(parents=True)
            topogen.touch()
            root = repository / "capstone_results"
            with patch.dict(os.environ, {"CAPSTONE_RESULTS_DIR": ""}):
                with patch("evpn_result_storage.result_root", return_value=root):
                    with patch("evpn_result_storage._repository_is_mounted", return_value=False):
                        with patch.object(Path, "exists", return_value=True):
                            with self.assertRaisesRegex(RuntimeError, "checkout is not mounted"):
                                create_capture_directory()
            self.assertFalse(root.exists())

    def test_default_rejects_a_helper_outside_the_frr_checkout(self):
        """A misplaced helper cannot create a results folder in an unrelated path."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "capstone_results"
            with patch.dict(os.environ, {"CAPSTONE_RESULTS_DIR": ""}):
                with patch("evpn_result_storage.result_root", return_value=root):
                    with self.assertRaisesRegex(RuntimeError, "Cannot locate the FRR checkout"):
                        create_capture_directory()
            self.assertFalse(root.exists())

    @unittest.skipUnless(os.name == "posix", "Linux mountinfo paths")
    def test_bind_mount_detection_uses_the_declared_repository_mount(self):
        """Recognize bind mounts even when is_mount cannot distinguish devices."""
        mountinfo = (
            "1 0 0:1 / / rw - overlay overlay rw\n"
            "2 1 8:1 /home/roy/src/frr /home/frr/frr rw - ext4 /dev/sda1 rw\n"
            "3 1 8:1 /checkout /checkout\\040shared rw - ext4 /dev/sda1 rw\n"
        )
        with patch.object(Path, "read_text", return_value=mountinfo):
            with patch.object(Path, "is_mount", return_value=False):
                self.assertTrue(_repository_is_mounted(Path("/home/frr/frr")))
                self.assertTrue(_repository_is_mounted(Path("/checkout shared")))
                self.assertFalse(_repository_is_mounted(Path("/home/frr/frr/not-mounted")))

    @unittest.skipUnless(os.name == "posix", "Linux ownership")
    def test_owner_comes_from_the_checkout_without_a_fixed_username_or_uid(self):
        """A teammate's UID/GID can differ from Roy's and from the frr group."""
        metadata = SimpleNamespace(st_uid=1234, st_gid=5678)
        with patch.object(Path, "is_file", return_value=True):
            with patch.object(Path, "stat", return_value=metadata):
                self.assertEqual(_result_owner(Path("/results")), (1234, 5678))

    @unittest.skipUnless(os.name == "posix", "Linux ownership")
    def test_root_repairs_report_ownership_for_a_snap_browser(self):
        """World-readable root-owned files must also become VM-user-owned."""
        report = Path("/results/type2_timeline.html")
        metadata = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o666)
        with patch.object(Path, "is_symlink", return_value=False):
            with patch.object(Path, "stat", return_value=metadata):
                with patch("evpn_result_storage.os.geteuid", return_value=0):
                    with patch("evpn_result_storage.os.chown") as change_owner:
                        _set_shared_access(report, directory=False, owner=(1234, 5678))
        change_owner.assert_called_once_with(report, 1234, 5678, follow_symlinks=False)

    @unittest.skipUnless(os.name == "posix", "Linux filesystem permissions")
    def test_all_users_get_directory_and_file_access(self):
        """777 directories and 666 data files permit shared edits and deletion."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "public"
            analysis = root / "run" / "analysis"
            analysis.mkdir(parents=True, mode=0o700)
            report = analysis / "type2_timeline.html"
            report.write_text("example", encoding="utf-8")
            report.chmod(0o600)
            with patch.dict(os.environ, {"CAPSTONE_RESULTS_DIR": str(root)}):
                share_result_permissions(analysis)
            for directory in (root, root / "run", analysis):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o777)
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o666)

    @unittest.skipUnless(os.name == "posix", "Linux filesystem permissions")
    def test_other_paths_and_symlink_targets_keep_their_modes(self):
        """A link in the results tree must not make a private sibling public."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "public"
            root.mkdir()
            private = Path(temporary) / "private.txt"
            private.write_text("private", encoding="utf-8")
            private.chmod(0o600)
            (root / "link").symlink_to(private)
            with patch.dict(os.environ, {"CAPSTONE_RESULTS_DIR": str(root)}):
                share_result_permissions(root)
                share_result_permissions(Path(temporary))
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
