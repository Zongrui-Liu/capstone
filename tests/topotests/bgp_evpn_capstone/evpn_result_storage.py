#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Store captures in the mounted FRR checkout and share artifact permissions."""

import datetime
import os
import stat
from pathlib import Path


def result_root():
    """Return the configured root, or <FRR checkout>/capstone_results.

    CAPSTONE_RESULTS_DIR is optional. Without it, this file's location under
    tests/topotests/bgp_evpn_capstone identifies the checkout, regardless of the
    current working directory. For the standard Docker mount, the result is
    /home/frr/frr/capstone_results. The VM source can be ~/frr or ~/src/frr.
    This function only chooses a path; create_capture_directory creates it.
    """
    configured = os.environ.get("CAPSTONE_RESULTS_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    repository = Path(__file__).resolve().parents[3]
    return repository / "capstone_results"


def _repository_is_mounted(repository):
    """Check whether repository (a Path) is a declared Linux mount point.

    Read mountinfo because Path.is_mount alone can miss a bind mount that uses
    the same filesystem as its parent. This reads metadata without changing it.
    """
    escaped = str(repository).replace("\\", "\\134")
    escaped = escaped.replace(" ", "\\040").replace("\t", "\\011").replace("\n", "\\012")
    try:
        mountinfo = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    except OSError:
        return repository.is_mount()
    for line in mountinfo.splitlines():
        fields = line.split()
        if len(fields) > 4 and fields[4] == escaped:
            return True
    return False


def create_capture_directory(output_dir=None):
    """Create one fresh capture directory on the VM-backed results filesystem.

    Args:
        output_dir (str or Path or None): Explicit new run directory. None uses
            <FRR checkout>/capstone_results/evpn_capture_<UTC timestamp>.
            The default results folder is created automatically inside the
            existing repository mount. CAPSTONE_RESULTS_DIR can select another
            existing, writable root. Explicit run directories must be new.

    Returns:
        Path: New directory, for example
            /home/frr/frr/capstone_results/evpn_capture_20261027T210000_123456Z.

    Side effects:
        Creates the default results folder if missing, then a fresh run folder.
        Refuses an existing run to prevent overwrite. Inside Docker, refuses
        the default location unless the repository is mounted from the VM.
        No image rebuild, extra mount, container recreation, or docker cp.
    """
    if output_dir is None:
        root = result_root()
        if not os.environ.get("CAPSTONE_RESULTS_DIR"):
            repository = root.parent
            if not (repository / "tests" / "topotests" / "lib" / "topogen.py").is_file():
                raise RuntimeError(
                    "Cannot locate the FRR checkout. Keep this helper under "
                    "tests/topotests/bgp_evpn_capstone, or set CAPSTONE_RESULTS_DIR."
                )
            if Path("/.dockerenv").exists() and not _repository_is_mounted(repository):
                raise RuntimeError(
                    "The FRR checkout is not mounted from the VM: " + str(repository)
                    + ". Use the existing -v <VM checkout>:/home/frr/frr mount, "
                    "or set CAPSTONE_RESULTS_DIR to an existing VM-backed folder."
                )
            root.mkdir(exist_ok=True)
        elif not root.is_dir():
            raise RuntimeError(
                "Prepare the VM results folder first: " + str(root)
                + ". CAPSTONE_RESULTS_DIR must select an existing writable folder."
            )
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
        output_dir = root / ("evpn_capture_" + stamp)
    directory = Path(output_dir).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    # Share only paths inside the result root, never the repository or VM home.
    share_result_permissions(directory)
    return directory


def _result_owner(root):
    """Return the checkout owner's numeric (UID, GID), independent of username.

    root is the configured results Path. In the FRR checkout, use the mounted
    repository's owner so sudo-created reports belong to the VM account that
    owns that checkout. A standalone helper copy uses the result root's owner.
    """
    repository = Path(__file__).resolve().parents[3]
    if (repository / "tests" / "topotests" / "lib" / "topogen.py").is_file():
        metadata = repository.stat()
    else:
        metadata = root.stat()
    return metadata.st_uid, metadata.st_gid


def _set_shared_access(path, directory, owner):
    """Set one result's owner and mode without following symlinks.

    path is a result Path, directory selects 777 instead of file mode 666, and
    owner is the checkout owner's (UID, GID). Root can repair ownership after
    sudo pytest; ordinary users only apply modes they are permitted to change.
    """
    if path.is_symlink():
        return
    metadata = path.stat()
    if os.geteuid() == 0:
        if (metadata.st_uid, metadata.st_gid) != owner:
            os.chown(path, owner[0], owner[1], follow_symlinks=False)
    mode = 0o777 if directory else 0o666
    # Avoid chmod on another user's file when it already has the desired mode.
    if stat.S_IMODE(metadata.st_mode) != mode:
        path.chmod(mode)


def share_result_permissions(directory):
    """Grant shared read/edit/delete permissions to completed capture artifacts.

    Args:
        directory (str or Path): A capture or analysis directory. Changes apply
            only inside CAPSTONE_RESULTS_DIR (<FRR checkout>/capstone_results
            by default).
            Offline reports elsewhere retain their normal permissions.

    Returns:
        None. On Linux, result directories become 0777 and files become 0666.
        When run as root, results also become owned by the mounted checkout's
        owner. This permits Firefox Snap to open reports in that user's home.
        Directory write/execute access permits deleting other users' result files.

    Side effects:
        Changes result ownership and modes, including parent result directories.
        Does not change the checkout, VM home directories, or symlink targets.
        Access through a VM home directory still requires that directory's
        traversal permission. Run after capture and decoding.

    Example:
        share_result_permissions(session["directory"])
    """
    if os.name != "posix":
        return
    path = Path(directory).resolve()
    root = result_root()
    try:
        path.relative_to(root)
    except ValueError:
        return
    if not path.is_dir():
        return
    # Use the mounted checkout's owner rather than hard-coding roy or UID 1000.
    owner = _result_owner(root)
    parent = path
    while True:
        _set_shared_access(parent, directory=True, owner=owner)
        if parent == root:
            break
        parent = parent.parent
    for current, subdirectories, filenames in os.walk(path, followlinks=False):
        current = Path(current)
        for name in subdirectories:
            _set_shared_access(current / name, directory=True, owner=owner)
        for name in filenames:
            entry = current / name
            if entry.is_file() and not entry.is_symlink():
                _set_shared_access(entry, directory=False, owner=owner)
