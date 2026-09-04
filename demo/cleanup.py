import os
import shlex
import shutil
import subprocess

ALLOWED_LEAVES = ("src", "dst")


def guard(path, work_dir):
    p = os.path.abspath(path)
    w = os.path.abspath(work_dir)
    if w in ("/", "", os.path.expanduser("~")):
        raise ValueError(f"unsafe work dir: {w}")
    if not p.startswith(w + os.sep):
        raise ValueError(f"{p} is not inside work dir {w}")
    if os.path.basename(p) not in ALLOWED_LEAVES:
        raise ValueError(f"refusing to remove {p}: not one of {ALLOWED_LEAVES}")
    return p


def _drop_caches_local():
    subprocess.run(["sync"], check=False)
    try:
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("3\n")
    except OSError:
        pass


def cleanup(peer, work_dir, src, peer_work_dir, drop_caches=True):
    subprocess.run(["pkill", "-x", "statediff_vfs"], check=False,
                   capture_output=True)

    shutil.rmtree(guard(src, work_dir), ignore_errors=True)

    dst = guard(peer.dst, peer_work_dir)
    peer.run(f"rm -rf {shlex.quote(dst)}", check=False)

    if drop_caches:
        _drop_caches_local()
        peer.run("sync; sudo -n sh -c 'echo 3 > /proc/sys/vm/drop_caches' "
                 "2>/dev/null || true", check=False)
