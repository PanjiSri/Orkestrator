import os
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time

import peer as peer_mod

SOCKET_GET = b"g"
SOCKET_ERROR_SIZE = (1 << 64) - 1


class CaptureLost(Exception):
    pass


class RsyncRecorder:
    name = "rsync"

    def __init__(self, peer, **_):
        self.peer = peer
        self.src = None

    def start(self, src):
        self.src = src

    def drain(self):
        return 0

    def sync(self):
        cmd = (["rsync", "-a", "--stats", "--no-whole-file"]
               + self.peer._remote_args()
               + [peer_mod.with_slash(self.src), self.peer._target()])
        t0 = time.perf_counter()
        p = subprocess.run(cmd, capture_output=True, text=True, env=peer_mod.ssh_env())
        elapsed = time.perf_counter() - t0
        if p.returncode != 0:
            raise RuntimeError("rsync sync failed: " + p.stderr.strip())
        return elapsed, _parse_bytes_sent(p.stdout)

    def stop(self):
        pass


def _parse_bytes_sent(stats):
    for line in stats.splitlines():
        if line.startswith("Total bytes sent:"):
            digits = "".join(c for c in line.split(":", 1)[1] if c.isdigit())
            return int(digits) if digits else 0
    return 0


class EbpfRecorder:
    name = "ebpf"

    def __init__(self, peer, capture_bin, apply_bin, remote_tmp, **_):
        self.peer = peer
        self.capture_bin = capture_bin
        self.apply_bin = apply_bin
        self.remote_tmp = remote_tmp
        self.proc = None
        self.conn = None
        self.sock_dir = None

    def start(self, src):
        self.sock_dir = tempfile.mkdtemp(prefix="sd-sock-")
        sock_path = os.path.join(self.sock_dir, "capture.sock")
        self.proc = subprocess.Popen(
            [self.capture_bin, "--quiet", "--socket", sock_path, src])

        deadline = time.time() + 120
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    "capturer exited before opening its socket "
                    "(run as root? kernel with BTF?)")
            try:
                c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                c.connect(sock_path)
                self.conn = c
                return
            except OSError:
                time.sleep(0.1)
        self.proc.kill()
        raise RuntimeError(f"timed out waiting for {sock_path}")

    def _harvest(self):
        self.conn.sendall(SOCKET_GET)
        size = struct.unpack("<Q", _recv_exactly(self.conn, 8))[0]
        if size == SOCKET_ERROR_SIZE:
            raise CaptureLost("capturer reported incomplete capture")
        return _recv_exactly(self.conn, size) if size else b""

    def drain(self):
        return len(self._harvest())

    def sync(self):
        t0 = time.perf_counter()
        artifact = self._harvest()
        if artifact:
            self.peer.push_and_apply(artifact, self.apply_bin, self.remote_tmp)
        return time.perf_counter() - t0, len(artifact)

    def stop(self):
        if self.conn:
            self.conn.close()
            self.conn = None
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.sock_dir:
            shutil.rmtree(self.sock_dir, ignore_errors=True)
            self.sock_dir = None


def _recv_exactly(conn, n):
    chunks = []
    got = 0
    while got < n:
        chunk = conn.recv(min(1 << 20, n - got))
        if not chunk:
            raise RuntimeError("capturer closed the socket mid-response")
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


ARMS = {"rsync": RsyncRecorder, "ebpf": EbpfRecorder}
