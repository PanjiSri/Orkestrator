import os
import pwd
import shlex
import subprocess

SSH_OPTS = [
    "-o", "ControlMaster=auto",
    "-o", "ControlPath=/tmp/proto-cm-%r@%h:%p",
    "-o", "ControlPersist=30m",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
]


def ssh_env():
    env = os.environ.copy()
    sudo_user = env.get("SUDO_USER")
    if sudo_user and os.geteuid() == 0:
        try:
            env["HOME"] = pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass
    return env


def with_slash(path):
    return path if path.endswith("/") else path + "/"


class Peer:
    def __init__(self, host, dst):
        self.host = host or ""
        self.dst = dst

    @property
    def is_local(self):
        return self.host == ""

    def rsh(self):
        return "ssh " + " ".join(SSH_OPTS)

    def _remote_args(self):
        return [] if self.is_local else ["-e", self.rsh()]

    def _target(self):
        d = with_slash(self.dst)
        return d if self.is_local else f"{self.host}:{d}"

    def run(self, script, check=True, timeout=120):
        if self.is_local:
            cmd = ["sh", "-c", script]
        else:
            cmd = ["ssh"] + SSH_OPTS + [self.host, script]
        p = subprocess.run(cmd, capture_output=True, text=True, env=ssh_env(),
                           timeout=timeout)
        if check and p.returncode != 0:
            raise RuntimeError(f"peer command failed: {script}\n{p.stderr.strip()}")
        return p.stdout

    def push_and_apply(self, artifact, apply_bin, remote_tmp):
        script = (
            f"cat > {shlex.quote(remote_tmp)} && "
            f"{shlex.quote(apply_bin)} {shlex.quote(remote_tmp)} {shlex.quote(self.dst)} && "
            f"rm -f {shlex.quote(remote_tmp)}"
        )
        cmd = ["sh", "-c", script] if self.is_local else ["ssh"] + SSH_OPTS + [self.host, script]
        p = subprocess.run(cmd, input=artifact, capture_output=True, env=ssh_env())
        if p.returncode != 0:
            raise RuntimeError("push+apply failed: " + p.stderr.decode(errors="replace").strip())

    def seed(self, src):
        self.run(f"rm -rf {shlex.quote(self.dst)} && mkdir -p {shlex.quote(self.dst)}")
        cmd = (["rsync", "-a", "--no-whole-file"] + self._remote_args()
               + [with_slash(src), self._target()])
        p = subprocess.run(cmd, capture_output=True, text=True, env=ssh_env())
        if p.returncode != 0:
            raise RuntimeError("seed failed: " + p.stderr.strip())

    def verify(self, src):
        cmd = (["rsync", "-rin", "--checksum", "--delete"] + self._remote_args()
               + [with_slash(src), self._target()])
        p = subprocess.run(cmd, capture_output=True, text=True, env=ssh_env())
        if p.returncode != 0:
            raise RuntimeError("verify failed: " + p.stderr.strip())
        return sum(1 for line in p.stdout.splitlines() if line.strip())
