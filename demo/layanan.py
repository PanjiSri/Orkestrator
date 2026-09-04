import http.client
import json
import os
import shlex
import subprocess
import time

import tampilan

PORT_UTAMA = 8080
PORT_CADANGAN = 8081
PG_PORT = 5433
PG_DB = "tasks"


PROYEK_UTAMA = "demo-utama"
PROYEK_CADANGAN = "demo-cadangan"


def _sh(perintah, check=True):
    p = subprocess.run(["sh", "-c", perintah], capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"gagal: {perintah}\n{p.stderr.strip()}")
    return p.stdout


def _compose(berkas, proyek, state_dir, perintah, sudo=False):
    awalan = "sudo -n " if sudo else ""
    return (f"{awalan}env STATE_DIR={shlex.quote(state_dir)} PG_PORT={PG_PORT} "
            f"docker compose -f {shlex.quote(berkas)} -p {proyek} {perintah}")


def pg_naik_lokal(berkas_compose, state_dir):
    _sh(_compose(berkas_compose, PROYEK_UTAMA, state_dir, "up -d"))
    _tunggu_port_lokal(PG_PORT, batas=120)


def pg_turun_lokal(berkas_compose, state_dir, hapus=False):
    aksi = "down" if hapus else "stop"
    _sh(_compose(berkas_compose, PROYEK_UTAMA, state_dir, aksi), check=False)


def pg_pemilik(state_dir):
    pgdata = os.path.join(state_dir, "pgdata")
    return _sh(f"stat -c '%u:%g' {shlex.quote(pgdata)}").strip()


def pg_naik_cadangan(peer, berkas_compose_lokal, state_dir, pemilik):
    jauh = os.path.join(os.path.dirname(state_dir), "docker-compose.yml")
    isi = open(berkas_compose_lokal).read()
    peer.run(f"cat > {shlex.quote(jauh)} <<'BERKASCOMPOSE'\n{isi}\nBERKASCOMPOSE")

    pgdata = shlex.quote(os.path.join(state_dir, "pgdata"))
    peer.run(f"sudo chown -R {pemilik} {pgdata} && sudo chmod 0700 {pgdata}")
    peer.run(_compose(jauh, PROYEK_CADANGAN, state_dir, "up -d", sudo=True))
    _tunggu_port_cadangan(peer, PG_PORT, batas=120)


def pg_turun_cadangan(peer, state_dir):
    jauh = os.path.join(os.path.dirname(state_dir), "docker-compose.yml")
    peer.run(
        f"test -f {shlex.quote(jauh)} && "
        + _compose(jauh, PROYEK_CADANGAN, state_dir, "down", sudo=True)
        + " || true",
        check=False)


def _tunggu_port_lokal(port, batas=60):
    import socket as sock
    tenggat = time.time() + batas
    while time.time() < tenggat:
        with sock.socket() as s:
            s.settimeout(2)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                time.sleep(1.0)
                return
        time.sleep(0.5)
    raise RuntimeError(f"PostgreSQL di mesin utama tidak membuka port {port}")


def _tunggu_port_cadangan(peer, port, batas=60):
    tenggat = time.time() + batas
    while time.time() < tenggat:
        keluar = peer.run(
            f"(timeout 2 bash -c '</dev/tcp/127.0.0.1/{port}') "
            f">/dev/null 2>&1 && echo ok || echo belum", check=False).strip()
        if keluar == "ok":
            time.sleep(1.0)
            return
        time.sleep(0.5)
    jejak = peer.run("sudo -n docker logs demo-cadangan-database-1 2>&1 | tail -20 || true",
                     check=False)
    raise RuntimeError(f"PostgreSQL di cadangan tidak membuka port {port}\n{jejak}")


def _env_layanan(db, port, pgdata_dir=None):
    env = os.environ.copy()
    env.update({"PORT": str(port), "DB_TYPE": db})
    if db == "postgres":
        env.update({
            "DB_HOST": "127.0.0.1", "DB_PORT": str(PG_PORT),
            "DB_USER": "postgres", "DB_PASSWORD": "root",
            "DB_NAME": PG_DB, "DB_SSLMODE": "disable",
        })
    return env


def jalankan_utama(biner, cwd, db, port=PORT_UTAMA):
    subprocess.run(["pkill", "-x", "todo-go"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _tunggu_port_bebas(port)
    log = open(os.path.join(os.path.dirname(cwd), "todo-utama.log"), "wb")
    proc = subprocess.Popen([biner], cwd=cwd, env=_env_layanan(db, port),
                            stdout=log, stderr=log)
    _tunggu_lokal(port, proc)
    return proc


def hentikan_utama(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _tunggu_port_bebas(port, batas=20):
    import socket as sock
    tenggat = time.time() + batas
    while time.time() < tenggat:
        with sock.socket() as s:
            s.settimeout(1)
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return
        time.sleep(0.3)
    raise RuntimeError(f"port {port} masih dipegang proses lain")


def _tunggu_lokal(port, proc, batas=90):
    tenggat = time.time() + batas
    while time.time() < tenggat:
        if proc.poll() is not None:
            raise RuntimeError("layanan mati saat dinyalakan, lihat todo-utama.log")
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            c.request("GET", "/api/todo/tasks")
            c.getresponse().read()
            c.close()
            return
        except OSError:
            time.sleep(0.3)
    raise RuntimeError(f"layanan pada :{port} tidak pernah menjawab")


def jalankan_cadangan(peer, biner, cwd, db, port=PORT_CADANGAN, tunggu=10):
    lingkungan = f"PORT={port} DB_TYPE={db}"
    if db == "postgres":
        lingkungan += (f" DB_HOST=127.0.0.1 DB_PORT={PG_PORT} DB_USER=postgres"
                       f" DB_PASSWORD=root DB_NAME={PG_DB} DB_SSLMODE=disable")
    perintah = (f"cd {shlex.quote(cwd)} && {lingkungan} "
                f"setsid nohup {shlex.quote(biner)} "
                f"> /tmp/demo-todo.log 2>&1 < /dev/null & exit 0")
    try:
        peer.run(perintah, check=False, timeout=15)
    except subprocess.TimeoutExpired:
        pass
    tampilan.baris(f"menunggu {tunggu} detik")
    time.sleep(tunggu)


def _alamat_cadangan(peer):
    return peer.host.split("@")[-1] or "127.0.0.1"


def _ambil_http(host, port, batas=10):
    c = http.client.HTTPConnection(host, port, timeout=batas)
    try:
        c.request("GET", "/api/todo/tasks")
        r = c.getresponse()
        return r.status, r.read().decode()
    finally:
        c.close()


def hentikan_cadangan(peer):
    peer.run("pkill -x todo-go || true", check=False)


def kirim_post(port, jumlah, awalan):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    kepala = {"Content-Type": "application/json"}
    terkirim = []
    try:
        for i in range(1, jumlah + 1):
            item = f"{awalan}-{i:02d}"
            conn.request("POST", "/api/todo/tasks",
                         json.dumps({"item": item}), kepala)
            r = conn.getresponse()
            r.read()
            if r.status != 200:
                raise RuntimeError(f"POST {item} menjawab {r.status}")
            terkirim.append(item)
    finally:
        conn.close()
    return terkirim


def get_cadangan(peer, port=PORT_CADANGAN):
    host = _alamat_cadangan(peer)
    try:
        _, mentah = _ambil_http(host, port, 15)
    except OSError as e:
        raise RuntimeError(f"GET ke {host}:{port} gagal: {e}")
    return _ambil_item(mentah), mentah.strip()


def _ambil_item(mentah):
    try:
        data = json.loads(mentah)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        for kunci in ("tasks", "data", "items", "result"):
            if isinstance(data.get(kunci), list):
                data = data[kunci]
                break
    if not isinstance(data, list):
        return []
    hasil = []
    for e in data:
        if isinstance(e, str):
            hasil.append(e)
        elif isinstance(e, dict):
            for kunci in ("item", "Item", "task", "name", "title"):
                if kunci in e:
                    hasil.append(str(e[kunci]))
                    break
    return hasil


def identitas_cadangan(peer):
    nama = peer.run("hostname").strip()
    ip = peer.run(
        "ip -4 -o addr show scope global | awk '{print $4}' | "
        "cut -d/ -f1 | paste -sd' '").strip()
    return nama, ip
