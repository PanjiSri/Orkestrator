import csv
import http.client
import json
import os
import random
import shutil
import statistics
import subprocess
import time

import cleanup as cleanup_mod
import peer as peer_mod
import recorder as recorder_mod

SAMPLE_FIELDS = ["exp", "cond", "trial", "i", "latency_us"]
SUMMARY_FIELDS = [
    "exp", "cond", "trial", "ops", "wall_s", "throughput_ops_s",
    "p50_us", "p90_us", "p99_us", "batch_bytes", "capture_lost", "errors",
]

WAL = "true"


class _NoRecorder:
    name = "off"

    def drain(self):
        return 0

    def stop(self):
        pass


def _start_recorder(cond, cfg, src):
    if cond != "ebpf":
        return _NoRecorder()
    rec = recorder_mod.EbpfRecorder(
        peer=peer_mod.Peer("", cfg["dst"]),
        capture_bin=cfg["capture_bin"],
        apply_bin=cfg["apply_bin"],
        remote_tmp=cfg["remote_tmp"],
    )
    rec.start(src)
    return rec


def _percentiles(samples_us):
    s = sorted(samples_us)
    def pct(q):
        return round(s[min(len(s) - 1, int(q * len(s)))], 2)
    return pct(0.50), pct(0.90), pct(0.99)


def run_fs_once(cfg, cond, trial, ops, warmup, write_size, file_size, seed):
    src = cfg["src"]
    peer = peer_mod.Peer("", cfg["dst"])
    cleanup_mod.cleanup(peer, cfg["work_dir"], src, cfg["peer_work_dir"])
    os.makedirs(src, exist_ok=True)

    rec = _start_recorder(cond, cfg, src)
    row = {"exp": "cdf_fs", "cond": cond, "trial": trial, "ops": ops,
           "capture_lost": 0, "errors": 0}
    latencies = []
    try:
        path = os.path.join(src, "data.bin")
        chunk = 1 << 20
        with open(path, "wb") as f:
            remaining = file_size
            while remaining > 0:
                n = min(chunk, remaining)
                f.write(os.urandom(n))
                remaining -= n
            os.fsync(f.fileno())
        rec.drain()

        rng = random.Random(seed)
        buf = rng.randbytes(write_size)
        span = max(1, (file_size - write_size) // 4096)
        offsets = [rng.randrange(span) * 4096 for _ in range(warmup + ops)]

        fd = os.open(path, os.O_WRONLY)
        try:
            for i in range(warmup):
                os.pwrite(fd, buf, offsets[i])
            t_start = time.perf_counter()
            for i in range(warmup, warmup + ops):
                t0 = time.perf_counter_ns()
                os.pwrite(fd, buf, offsets[i])
                latencies.append((time.perf_counter_ns() - t0) / 1000.0)
            row["wall_s"] = round(time.perf_counter() - t_start, 3)
            os.fsync(fd)
        finally:
            os.close(fd)

        row["batch_bytes"] = rec.drain()
    except recorder_mod.CaptureLost as e:
        row["capture_lost"] = 1
        print(f"  !! CAPTURE LOST: {e}")
    finally:
        rec.stop()
        cleanup_mod.cleanup(peer, cfg["work_dir"], src, cfg["peer_work_dir"])

    return row, latencies


def _wait_until_serving(port, proc, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("service exited during start-up")
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            c.request("GET", "/api/todo/tasks")
            c.getresponse().read()
            c.close()
            return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"service on :{port} never answered")


def run_db_once(cfg, cond, trial, ops, warmup, port, seed):
    src = cfg["src"]
    peer = peer_mod.Peer("", cfg["dst"])
    cleanup_mod.cleanup(peer, cfg["work_dir"], src, cfg["peer_work_dir"])
    os.makedirs(src, exist_ok=True)

    rec = _start_recorder(cond, cfg, src)
    row = {"exp": "cdf_db", "cond": cond, "trial": trial, "ops": ops,
           "capture_lost": 0, "errors": 0}
    latencies = []
    proc = None
    try:
        env = os.environ.copy()
        env.update({"PORT": str(port), "DB_TYPE": "sqlite", "ENABLE_WAL": WAL})
        log = open(os.path.join(cfg["work_dir"], "service.log"), "wb")
        proc = subprocess.Popen([cfg["service_bin"]], cwd=src, env=env,
                                stdout=log, stderr=log)
        _wait_until_serving(port, proc)
        rec.drain()

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        headers = {"Content-Type": "application/json"}

        def post(item):
            conn.request("POST", "/api/todo/tasks",
                         json.dumps({"item": item}), headers)
            r = conn.getresponse()
            r.read()
            return r.status

        for i in range(warmup):
            post(f"warm-{seed}-{i}")

        t_start = time.perf_counter()
        for i in range(ops):
            item = f"task-{seed}-{i}"
            t0 = time.perf_counter_ns()
            status = post(item)
            latencies.append((time.perf_counter_ns() - t0) / 1000.0)
            if status != 200:
                row["errors"] += 1
        row["wall_s"] = round(time.perf_counter() - t_start, 3)
        conn.close()

        row["batch_bytes"] = rec.drain()
    except recorder_mod.CaptureLost as e:
        row["capture_lost"] = 1
        print(f"  !! CAPTURE LOST: {e}")
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        rec.stop()
        cleanup_mod.cleanup(peer, cfg["work_dir"], src, cfg["peer_work_dir"])

    return row, latencies


def sweep(cfg, exp, run_once, trials, out_csv, conds=("off", "ebpf"), **kwargs):
    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    summary_path = os.path.splitext(out_csv)[0] + ".summary.csv"

    with open(out_csv, "w", newline="") as sf, \
            open(summary_path, "w", newline="") as mf:
        samples = csv.DictWriter(sf, fieldnames=SAMPLE_FIELDS)
        samples.writeheader()
        summary = csv.DictWriter(mf, fieldnames=SUMMARY_FIELDS)
        summary.writeheader()

        for trial in range(trials):
            for cond in conds:
                print(f"\n=== {exp}  cond={cond:<4}  trial={trial} ===")
                row, lat = run_once(cfg, cond, trial, seed=1000 + trial, **kwargs)

                if lat:
                    p50, p90, p99 = _percentiles(lat)
                    row.update(p50_us=p50, p90_us=p90, p99_us=p99)
                    row["throughput_ops_s"] = round(
                        row["ops"] / row["wall_s"], 1) if row.get("wall_s") else ""
                    for i, v in enumerate(lat):
                        samples.writerow({"exp": exp, "cond": cond,
                                          "trial": trial, "i": i,
                                          "latency_us": round(v, 3)})
                    sf.flush()
                    print(f"  p50={p50} us  p90={p90} us  p99={p99} us  "
                          f"batch={row.get('batch_bytes')} B  "
                          f"errors={row['errors']}")
                summary.writerow({k: row.get(k, "") for k in SUMMARY_FIELDS})
                mf.flush()

    print(f"\nselesai -> {out_csv}\n           {summary_path}")
