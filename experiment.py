import csv
import json
import os
import platform
import socket as socket_mod
import subprocess
import sys
import time

import cleanup as cleanup_mod
import recorder as recorder_mod
import workload

FIELDS = [
    "exp", "arm", "x_label", "x_value", "trial",
    "sync_ms", "bytes_sent",
    "file_size", "change_size", "repeats",
    "verify_mismatch", "capture_lost",
]


def run_point(cfg, peer, exp, arm_name, x_label, x_value,
              trial, file_size, change_size, repeats, seed):
    src = cfg["src"]
    cleanup_mod.cleanup(peer, cfg["work_dir"], src, cfg["peer_work_dir"])
    os.makedirs(src, exist_ok=True)

    rec = recorder_mod.ARMS[arm_name](
        peer=peer,
        capture_bin=cfg["capture_bin"],
        apply_bin=cfg["apply_bin"],
        remote_tmp=cfg["remote_tmp"],
    )

    row = {
        "exp": exp, "arm": arm_name, "x_label": x_label, "x_value": x_value,
        "trial": trial, "file_size": file_size, "change_size": change_size,
        "repeats": repeats, "sync_ms": "", "bytes_sent": "",
        "verify_mismatch": "", "capture_lost": 0,
    }

    rec.start(src)
    try:
        path = workload.populate_file(src, file_size, rec, seed)
        peer.seed(src)
        rec.drain()

        offset = workload.change_offset(file_size)
        workload.write_change(path, offset, change_size, repeats, seed + 1)

        elapsed, nbytes = rec.sync()
        row["sync_ms"] = round(elapsed * 1000, 3)
        row["bytes_sent"] = nbytes
        row["verify_mismatch"] = peer.verify(src)
    except recorder_mod.CaptureLost as e:
        row["capture_lost"] = 1
        print(f"  !! CAPTURE LOST: {e}", file=sys.stderr)
    finally:
        rec.stop()
        cleanup_mod.cleanup(peer, cfg["work_dir"], src, cfg["peer_work_dir"])

    return row


def _open_csv(out_csv, fresh):
    existing = 0
    if os.path.exists(out_csv) and not fresh:
        with open(out_csv, newline="") as f:
            rows = list(csv.reader(f))
        if rows and rows[0] == FIELDS:
            existing = len(rows) - 1
            print(f"melanjutkan {out_csv} ({existing} baris sudah ada; "
                  f"--fresh untuk menimpa)")
            return open(out_csv, "a", newline=""), False
        print(f"peringatan: {out_csv} ada tapi headernya beda -- ditimpa")
    return open(out_csv, "w", newline=""), True


def sweep(cfg, peer, exp, x_label, points, trials, out_csv, base_seed=1,
          fresh=False):
    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    write_manifest(cfg, exp, x_label, points, trials, out_csv)

    f, need_header = _open_csv(out_csv, fresh)
    with f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if need_header:
            w.writeheader()

        for trial in range(trials):
            for arm_name in cfg["arms"]:
                for i, point in enumerate(points):
                    seed = base_seed + trial * 1000 + i

                    label = (f"{exp} {arm_name:<5} {x_label}={point['x_value']:<8} "
                             f"trial={trial}")
                    print(f"\n=== {label} ===")
                    t0 = time.time()
                    row = run_point(
                        cfg, peer, exp, arm_name, x_label, point["x_value"],
                        trial, point["file_size"], point["change_size"],
                        point["repeats"], seed)
                    w.writerow(row)
                    f.flush()

                    status = "OK"
                    if row["capture_lost"]:
                        status = "CAPTURE LOST -- dibuang"
                    elif row["verify_mismatch"] != 0:
                        status = f"GAGAL VERIFIKASI ({row['verify_mismatch']} beda)"
                    print(f"  sync={row['sync_ms']} ms  bytes={row['bytes_sent']}  "
                          f"[{time.time() - t0:.0f}s wall]  {status}")

    print(f"\nselesai -> {out_csv}")


def write_manifest(cfg, exp, x_label, points, trials, out_csv):
    manifest = {
        "experiment": exp,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "hostname": socket_mod.gethostname(),
        "kernel": platform.release(),
        "rsync_version": _first_line(["rsync", "--version"]),
        "x_label": x_label,
        "trials": trials,
        "points": points,
        "config": {k: v for k, v in cfg.items() if k != "arms"} | {"arms": cfg["arms"]},
    }
    path = os.path.splitext(out_csv)[0] + ".manifest.json"
    history = []
    if os.path.exists(path):
        try:
            with open(path) as f:
                prev = json.load(f)
            history = prev if isinstance(prev, list) else [prev]
        except (OSError, ValueError):
            history = []
    history.append(manifest)
    with open(path, "w") as f:
        json.dump(history, f, indent=2)


def _first_line(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              check=False).stdout.splitlines()[0]
    except (OSError, IndexError):
        return "unknown"
