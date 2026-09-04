#!/usr/bin/env python3
import argparse
import os
import shlex
import subprocess
import sys
import uuid

import cdf
import experiment
import peer as peer_mod

MB = 1 << 20
DEFAULT_CHANGE = 4096


def build_cfg(args):
    work_dir = os.path.abspath(args.work_dir)
    peer_work_dir = os.path.abspath(args.peer_work_dir or args.work_dir)
    return {
        "work_dir": work_dir,
        "peer_work_dir": peer_work_dir,
        "src": os.path.join(work_dir, "src"),
        "dst": os.path.join(peer_work_dir, "dst"),
        "capture_bin": os.path.abspath(args.capture_bin),
        "apply_bin": os.path.join(peer_work_dir, "statediff_apply_vfs"),
        "remote_tmp": os.path.join(peer_work_dir, "batch.sd"),
        "service_bin": os.path.abspath(
            getattr(args, "service_bin", "services/todo-go/todo-go")),
        "arms": [a.strip() for a in args.arms.split(",") if a.strip()],
    }


def make_peer(args, cfg):
    return peer_mod.Peer(args.peer, cfg["dst"])


REJECTED_FS = {
    "tmpfs": "tmpfs -- berkas 1 GB akan memakan RAM dan perilaku "
             "filesystem-nya tidak representatif",
    "nfs": "NFS -- di CloudLab /users dan /proj dibagi antar-node, jadi "
           "sumber dan replika bisa jadi direktori fisik yang sama",
    "ramfs": "ramfs -- bukan disk nyata",
}


def ensure_dir_local(path):
    if os.path.isdir(path) and os.access(path, os.W_OK):
        return
    subprocess.run(["sh", "-c",
                    f"mkdir -p {shlex.quote(path)} 2>/dev/null || "
                    f"sudo -n mkdir -p {shlex.quote(path)}"], check=True)
    subprocess.run(["sh", "-c",
                    f"sudo -n chown $(id -u):$(id -g) {shlex.quote(path)} "
                    "2>/dev/null || true"], check=False)


def ensure_dir_peer(peer, path):
    q = shlex.quote(path)
    peer.run(f"mkdir -p {q} 2>/dev/null || sudo -n mkdir -p {q}")
    peer.run(f"sudo -n chown $(id -u):$(id -g) {q} 2>/dev/null || true",
             check=False)


def fs_type_local(path):
    return subprocess.run(["stat", "-f", "-c", "%T", path],
                          capture_output=True, text=True).stdout.strip()


def check_fs(label, fstype):
    for bad, why in REJECTED_FS.items():
        if fstype.startswith(bad):
            sys.exit(f"error: {label} adalah {why}. Pakai direktori di disk "
                     "lokal mesin itu sendiri.")


def check_not_shared(peer, cfg):
    if peer.is_local:
        return
    marker = os.path.join(cfg["work_dir"], f".probe-{uuid.uuid4().hex}")
    with open(marker, "w") as f:
        f.write("probe\n")
    try:
        out = peer.run(f"test -e {shlex.quote(marker)} && echo SHARED || echo SEPARATE",
                       check=False)
    finally:
        os.remove(marker)
    if "SHARED" in out:
        sys.exit(f"error: {cfg['work_dir']} terlihat dari kedua mesin -- "
                 "penyimpanannya dibagi (NFS?). Sumber dan replika akan "
                 "menjadi direktori yang sama dan seluruh eksperimen tidak "
                 "berarti. Pakai disk lokal di masing-masing mesin.")
    print("    penyimpanan  : terpisah antara primary dan backup (diverifikasi)")


def preflight(cfg, peer, args):
    if "ebpf" in cfg["arms"] and os.geteuid() != 0:
        sys.exit("error: lengan eBPF butuh root -- jalankan dengan sudo")
    if "ebpf" in cfg["arms"] and not os.path.exists(cfg["capture_bin"]):
        sys.exit(f"error: {cfg['capture_bin']} tidak ada -- "
                 "'cd native/ebpf && make clean && make' di mesin ini")
    if not os.path.isdir(cfg["work_dir"]):
        sys.exit(f"error: --work-dir {cfg['work_dir']} tidak ada")

    fstype = fs_type_local(cfg["work_dir"])
    check_fs(cfg["work_dir"], fstype)
    print(f"work_dir={cfg['work_dir']} (fs={fstype})  "
          f"peer={'lokal' if peer.is_local else args.peer}")


def cmd_setup(args):
    cfg = build_cfg(args)
    peer = make_peer(args, cfg)

    print("==> memastikan direktori kerja ada di kedua mesin")
    ensure_dir_local(cfg["work_dir"])
    ensure_dir_peer(peer, cfg["peer_work_dir"])

    if not peer.is_local:
        print("==> membuka kanal SSH multipleks")
        peer.run("true")
        print("==> biaya koneksi berikutnya (harus jauh di bawah 50 ms):")
        subprocess.run(["bash", "-c",
                        "time ssh " + " ".join(peer_mod.SSH_OPTS)
                        + f" {shlex.quote(args.peer)} true"],
                       env=peer_mod.ssh_env())

        print("==> mengirim statediff_apply_vfs ke peer")
        apply_src = os.path.join(os.path.dirname(cfg["capture_bin"]),
                                 "statediff_apply_vfs")
        subprocess.run(["scp"] + peer_mod.SSH_OPTS
                       + [apply_src, f"{args.peer}:{cfg['apply_bin']}"],
                       check=True, env=peer_mod.ssh_env())
        peer.run(f"chmod +x {shlex.quote(cfg['apply_bin'])}")
    else:
        apply_src = os.path.join(os.path.dirname(cfg["capture_bin"]),
                                 "statediff_apply_vfs")
        subprocess.run(["cp", apply_src, cfg["apply_bin"]], check=True)

    print("\n==> pemeriksaan")
    fs_here = fs_type_local(cfg["work_dir"])
    check_fs(f"work_dir primary {cfg['work_dir']}", fs_here)
    print(f"    fs primary   : {fs_here}")
    if not peer.is_local:
        fs_there = peer.run(
            f"stat -f -c %T {shlex.quote(cfg['peer_work_dir'])}").strip()
        check_fs(f"work_dir backup {cfg['peer_work_dir']}", fs_there)
        print(f"    fs backup    : {fs_there}")
    check_not_shared(peer, cfg)
    print("    kernel BTF   :", "ada" if os.path.exists("/sys/kernel/btf/vmlinux")
          else "TIDAK ADA -- capturer tidak akan bisa jalan")
    print("    ruang kosong :")
    subprocess.run(["df", "-h", cfg["work_dir"]])

    print("\nCatatan: statediff_apply_vfs tidak memuat program BPF, jadi aman "
          "disalin antarmesin.\n"
          "statediff_vfs (penangkap) TIDAK aman disalin -- ia harus dibangun "
          "ulang di mesin tempat ia berjalan.")


def cmd_a2(args):
    cfg = build_cfg(args)
    peer = make_peer(args, cfg)
    preflight(cfg, peer, args)

    points = [
        {"x_value": s, "file_size": s * MB, "change_size": args.change_size,
         "repeats": 1}
        for s in [int(x) for x in args.sizes.split(",")]
    ]
    experiment.sweep(cfg, peer, "a2", "file_size_mb", points,
                     args.trials, args.out, fresh=args.fresh)


def cmd_cdf_fs(args):
    args.arms = args.conds
    cfg = build_cfg(args)
    preflight(cfg, make_peer(args, cfg), args)
    cdf.sweep(cfg, "cdf_fs", cdf.run_fs_once, args.trials, args.out,
              conds=cfg["arms"], ops=args.ops, warmup=args.warmup,
              write_size=args.write_size, file_size=args.file_size_mb * MB)


def cmd_cdf_db(args):
    args.arms = args.conds
    cfg = build_cfg(args)
    preflight(cfg, make_peer(args, cfg), args)
    if not os.path.exists(cfg["service_bin"]):
        sys.exit(f"error: {cfg['service_bin']} tidak ada -- "
                 "'cd services/todo-go && go build -o todo-go .'")
    cdf.sweep(cfg, "cdf_db", cdf.run_db_once, args.trials, args.out,
              conds=cfg["arms"], ops=args.ops, warmup=args.warmup,
              port=args.port)


def cmd_a3(args):
    cfg = build_cfg(args)
    peer = make_peer(args, cfg)
    preflight(cfg, peer, args)

    file_size = args.file_size_mb * MB
    points = [
        {"x_value": r, "file_size": file_size, "change_size": args.change_size,
         "repeats": r}
        for r in [int(x) for x in args.repeats.split(",")]
    ]
    experiment.sweep(cfg, peer, "a3", "repeats", points,
                     args.trials, args.out, fresh=args.fresh)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--peer", default="",
                       help="user@internal-ip mesin replika; kosong = lokal")
        p.add_argument("--work-dir", required=True,
                       help="direktori kerja di mesin ini (JANGAN /tmp -- sering tmpfs)")
        p.add_argument("--peer-work-dir", default=None,
                       help="direktori kerja di peer (default: sama dengan --work-dir)")
        p.add_argument("--capture-bin", default="native/ebpf/statediff_vfs")
        p.add_argument("--arms", default="ebpf,rsync")

    p = sub.add_parser("setup", help="siapkan peer sekali per sesi")
    common(p)
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("a2", help="biaya sinkronisasi vs ukuran berkas")
    common(p)
    p.add_argument("--sizes", default="10,50,200,500,1000",
                   help="ukuran berkas dalam MB")
    p.add_argument("--change-size", type=int, default=DEFAULT_CHANGE)
    p.add_argument("--trials", type=int, default=3)
    p.add_argument("--out", default="results/a2.csv")
    p.add_argument("--fresh", action="store_true",
                   help="timpa CSV yang ada, jangan menambah")
    p.set_defaults(func=cmd_a2)

    p = sub.add_parser("a3", help="biaya sinkronisasi vs jumlah tulis-ulang")
    common(p)
    p.add_argument("--file-size-mb", type=int, default=10,
                   help="tetap; 10 MB menyamai titik terkecil A2")
    p.add_argument("--repeats", default="1,10,100,1000,10000")
    p.add_argument("--change-size", type=int, default=DEFAULT_CHANGE)
    p.add_argument("--trials", type=int, default=3)
    p.add_argument("--out", default="results/a3.csv")
    p.add_argument("--fresh", action="store_true",
                   help="timpa CSV yang ada, jangan menambah")
    p.set_defaults(func=cmd_a3)

    p = sub.add_parser("cdf-fs", help="CDF latensi tulis filesystem, capture on/off")
    common(p)
    p.add_argument("--conds", default="off,ebpf", help="kondisi yang dijalankan")
    p.add_argument("--ops", type=int, default=5000)
    p.add_argument("--warmup", type=int, default=100)
    p.add_argument("--write-size", type=int, default=DEFAULT_CHANGE,
                   help="tetap; variabel kontrol, bukan variabel bebas")
    p.add_argument("--file-size-mb", type=int, default=10)
    p.add_argument("--trials", type=int, default=3)
    p.add_argument("--out", default="results/cdf_fs.csv")
    p.set_defaults(func=cmd_cdf_fs)

    p = sub.add_parser("cdf-db", help="CDF latensi POST todo+SQLite, capture on/off")
    common(p)
    p.add_argument("--conds", default="off,ebpf", help="kondisi yang dijalankan")
    p.add_argument("--ops", type=int, default=5000)
    p.add_argument("--warmup", type=int, default=100)
    p.add_argument("--port", type=int, default=18080)
    p.add_argument("--service-bin", default="services/todo-go/todo-go")
    p.add_argument("--trials", type=int, default=3)
    p.add_argument("--out", default="results/cdf_db.csv")
    p.set_defaults(func=cmd_cdf_db)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
