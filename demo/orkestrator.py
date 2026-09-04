import argparse
import os
import shlex
import subprocess
import sys

SINI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SINI)

import cleanup as cleanup_mod
import peer as peer_mod

import kasus
import layanan
import tampilan

NAMA_ARM = {"rsync": "rsync", "ebpf": "eBPF"}

KUNCI_KANDIDAT = ("id_demo", "id_cloudlab", "id_ed25519", "id_rsa", "id_ecdsa")


def cari_kunci_ssh(eksplisit):
    if eksplisit:
        return eksplisit if os.path.isfile(eksplisit) else None
    pengguna = os.environ.get("SUDO_USER")
    rumah = os.path.expanduser("~" + pengguna) if pengguna else os.path.expanduser("~")
    for nama in KUNCI_KANDIDAT:
        jalur = os.path.join(rumah, ".ssh", nama)
        if os.path.isfile(jalur):
            return jalur
    return None


def bangun_cfg(args):
    wd = os.path.abspath(args.work_dir)
    pwd_ = os.path.abspath(args.peer_work_dir or args.work_dir)
    return {
        "work_dir": wd,
        "peer_work_dir": pwd_,
        "src": os.path.join(wd, "src"),
        "dst": os.path.join(pwd_, "dst"),
        "capture_bin": os.path.abspath(args.capture_bin),
        "apply_bin": os.path.join(pwd_, "statediff_apply_vfs"),
        "remote_tmp": os.path.join(pwd_, "batch.sd"),
        "service_bin": os.path.abspath(args.service_bin),
        "peer_service_bin": os.path.join(pwd_, "todo-go"),
        "compose_file": os.path.abspath(args.compose_file),
        "apply_bin_lokal": os.path.join(SINI, "ebpf", "statediff_apply_vfs"),
    }


def kirim_ke_cadangan(peer, lokal, jauh):
    peer.run(f"mkdir -p {shlex.quote(os.path.dirname(jauh))}", check=False)
    p = subprocess.run(
        ["rsync", "-a"] + peer._remote_args() + [lokal, f"{peer.host}:{jauh}"],
        capture_output=True, text=True, env=peer_mod.ssh_env())
    if p.returncode == 0:
        return True, ""
    return False, (p.stderr.strip().splitlines() or ["rsync gagal"])[-1]


def prapemeriksaan(cfg, peer, db):
    tampilan.judul("PRAPEMERIKSAAN")
    masalah = []

    if os.geteuid() != 0:
        masalah.append("harus dijalankan sebagai root (pakai sudo)")
    tampilan.info("hak akses root", "ada" if os.geteuid() == 0 else "TIDAK ADA")

    for label, jalur in (("biner penangkap", cfg["capture_bin"]),
                         ("biner Todo Service", cfg["service_bin"])):
        ada = os.access(jalur, os.X_OK)
        tampilan.info(label, jalur if ada else f"TIDAK ADA -> {jalur}")
        if not ada:
            masalah.append(f"{label} tidak ada atau tidak dapat dieksekusi")

    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        masalah.append("kernel tanpa BTF, penangkap eBPF tidak akan dimuat")
    tampilan.info("BTF kernel",
                  "ada" if os.path.exists("/sys/kernel/btf/vmlinux") else "TIDAK ADA")

    kunci = [o for i, o in enumerate(peer_mod.SSH_OPTS)
             if i and peer_mod.SSH_OPTS[i - 1] == "-i"]
    tampilan.info("kunci SSH", kunci[0] if kunci else "agent / bawaan ssh")

    try:
        nama = peer.run("hostname").strip()
        tampilan.info("mesin cadangan", f"{peer.host} ({nama})")
    except Exception as e:
        tampilan.info("mesin cadangan", f"TIDAK TERJANGKAU -> {e}")
        masalah.append("mesin cadangan tidak terjangkau lewat SSH")
        if "publickey" in str(e):
            masalah.append(
                "sudo membuang SSH_AUTH_SOCK sehingga agent tidak terbawa. "
                "Beri --ssh-key <berkas>, atau jalankan dengan "
                "sudo SSH_AUTH_SOCK=$SSH_AUTH_SOCK python3 orkestrator.py")
        cetak_masalah(masalah)
        return False

    for label, lokal, jauh in (
            ("biner penerap di cadangan",
             cfg["apply_bin_lokal"], cfg["apply_bin"]),
            ("biner Todo Service di cadangan",
             cfg["service_bin"], cfg["peer_service_bin"])):
        ada = peer.run(f"test -x {shlex.quote(jauh)} && echo ya || echo tidak",
                       check=False).strip() == "ya"
        if ada:
            tampilan.info(label, jauh)
            continue
        if not os.path.isfile(lokal):
            tampilan.info(label, f"SUMBERNYA TIDAK ADA -> {lokal}")
            masalah.append(f"{label}: berkas sumber {lokal} tidak ada di mesin ini. "
                           f"Jalankan: make -C {os.path.dirname(lokal)}")
            continue
        berhasil, pesan = kirim_ke_cadangan(peer, lokal, jauh)
        if berhasil:
            tampilan.info(label, f"{jauh} (baru dikirim)")
        else:
            tampilan.info(label, f"GAGAL DIKIRIM -> {pesan}")
            masalah.append(f"{label}: pengiriman gagal, {pesan}")

    if db == "postgres":
        ada_compose = os.path.isfile(cfg["compose_file"])
        tampilan.info("berkas docker-compose",
                      cfg["compose_file"] if ada_compose else "TIDAK ADA")
        if not ada_compose:
            masalah.append("berkas docker-compose.yml tidak ada")

        lokal = subprocess.run(
            ["sh", "-c", "docker compose version --short 2>/dev/null"],
            capture_output=True, text=True).stdout.strip()
        jauh = peer.run("sudo -n docker compose version --short 2>/dev/null || true",
                        check=False).strip()
        for nama_sisi, versi in (("Docker Compose di mesin utama", lokal),
                                 ("Docker Compose di cadangan", jauh)):
            tampilan.info(nama_sisi, f"v{versi}" if versi else "TIDAK TERPASANG")
            if not versi:
                masalah.append(f"{nama_sisi} tidak terpasang, lihat README")

    cetak_masalah(masalah)
    return not masalah


def cetak_masalah(masalah):
    if masalah:
        tampilan.galat("prapemeriksaan gagal:")
        for m in masalah:
            print(f"     - {m}")
    else:
        print()
        print("  -> SIAP")


def _matikan_sisa(cfg, peer):
    turun = ("%s docker compose -p %s down --remove-orphans "
             ">/dev/null 2>&1 || true")

    subprocess.run(["sh", "-c", turun % ("", layanan.PROYEK_UTAMA)],
                   capture_output=True)
    subprocess.run(["pkill", "-x", "todo-go"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    peer.run(turun % ("sudo -n", layanan.PROYEK_CADANGAN), check=False)
    peer.run("pkill -x todo-go || true", check=False)

    peer.run(f"sudo rm -rf {shlex.quote(cfg['dst'])} || true", check=False)


def bersihkan(cfg, peer):
    tampilan.bagian("PEMBERSIHAN")
    _matikan_sisa(cfg, peer)
    cleanup_mod.cleanup(peer, cfg["work_dir"], cfg["src"], cfg["peer_work_dir"])

    src_kosong = not os.path.exists(cfg["src"]) or not os.listdir(cfg["src"])
    dst_kosong = peer.run(
        f"if [ ! -d {shlex.quote(cfg['dst'])} ] || "
        f"[ -z \"$(ls -A {shlex.quote(cfg['dst'])} 2>/dev/null)\" ]; "
        f"then echo ya; else echo tidak; fi", check=False).strip() == "ya"
    penangkap = subprocess.run(["pgrep", "-x", "statediff_vfs"],
                               capture_output=True).returncode != 0
    todo_utama = subprocess.run(["pgrep", "-x", "todo-go"],
                                capture_output=True).returncode != 0
    todo_cadangan = peer.run("pgrep -x todo-go >/dev/null && echo ada || echo tidak",
                             check=False).strip() == "tidak"

    tampilan.info("direktori sumber", "kosong" if src_kosong else "MASIH BERISI")
    tampilan.info("direktori replika di cadangan",
                  "kosong" if dst_kosong else "MASIH BERISI")
    tampilan.info("proses penangkap", "tidak ada" if penangkap else "MASIH ADA")
    tampilan.info("proses Todo Service (2 mesin)",
                  ("tidak ada" if todo_utama else "MASIH ADA") + " / " +
                  ("tidak ada" if todo_cadangan else "MASIH ADA"))
    wadah = subprocess.run(
        ["sh", "-c", "docker ps -q --filter name=demo- 2>/dev/null | wc -l"],
        capture_output=True, text=True).stdout.strip() in ("", "0")
    wadah_cadangan = peer.run(
        "sudo -n docker ps -q --filter name=demo- 2>/dev/null | wc -l",
        check=False).strip() in ("", "0")
    tampilan.info("kontainer demo (2 mesin)",
                  ("tidak ada" if wadah else "MASIH ADA") + " / " +
                  ("tidak ada" if wadah_cadangan else "MASIH ADA"))
    tampilan.info("cache halaman", "dijatuhkan di kedua mesin")

    bersih = all([src_kosong, dst_kosong, penangkap, todo_utama, todo_cadangan,
                  wadah, wadah_cadangan])
    print()
    print("  -> BERSIH" if bersih else "  -> TIDAK BERSIH, kasus dibatalkan")
    return bersih


def kotak_terukur(nama_kasus, keterangan, hasil, catatan=None):
    isi = [f"{'mekanisme':<16}{'waktu sinkronisasi':>24}", ""]
    for arm in ("rsync", "ebpf"):
        if arm in hasil:
            isi.append(f"{NAMA_ARM[arm]:<16}{tampilan.ms(hasil[arm]['ms']):>24}")
    if len(hasil) == 2:
        r = hasil["rsync"]["ms"] / hasil["ebpf"]["ms"]
        isi.append("")
        label = "rsync lebih lambat" if r >= 1 else "eBPF lebih lambat"
        nilai = r if r >= 1 else 1 / r
        rasio = f"{nilai:.1f}".replace(".", ",") + "x"
        isi.append(f"{label:<16}{rasio:>24}")
    tampilan.kotak(f"HASIL - {nama_kasus} - {keterangan}", isi, catatan)


def kotak_kasus_3(db, arm, hasil, jumlah):
    cocok = hasil["terkirim"] == hasil["diterima"]
    isi = [
        f"{'punggung basis data':<32}{db}",
        f"{'mekanisme sinkronisasi':<32}{NAMA_ARM[arm]}",
        "",
        f"{'data dikirim di mesin utama':<32}{len(hasil['terkirim'])}",
        f"{'data dibaca di mesin cadangan':<32}{len(hasil['diterima'])}",
        f"{'isi keduanya':<32}"
        f"{'sama persis' if cocok else 'BERBEDA'}",
        "",
        f"{'layanan berjalan di':<32}{hasil['hostname']}",
        f"{'alamat mesin tersebut':<32}{hasil['ip']}",
    ]
    tampilan.kotak(f"HASIL - Kasus 3 - Todo Service + {db}", isi)


KASUS = {
    "1": ("Kasus 1", "berkas 50 MB, perubahan 4 KB"),
    "2": ("Kasus 2", "berkas 10 MB, ditulis 4 KB sebanyak 10.000 kali"),
    "3": ("Kasus 3", "Todo Service, alih layanan ke mesin cadangan"),
}


def menu_kasus():
    tampilan.judul("MENU")
    for k, (nama, ket) in KASUS.items():
        print(f"   {k}) {nama:<9} {ket}")
    print("   0) Keluar")
    print()
    return input("  pilih kasus > ").strip()


def menu_mekanisme(boleh_keduanya):
    print()
    print("   r) rsync      e) eBPF" + ("      b) keduanya" if boleh_keduanya else ""))
    while True:
        p = input("  pilih mekanisme > ").strip().lower()
        if p == "r":
            return ["rsync"]
        if p == "e":
            return ["ebpf"]
        if p == "b" and boleh_keduanya:
            return ["rsync", "ebpf"]
        print("  pilihan tidak dikenal")


CATATAN_KASUS_2 = (
    "Penangkap menyimpan setiap operasi tanpa penggabungan, sehingga artefaknya "
    "tumbuh sebanding dengan banyaknya penulisan meskipun perubahan akhirnya "
    "tetap 4 KB. rsync hanya melihat keadaan akhir, sehingga biayanya datar."
)


def jalankan(cfg, peer, pilihan, args):
    nama, ket = KASUS[pilihan]
    lengan = menu_mekanisme(boleh_keduanya=(pilihan != "3"))

    hasil = {}
    for arm in lengan:
        tampilan.judul(f"{nama} - {ket} - {NAMA_ARM[arm]}")
        if not bersihkan(cfg, peer):
            return
        try:
            if pilihan == "1":
                hasil[arm] = kasus.kasus_1(cfg, peer, arm)
            elif pilihan == "2":
                hasil[arm] = kasus.kasus_2(cfg, peer, arm)
            else:
                hasil[arm] = kasus.kasus_3(cfg, peer, arm, args.db, args.jumlah)
        except Exception as e:
            tampilan.galat(f"{nama} dengan {NAMA_ARM[arm]} gagal: {e}")
            return

    if pilihan == "1":
        kotak_terukur(nama, ket, hasil)
    elif pilihan == "2":
        kotak_terukur(nama, ket, hasil, CATATAN_KASUS_2)
    else:
        kotak_kasus_3(args.db, lengan[0], hasil[lengan[0]], args.jumlah)


def main():
    p = argparse.ArgumentParser(description="Demo replikasi direktori")
    p.add_argument("--peer", default="panjisri@10.10.1.4")
    p.add_argument("--ssh-key", default=None,
                   help="berkas kunci SSH; bawaan mencari di home pengguna sudo")
    p.add_argument("--work-dir", default="/var/tmp/demo")
    p.add_argument("--peer-work-dir", default=None)
    p.add_argument("--capture-bin",
                   default=os.path.join(SINI, "ebpf", "statediff_vfs"))
    p.add_argument("--service-bin",
                   default=os.path.join(SINI, "services", "todo-go", "todo-go"))
    p.add_argument("--compose-file",
                   default=os.path.join(SINI, "services", "todo-go",
                                        "docker-compose.yml"))
    p.add_argument("--port", type=int, default=8080,
                   help="port Todo Service di mesin utama; cadangan memakai +1")
    p.add_argument("--pg-port", type=int, default=5433,
                   help="port host untuk kontainer PostgreSQL")
    p.add_argument("--db", choices=("postgres", "sqlite"), default="postgres",
                   help="punggung basis data kasus 3")
    p.add_argument("--jumlah", type=int, default=10,
                   help="banyaknya permintaan pada kasus 3")
    args = p.parse_args()

    kunci = cari_kunci_ssh(args.ssh_key)
    if kunci:
        peer_mod.SSH_OPTS.extend(["-i", kunci])

    layanan.PG_PORT = args.pg_port
    layanan.PORT_UTAMA = args.port
    layanan.PORT_CADANGAN = args.port + 1
    cfg = bangun_cfg(args)
    peer = peer_mod.Peer(args.peer, cfg["dst"])

    if not prapemeriksaan(cfg, peer, args.db):
        return 1

    try:
        while True:
            pilihan = menu_kasus()
            if pilihan == "0":
                break
            if pilihan not in KASUS:
                print("  pilihan tidak dikenal")
                continue
            jalankan(cfg, peer, pilihan, args)
    except KeyboardInterrupt:
        print()
    finally:
        tampilan.judul("PEMBERSIHAN AKHIR")
        bersihkan(cfg, peer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
