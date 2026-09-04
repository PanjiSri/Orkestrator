import os

import recorder as recorder_mod
import workload

import layanan
import tampilan

MB = 1 << 20

BENIH_KASUS_1 = 1 + 1
BENIH_KASUS_2 = 1 + 4


def _perekam(cfg, peer, arm):
    return recorder_mod.ARMS[arm](
        peer=peer,
        capture_bin=cfg["capture_bin"],
        apply_bin=cfg["apply_bin"],
        remote_tmp=cfg["remote_tmp"],
    )


def _sinkronisasi_terukur(cfg, peer, arm, ukuran_berkas, ukuran_perubahan,
                          pengulangan, benih):
    src = cfg["src"]
    os.makedirs(src, exist_ok=True)
    rec = _perekam(cfg, peer, arm)

    tampilan.bagian("PERSIAPAN")
    tampilan.tahap(1, 3, "menyalakan perekam pada direktori kosong")
    rec.start(src)
    try:
        tampilan.tahap(2, 3, f"membangun berkas {ukuran_berkas // MB} MB "
                             f"di direktori sumber")
        path = workload.populate_file(src, ukuran_berkas, rec, benih)

        tampilan.tahap(3, 3, "menyamakan replika lalu mengosongkan batch perekam")
        peer.seed(src)
        rec.drain()

        tampilan.bagian("PENJALANAN")
        offset = workload.change_offset(ukuran_berkas)
        if pengulangan == 1:
            tampilan.baris(f"menulis {ukuran_perubahan // 1024} KB pada offset "
                           f"{offset:,}".replace(",", "."))
        else:
            tampilan.baris(f"menulis {ukuran_perubahan // 1024} KB sebanyak "
                           f"{pengulangan:,} kali pada offset yang sama"
                           .replace(",", "."))
        tampilan.baris("menunggu jam melewati batas detik berikutnya")
        workload.write_change(path, offset, ukuran_perubahan, pengulangan,
                              benih + 1)

        tampilan.ukur("SINKRONISASI DIUKUR")
        detik, nbytes = rec.sync()
        return {"ms": detik * 1000, "bytes": nbytes}
    finally:
        rec.stop()


def kasus_1(cfg, peer, arm):
    return _sinkronisasi_terukur(cfg, peer, arm, 50 * MB, 4096, 1,
                                 BENIH_KASUS_1)


def kasus_2(cfg, peer, arm):
    return _sinkronisasi_terukur(cfg, peer, arm, 10 * MB, 4096, 10000,
                                 BENIH_KASUS_2)


def kasus_3(cfg, peer, arm, db, jumlah):
    src, dst = cfg["src"], cfg["dst"]
    total = 5 if db == "postgres" else 4
    pemilik_pgdata = None
    n = 0
    rec = _perekam(cfg, peer, arm)
    proc = None

    tampilan.bagian("PERSIAPAN")
    n += 1
    tampilan.tahap(n, total, "menyalakan perekam pada direktori kosong")
    os.makedirs(src, exist_ok=True)
    rec.start(src)
    try:
        if db == "postgres":
            n += 1
            tampilan.tahap(n, total, "menjalankan kontainer PostgreSQL dengan "
                                     "direktori datanya di dalam direktori sumber")
            layanan.pg_naik_lokal(cfg["compose_file"], src)

        n += 1
        tampilan.tahap(n, total, f"menjalankan Todo Service di mesin utama "
                                 f"port {layanan.PORT_UTAMA}")
        proc = layanan.jalankan_utama(cfg["service_bin"], src, db)

        n += 1
        tampilan.tahap(n, total, "menyamakan replika")
        peer.seed(src)

        n += 1
        tampilan.tahap(n, total, "mengosongkan batch perekam")
        rec.drain()

        tampilan.bagian("PENJALANAN")
        tampilan.baris(f"mengirim {jumlah} permintaan POST ke mesin utama")
        terkirim = layanan.kirim_post(layanan.PORT_UTAMA, jumlah, "tugas")
        for it in terkirim:
            print(f"          POST  {it}")

        tampilan.baris("menghentikan Todo Service di mesin utama")
        layanan.hentikan_utama(proc)
        proc = None
        if db == "postgres":
            pemilik_pgdata = layanan.pg_pemilik(src)
            tampilan.baris("menghentikan kontainer PostgreSQL di mesin utama")
            layanan.pg_turun_lokal(cfg["compose_file"], src)

        tampilan.ukur("SINKRONISASI")
        detik, nbytes = rec.sync()
        tampilan.baris("artefak diterapkan pada direktori replika")

        tampilan.bagian("MESIN CADANGAN")
        if db == "postgres":
            tampilan.baris("menjalankan kontainer PostgreSQL atas direktori "
                           "data hasil replikasi")
            layanan.pg_naik_cadangan(peer, cfg["compose_file"], dst,
                                     pemilik_pgdata)
        tampilan.baris(f"menjalankan Todo Service port {layanan.PORT_CADANGAN}")
        layanan.jalankan_cadangan(peer, cfg["peer_service_bin"], dst, db)

        nama, ip = layanan.identitas_cadangan(peer)
        tampilan.baris(f"layanan berjalan di {nama} ({ip})")

        diterima, _ = layanan.get_cadangan(peer)
        for it in diterima:
            print(f"          GET   {it}")

        return {"terkirim": terkirim, "diterima": diterima,
                "hostname": nama, "ip": ip, "bytes": nbytes}
    finally:
        if proc:
            layanan.hentikan_utama(proc)
        rec.stop()
