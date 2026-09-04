# prototype

## Struktur

```
prototype/
├── run.py                       orkestrator eksperimen: setup, a2, a3, cdf-fs, cdf-db
├── experiment.py                bentuk pengukuran bersama, CSV, manifes
├── cdf.py                       pengukuran distribusi latensi jalur tulis
├── recorder.py                  RsyncRecorder dan EbpfRecorder
├── peer.py                      replika lokal atau user@ip lewat SSH
├── workload.py                  pembangun berkas dan penulis perubahan
├── cleanup.py                   pembersihan sebelum dan sesudah tiap titik
├── plot/                        plot_a2.py, plot_a3.py, plot_sosp.py
├── results/                     CSV, manifes, dan gambar hasil
├── native/ebpf/                 penangkap dan penerap eBPF
│   ├── statediff_vfs.bpf.c      program BPF
│   ├── statediff_vfs.c          pemuat, penangkap, server soket
│   ├── statediff_apply_vfs.c    penerap batch di mesin cadangan
│   ├── include/statediff_vfs.h  format batch dan protokol soket
│   ├── Makefile
│   └── libbpf-bootstrap/        vendored
├── services/todo-go/            Todo Service, proyek Go
└── demo/                        demo dua mesin, berdiri sendiri
    ├── orkestrator.py           orkestrator demo: prapemeriksaan, menu, hasil
    ├── kasus.py                 tiga kasus demo
    ├── layanan.py               Todo Service dan basis data di kedua mesin
    ├── tampilan.py              keluaran terminal
    ├── setup.sh                 pasang dependensi, bangun penangkap, kirim biner
    ├── recorder.py peer.py workload.py cleanup.py   salinan modul harness
    ├── ebpf/                    salinan native/ebpf
    └── services/todo-go/        salinan services/todo-go
```

## Menjalankan orkestrator

Eksperimen, dari `prototype/` di mesin utama:

```bash
python3 run.py setup --peer <user@ip-cadangan> --work-dir /var/tmp/exp

sudo python3 run.py a2     --peer <user@ip-cadangan> --work-dir /var/tmp/exp --trials 3
sudo python3 run.py a3     --peer <user@ip-cadangan> --work-dir /var/tmp/exp --trials 3
sudo python3 run.py cdf-fs --work-dir /var/tmp/exp --trials 3
sudo python3 run.py cdf-db --work-dir /var/tmp/exp --trials 3
```

Grafik dari CSV di `results/`:

```bash
python3 plot/plot_sosp.py results results/not_zero
```

Demo, dari `demo/`:

```bash
./setup.sh <user@ip-cadangan> /var/tmp/demo
sudo python3 orkestrator.py --peer <user@ip-cadangan> --work-dir /var/tmp/demo --db postgres
```

## Menjalankan program eBPF

Bangun di mesin yang akan menjalankannya; skeleton BPF diturunkan dari BTF
kernel yang membangunnya. Butuh clang, llvm, libelf, zlib, dan kernel ber-BTF.

```bash
cd native/ebpf && make
```

Mode berkas, satu batch ditulis saat `SIGINT` atau `SIGTERM`:

```bash
sudo ./statediff_vfs <dir-sumber> keluaran.sd
./statediff_apply_vfs keluaran.sd <dir-tujuan>
```

Mode soket, dipakai `run.py` dan `orkestrator.py`. Klien mengirim satu byte
`g`, balasannya panjang 8 byte little-endian lalu batch:

```bash
sudo ./statediff_vfs --socket /tmp/statediff.sock <dir-sumber>
```

Hanya `statediff_apply_vfs` yang boleh disalin ke mesin cadangan.

## Menjalankan Todo Service

```bash
cd services/todo-go && go build -o todo-go .
```

SQLite:

```bash
PORT=8080 DB_TYPE=sqlite ENABLE_WAL=true ./todo-go
```

PostgreSQL:

```bash
PORT=8080 DB_TYPE=postgres DB_HOST=127.0.0.1 DB_PORT=5433 \
  DB_USER=postgres DB_PASSWORD=root DB_NAME=tasks DB_SSLMODE=disable ./todo-go
```

Kontainer basis datanya ada di `demo/services/todo-go/docker-compose.yml`.
