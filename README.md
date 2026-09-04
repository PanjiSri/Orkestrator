# prototype

Harness untuk empat eksperimen Bab IV, dalam dua kelompok.

**A2/A3 — biaya saat sinkronisasi.** Keduanya adalah pengukuran yang sama
dengan parameter berbeda: bangun sebuah *state*, samakan replika dengannya,
lakukan satu perubahan terkendali, lalu ukur **satu** sinkronisasi.

**CDF — biaya pada jalur tulis aplikasi.** Latensi per operasi dengan
penangkapan hidup dan mati, untuk operasi filesystem mentah dan untuk layanan
nyata di atas SQLite.

Bersama-sama keduanya menyatakan seluruh argumen Bab IV: kedua mekanisme
membayar dengan besaran sebanding, tetapi di tempat yang berbeda — rsync saat
sinkronisasi, penangkapan saat aplikasi menulis.

| | Dikunci | Divariasikan | Yang dibuktikan |
|---|---|---|---|
| **A2** | perubahan 4 KB | ukuran berkas `S`: 10 → 1000 MB | biaya rsync ditentukan ukuran *state*; eBPF tidak |
| **A3** | satu berkas 10 MB | tulis-ulang `R`: 1 → 10000 | eBPF kalah saat rentang byte yang sama ditulis berulang |

| | Kondisi | Diukur | Yang dibuktikan |
|---|---|---|---|
| **cdf-fs** | `off` vs `ebpf` | latensi tiap `pwrite` 4 KB | besar biaya inline penangkapan, terisolasi |
| **cdf-db** | `off` vs `ebpf` | latensi tiap POST ke todo+SQLite | biaya itu pada aplikasi nyata, tanpa modifikasi apa pun (NF-2) |

Lima grafik dari keempat CSV: A2-waktu, A3-waktu, A3-byte, CDF-fs, CDF-db.

### Baseline CDF bukan aproksimasi rsync

rsync tidak menginstrumentasi apa pun, jadi biaya yang dibebankannya pada jalur
eksekusi aplikasi **nol secara konstruksi**. Kurva `off` **adalah** biaya
jalur-tulis rsync. Biaya rsync yang sebenarnya dibayar di tempat lain — saat
sinkronisasi — dan itu yang sudah diukur A2 dan A3.

Yang **tidak** diukur di sini: rebutan CPU dan I/O yang ditimbulkan rsync pada
aplikasi selama ia memindai. Tidak ada sinkronisasi yang berjalan saat
pengukuran CDF. Sebutkan sebagai batasan, jangan diklaim.

## Uji konsistensi silang

A3 pada `R = 1` dan A2 pada `S = 10 MB` adalah percobaan yang **identik** —
ukuran berkas, offset, isi, dan benih RNG-nya sama persis. Kedua angka harus
cocok. Kalau tidak, ada yang rusak di harness dan kamu tahu sebelum menulis
Bab IV.

## Isi

| Berkas | Isi |
|---|---|
| `run.py` | CLI: `setup`, `a2`, `a3` |
| `peer.py` | Replika lokal atau `user@internal-ip`. SSH multipleks, penyemaian, verifikasi |
| `recorder.py` | `RsyncRecorder` dan `EbpfRecorder` di balik antarmuka yang sama |
| `workload.py` | Pembangun berkas per potongan, penulis perubahan terkendali |
| `cleanup.py` | Pembersihan berpagar, sebelum dan sesudah tiap titik |
| `experiment.py` | Bentuk pengukuran bersama, CSV, manifes |
| `native/ebpf/` | Salinan penuh capturer. **Jangan pindahkan `statediff_vfs` antarmesin** |

## Peta mesin

| Peran | Node | Host | Yang berjalan di sana |
|---|---|---|---|
| **PRIMARY** | node4 | `clnode387` | harness, direktori sumber, `statediff_vfs`, beban tulis |
| **BACKUP** | node3 | `clnode393` | direktori replika, `statediff_apply_vfs` |

Harness dijalankan **di primary**. `--peer` menunjuk ke **backup**. Perubahan
terjadi di primary, artefaknya diseberangkan, lalu diterapkan di backup.

## Menyiapkan CloudLab

Dari laptop, kirim ke **primary**:

```bash
rsync -a --exclude '__pycache__' --exclude 'results/*.csv' \
  prototype/ panjisri@clnode387.clemson.cloudlab.us:~/prototype/
```

### Memilih `--work-dir`

Harus **disk lokal di masing-masing mesin**, dengan ≥10 GB kosong. Cek dulu:

```bash
df -h /var/tmp /mnt 2>/dev/null; lsblk
```

`/var/tmp/exp` biasanya pilihan paling mudah: ia ada di root filesystem (disk
nyata), mode 1777 sehingga tidak perlu `sudo` untuk membuatnya. Kalau root
filesystem terlalu kecil, pakai disk lokal yang termount (mis. `/mnt/exp`) —
`setup` akan membuatnya lewat `sudo -n` kalau perlu.

**Jangan pakai `/users/panjisri` atau `/proj/...`.** Keduanya NFS yang dibagi
antar-node CloudLab, jadi sumber dan replika akan menjadi direktori fisik yang
sama: rsync tidak mengirim apa pun, verifikasi selalu lolos, dan seluruh
pengukuran tidak berarti. `setup` menolak keduanya, dan juga membuktikan secara
langsung bahwa kedua direktori kerja benar-benar terpisah dengan menaruh berkas
penanda di primary lalu memastikan ia **tidak** terlihat dari backup.

`/tmp` juga ditolak kalau ternyata tmpfs.

### Perintah

Di **primary (node4, clnode387)** — hanya di sini toolchain BPF diperlukan:

```bash
sudo apt install -y clang llvm libelf-dev zlib1g-dev rsync
cd ~/prototype/native/ebpf && make clean && make && cd ~/prototype

python3 run.py setup --peer panjisri@<INTERNAL-IP-node3> --work-dir /var/tmp/exp
```

Di **backup (node3, clnode393)** — tidak perlu toolchain, tidak perlu membuat
direktori (`setup` yang membuatnya dari primary):

```bash
sudo apt install -y rsync
```

`statediff_apply_vfs` hanya tertaut libc (tidak memuat program BPF), jadi
`run.py setup` cukup menyalinnya dari primary. Yang **tidak boleh** disalin
adalah `statediff_vfs`: skeleton BPF-nya diturunkan dari BTF kernel yang sedang
berjalan, jadi ia harus dibangun di mesin tempat ia dijalankan.

`setup` membuat direktori kerja di kedua mesin, membuka kanal SSH multipleks,
mengirim `statediff_apply_vfs` ke backup, memeriksa jenis filesystem di kedua
sisi, membuktikan keduanya bukan penyimpanan yang sama, lalu memeriksa BTF dan
ruang kosong.

## Menjalankan

```bash
sudo python3 run.py a2 --peer panjisri@<INTERNAL-IP-node3> --work-dir /var/tmp/exp --trials 3
sudo python3 run.py a3 --peer panjisri@<INTERNAL-IP-node3> --work-dir /var/tmp/exp --trials 3
```

**Harus `sudo`.** Capturer meng-`chmod 0600` soketnya, jadi hanya pengguna yang
menjalankannya yang bisa connect. Sebagai gantinya `HOME` untuk subproses `ssh`
diarahkan ke home pengguna asli (lewat `SUDO_USER`), supaya `ssh` tetap
menemukan kunci CloudLab meskipun berjalan sebagai root.

Sanity check lokal — tanpa `--peer`, jalur kode identik:

```bash
python3 run.py setup --work-dir ~/proto-exp --arms rsync
python3 run.py a2 --arms rsync --work-dir ~/proto-exp --sizes 4,16,64 --trials 1
```

## Urutan tiap titik

```
cleanup (pkill, rm -rf berpagar, drop_caches)
mkdir src kosong
start recorder            eBPF: pada direktori KOSONG | rsync: no-op
populate berkas           per potongan 64 MB, batch dibuang tiap potongan
rsync -a src/ peer:dst/   semai — replika identik
buang batch               recorder bersih
tulis perubahan terkendali
⏱  SATU sinkronisasi, diukur
verifikasi                wajib 0 beda
stop recorder + cleanup
```

## Kolom CSV

`sync_ms` sumbu-Y A2 dan A3-waktu · `bytes_sent` sumbu-Y A3-byte, dan kontrol
untuk A2 (kedua lengan mengirim byte yang mirip, jadi selisih waktu di A2 tidak
bisa dijelaskan oleh volume transfer) · `verify_mismatch` bukan nol berarti
percobaan gagal, bukan percobaan cepat · `capture_lost` = 1 berarti capturer
melaporkan penangkapan tidak lengkap dan titik itu dibuang.

Tiap sweep juga menulis `<out>.manifest.json`: versi kernel, versi rsync,
konfigurasi, waktu mulai.

## Dua hal yang sudah menggigit, dan sudah ditangani

**1. Pemeriksaan cepat rsync bekerja pada resolusi satu detik.**
Perubahan di sini tidak mengubah panjang berkas, jadi perubahan yang jatuh pada
detik yang sama dengan penyemaian **tidak terlihat oleh rsync** — ia tidak
mengirim apa pun dan replika diam-diam salah. `write_change()` karena itu
menunggu sampai jam melewati batas detik berikutnya, lalu memeriksa bahwa mtime
benar-benar maju. Aplikasi nyata menulis berdetik atau bermenit setelah
sinkronisasi sebelumnya; hanya harness ini yang memampatkan keduanya ke satu
detik, jadi penungguan itu membuang artefak, bukan memberi rsync keuntungan.

**2. Memori saat populate.** Recorder sudah menyala sebelum berkas dibuat (ia
hanya melihat operasi setelah start), jadi membuat berkas 1 GB akan menumpuk
batch 1 GB di memori dan bisa memicu penghitung kehilangan. Populate menulis
per potongan 64 MB dan membuang batch tiap potongan.

## Catatan pengukuran untuk Bab IV

- **Cache halaman hangat secara alami** (populate → semai → ukur). Itu kondisi
  terbaik rsync, jadi hasilnya konservatif terhadap klaim kita.
- **`--no-whole-file` dipasang eksplisit**, supaya algoritma delta rsync juga
  berjalan pada sanity check lokal. Tanpa itu rsync menyalin berkas utuh untuk
  transfer lokal dan angka lokal tidak sebanding bentuknya dengan CloudLab.
- **`bytes_sent` rsync naik seiring `S`** untuk perubahan 4 KB yang sama
  (~20 KB pada 16 MB, ~41 KB pada 64 MB), karena ukuran blok default rsync
  tumbuh kira-kira seakar ukuran berkas. Temuan pendukung gratis untuk A2.

## Yang akan kamu lihat di CDF, dan cara membacanya

Baseline `pwrite` 4 KB di mesin pengembangan: p50 ≈ 2,0 µs, p99 ≈ 2,8 µs —
distribusi yang sangat rapat, jadi biaya inline penangkapan akan terlihat jelas
di `cdf-fs`.

Baseline POST todo+SQLite: p50 ≈ 4,9 ms, throughput ≈ 200 ops/s — didominasi
`fsync` dari `synchronous=FULL`. **Perkirakan biaya penangkapan tidak
terdistingusi di `cdf-db`**, karena beberapa mikrodetik hilang di bawah
milidetik `fsync`.

Itu bukan kegagalan eksperimen, itu hasilnya: `cdf-fs` memberi besaran biaya
inline secara terisolasi, `cdf-db` menunjukkan besaran itu tenggelam pada jalur
tulis basis data yang benar-benar durable. Laporkan **selisih absolut dalam
mikrodetik**, bukan rasio — harness Python menambah ~1 µs yang identik di kedua
kondisi, jadi selisihnya tetap benar sementara rasionya tertekan.

## Sudah diverifikasi

Seluruh modul kompilasi bersih. `setup`, `a2`, dan `a3` sudah dijalankan
end-to-end untuk **lengan rsync** secara lokal: pembangunan berkas, penyemaian,
perubahan terkendali, sinkronisasi berwaktu, verifikasi (0 beda di semua titik),
CSV, dan manifes.

Hasil smoke A3 sudah menunjukkan garis dasar yang diharapkan: `bytes_sent`
rsync **datar** di ~19,58 KB untuk `R` = 1, 100, dan 1000.

`cdf-fs` dan `cdf-db` juga sudah dijalankan end-to-end pada kondisi `off`:
pembuatan berkas, warm-up, 3.000 `pwrite` berwaktu, start/health-poll/stop
layanan todo-go, 800 POST closed-loop pada satu koneksi persisten, penulisan
sampel dan ringkasan. Biner `todo-go` prabangun berjalan apa adanya di sini;
kalau ia gagal di CloudLab (ia tertaut dinamis lewat cgo), bangun ulang dengan
`cd services/todo-go && go build -o todo-go .`

**Lengan eBPF belum pernah dijalankan** — mesin pengembangan meminta kata sandi
untuk `sudo`. Konstanta protokol dicocokkan terhadap
`native/ebpf/include/statediff_vfs.h` dan bentuk argumen terhadap
`statediff_vfs.c`, tetapi jalur itu harus dijalankan sekali sebelum datanya
dipercaya.
# Orkestrator
