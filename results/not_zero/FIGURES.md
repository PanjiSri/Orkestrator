# Gambar Bab IV — angka dan caption

Semua titik: 3 ulangan, `verify_mismatch = 0` dan `capture_lost = 0` di
seluruh baris. Galat pada gambar adalah rentang min–maks antar-ulangan.

Berkas: `.pdf` untuk disisipkan ke LaTeX, `.png` untuk pratinjau.
---

## a2_time — biaya sinkronisasi vs ukuran state

| Ukuran berkas | rsync | eBPF | rasio |
|---|---|---|---|
| 10 MB | 75.8 ms | 10.3 ms | 7x |
| 50 MB | 161.1 ms | 10.0 ms | 16x |
| 200 MB | 465.1 ms | 10.1 ms | 46x |
| 500 MB | 1.029.0 ms | 10.2 ms | 101x |
| 1000 MB | 1.988.2 ms | 10.2 ms | 196x |

> Gambar IV.x Biaya menghasilkan satu artefak perubahan terhadap ukuran
> berkas yang sudah ada, dengan volume perubahan tetap 4 KB. Biaya rsync
> tumbuh sebanding ukuran state karena kedua sisi harus membaca berkas
> secara utuh untuk menentukan blok mana yang berbeda; biaya penangkapan
> tidak bergerak karena isi perubahan sudah dipegang saat operasi terjadi.

## a2_bytes — data terkirim (kontrol)

| Ukuran berkas | rsync | eBPF |
|---|---|---|
| 10 MB | 19.1 KB | 4.1 KB |
| 50 MB | 42.5 KB | 4.1 KB |
| 200 MB | 70.8 KB | 4.1 KB |
| 500 MB | 111.9 KB | 4.1 KB |
| 1000 MB | 158.3 KB | 4.1 KB |

> Gambar IV.x Data yang menyeberang ke replika untuk perubahan 4 KB yang
> sama. Kedua mekanisme mengirim byte dalam orde yang sama, sehingga
> selisih waktu pada Gambar sebelumnya tidak dapat dijelaskan oleh volume
> transfer. Kenaikan landai pada rsync berasal dari ukuran blok bawaannya
> yang tumbuh kira-kira seakar ukuran berkas.

## a3_time / a3_bytes — biaya vs tulis-ulang

| R | rsync (ms) | eBPF (ms) | rsync (byte) | eBPF (byte) |
|---|---|---|---|---|
| 1 | 75.3 | 10.2 | 19.1 KB | 0.00 MB |
| 10 | 75.3 | 10.4 | 19.1 KB | 0.04 MB |
| 100 | 75.6 | 12.7 | 19.1 KB | 0.40 MB |
| 1000 | 75.3 | 43.8 | 19.1 KB | 3.96 MB |
| 10000 | 75.5 | 269.8 | 19.1 KB | 39.60 MB |

Titik potong: **R ~ 2.000** dalam waktu, **R ~ 5** dalam byte.

> Gambar IV.x Biaya sinkronisasi ketika rentang 4 KB yang sama ditulis
> ulang R kali sebelum sinkronisasi. Berapa pun R, yang benar-benar
> berbeda di akhir tetap 4 KB, sehingga biaya rsync datar. Perekam
> menyimpan setiap operasi tanpa penggabungan, sehingga artefaknya tumbuh
> linier terhadap R dan menyalip rsync.

## cdf_fs — latensi satu pwrite 4 KB

| | p50 | p90 | p99 |
|---|---|---|---|
| tanpa perekam | 1.8 us | 2.2 us | 2.5 us |
| eBPF | 4.8 us | 5.4 us | 6.2 us |
| **selisih** | **+3.0** | **+3.2** | **+3.8** |

45.000 sampel per kondisi (3 ulangan x 5.000). digabung.
Sumbu dipotong pada p99.9; ekor terpanjang mencapai 23 us.

## cdf_db — latensi satu permintaan POST

| | p50 | p90 | p99 |
|---|---|---|---|
| tanpa perekam | 155.1 us | 213.8 us | 273.2 us |
| eBPF | 167.8 us | 229.3 us | 292.2 us |
| **selisih** | **+12.7** | **+15.6** | **+19.1** |

45.000 sampel per kondisi (3 ulangan x 5.000). digabung.
Sumbu dipotong pada p99.9; ekor terpanjang mencapai 2.303 us.

> Gambar IV.x Distribusi latensi dengan penangkapan mati dan hidup.
> Baseline bukan aproksimasi rsync: rsync tidak menginstrumentasi apa pun,
> sehingga biaya yang dibebankannya pada jalur eksekusi aplikasi nol
> secara konstruksi. Biaya rsync dibayar saat sinkronisasi, yang diukur
> pada Gambar A2 dan A3.

Selisih dilaporkan sebagai **nilai absolut**, bukan rasio: harness menambah
overhead tetap yang identik di kedua kondisi, yang menyisakan selisihnya
utuh tetapi menekan rasionya.
