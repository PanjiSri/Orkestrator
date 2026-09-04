#!/usr/bin/env python3
import os
import sys

from plot_a3 import draw, load

A2_X = ("Ukuran berkas (MB)", [0, 200, 400, 600, 800, 1000],
        ["0", "200", "400", "600", "800", "1.000"], (0, 1050))

A2_X_LOG = ("Ukuran berkas (MB)", [10, 50, 200, 1000],
            ["10", "50", "200", "1.000"], (7, 1500))


def main(csv_path, outdir="results", mode="linear"):
    t, b = load(csv_path)
    os.makedirs(outdir, exist_ok=True)

    if mode == "log":
        draw(t, "Waktu sinkronisasi (ms)",
             [10, 30, 100, 300, 1000, 3000],
             ["10", "30", "100", "300", "1.000", "3.000"], (7, 4000),
             f"{outdir}/a2_time", legend_loc="upper left",
             xaxis=A2_X_LOG, log=True)
        draw(b, "Data terkirim ke replika",
             [4e3, 1e4, 4e4, 1e5], ["4 KB", "10 KB", "40 KB", "100 KB"],
             (2.5e3, 3e5), f"{outdir}/a2_bytes", legend_loc="upper left",
             xaxis=A2_X_LOG, log=True)
        return

    draw(t, "Waktu sinkronisasi (ms)",
         [0, 500, 1000, 1500, 2000],
         ["0", "500", "1.000", "1.500", "2.000"], (0, 2150),
         f"{outdir}/a2_time", legend_loc="upper left", xaxis=A2_X,
         annotate={"ebpf": "10 ms (tetap)"})

    draw(b, "Data terkirim ke replika",
         [0, 50e3, 100e3, 150e3],
         ["0", "50 KB", "100 KB", "150 KB"], (0, 180e3),
         f"{outdir}/a2_bytes", legend_loc="upper left", xaxis=A2_X,
         annotate={"ebpf": "4,2 KB (tetap)"})


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--log"]
    if not args:
        sys.exit("usage: plot_a2.py results/a2.csv [outdir] [--log]")
    main(args[0], args[1] if len(args) > 1 else "results",
         "log" if "--log" in sys.argv else "linear")
