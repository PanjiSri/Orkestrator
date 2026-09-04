#!/usr/bin/env python3
import csv
import os
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FixedLocator, FixedFormatter

SURFACE = "#ffffff"
INK = "#111111"
INK_MUTED = "#6b6b6b"
GRID = "#dcdcdc"
RULE = "#9a9a9a"

STYLE = {
    "rsync": dict(color="#2a78d6", marker="o", ls="-", mfc="#2a78d6", label="rsync"),
    "ebpf": dict(color="#eb6834", marker="s", ls="--", mfc=SURFACE, label="eBPF"),
}
ORDER = ["rsync", "ebpf"]


def rc():
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["DejaVu Serif"],
        "font.size": 8,
        "axes.labelsize": 8,
        "axes.linewidth": 0.6,
        "xtick.labelsize": 7.5,
        "ytick.labelsize": 7.5,
        "xtick.major.width": 0.6,
        "ytick.major.width": 0.6,
        "xtick.major.size": 2.5,
        "ytick.major.size": 2.5,
        "legend.fontsize": 7.5,
        "figure.dpi": 400,
        "savefig.dpi": 400,
    })


def load(path):
    t = defaultdict(lambda: defaultdict(list))
    b = defaultdict(lambda: defaultdict(list))
    dropped = 0
    with open(path) as f:
        for row in csv.DictReader(f):
            if int(row["verify_mismatch"]) or int(row["capture_lost"]):
                dropped += 1
                continue
            arm, x = row["arm"], float(row["x_value"])
            t[arm][x].append(float(row["sync_ms"]))
            b[arm][x].append(float(row["bytes_sent"]))
    if dropped:
        print(f"dropped {dropped} invalid row(s)", file=sys.stderr)
    return t, b


def series(d, arm):
    xs = sorted(d[arm])
    mean = [sum(d[arm][x]) / len(d[arm][x]) for x in xs]
    lo = [m - min(d[arm][x]) for x, m in zip(xs, mean)]
    hi = [max(d[arm][x]) - m for x, m in zip(xs, mean)]
    return xs, mean, lo, hi


def crossing(d, log=False):
    import math
    xs = sorted(set(d["rsync"]) & set(d["ebpf"]))
    if len(xs) < 2:
        return None

    def val(arm, x):
        v = sum(d[arm][x]) / len(d[arm][x])
        return math.log10(v) if log else v

    for a, bx in zip(xs, xs[1:]):
        d0 = val("ebpf", a) - val("rsync", a)
        d1 = val("ebpf", bx) - val("rsync", bx)
        if d0 == 0:
            return a
        if d0 * d1 < 0:
            f = d0 / (d0 - d1)
            if log:
                la, lb = math.log10(a), math.log10(bx)
                return 10 ** (la + (lb - la) * f)
            return a + (bx - a) * f
    return None


A3_X = ("Jumlah penulisan ulang (R)", [0, 2000, 4000, 6000, 8000, 10000],
        ["0", "2.000", "4.000", "6.000", "8.000", "10.000"], (0, 10400))

A3_X_LOG = ("Jumlah penulisan ulang (R)", [1, 10, 100, 1000, 10000],
            ["1", "10", "100", "1.000", "10.000"], (0.65, 16000))


def frame(ax, xaxis=A3_X, log=False):
    xlabel, xticks, xlabels, xlim = xaxis
    ax.set_facecolor(SURFACE)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(RULE)
    ax.tick_params(colors=INK_MUTED)
    ax.grid(axis="y", which="major", color=GRID, linewidth=0.4, zorder=0)
    ax.set_axisbelow(True)
    if log:
        ax.set_xscale("log")
        ax.set_yscale("log")
    ax.set_xlabel(xlabel, color=INK)
    ax.xaxis.set_major_locator(FixedLocator(xticks))
    ax.xaxis.set_major_formatter(FixedFormatter(xlabels))
    ax.set_xlim(*xlim)
    ax.minorticks_off()


def draw(d, ylabel, yticks, ylabels, ylim, out, legend_loc="upper left",
         label_y=0.5, xaxis=A3_X, annotate=None, log=False):
    rc()
    fig, ax = plt.subplots(figsize=(3.35, 2.3))
    fig.patch.set_facecolor(SURFACE)
    frame(ax, xaxis, log)

    xc = crossing(d, log)
    if xc:
        ax.axvline(xc, color=RULE, lw=0.6, ls=":", zorder=1)
        ax.annotate("titik potong", xy=(xc, label_y), xycoords=("data", "axes fraction"),
                    xytext=(3, 0), textcoords="offset points", rotation=90,
                    color=INK_MUTED, fontsize=6.5, ha="left", va="center")

    for arm in ORDER:
        if arm not in d:
            continue
        xs, mean, lo, hi = series(d, arm)
        st = STYLE[arm]
        ax.errorbar(xs, mean, yerr=[lo, hi], color=st["color"], lw=1.4,
                    ls=st["ls"], marker=st["marker"], ms=4.5,
                    markerfacecolor=st["mfc"], markeredgecolor=st["color"],
                    markeredgewidth=1.1, elinewidth=0.8, capsize=2,
                    label=st["label"], zorder=3, clip_on=False)

    for arm, text in ({} if log else (annotate or {})).items():
        if arm not in d:
            continue
        xs, mean, _, _ = series(d, arm)
        ax.annotate(text, xy=(xs[-1], mean[-1]), xytext=(-2, 7),
                    textcoords="offset points", ha="right",
                    color=STYLE[arm]["color"], fontsize=6.5, zorder=4)

    ax.set_ylabel(ylabel, color=INK)
    ax.yaxis.set_major_locator(FixedLocator(yticks))
    ax.yaxis.set_major_formatter(FixedFormatter(ylabels))
    ax.set_ylim(*ylim)

    handles = [Line2D([], [], color=STYLE[a]["color"], ls=STYLE[a]["ls"], lw=1.4,
                      marker=STYLE[a]["marker"], ms=4.5,
                      markerfacecolor=STYLE[a]["mfc"],
                      markeredgecolor=STYLE[a]["color"], markeredgewidth=1.1,
                      label=STYLE[a]["label"])
               for a in ORDER if a in d]
    leg = ax.legend(handles=handles, loc=legend_loc, frameon=False,
                    handlelength=2.2, borderaxespad=0.2, labelspacing=0.25)
    for txt in leg.get_texts():
        txt.set_color(INK)

    fig.tight_layout(pad=0.3)
    for ext in ("pdf", "png"):
        fig.savefig(f"{out}.{ext}", facecolor=SURFACE, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {out}.pdf / {out}.png")


def main(csv_path, outdir="results", mode="linear"):
    t, b = load(csv_path)
    os.makedirs(outdir, exist_ok=True)

    if mode == "log":
        draw(t, "Waktu sinkronisasi (ms)",
             [10, 30, 100, 300], ["10", "30", "100", "300"], (8, 400),
             f"{outdir}/a3_time", legend_loc="upper left", label_y=0.25,
             xaxis=A3_X_LOG, log=True)
        draw(b, "Data terkirim ke replika",
             [1e4, 1e5, 1e6, 1e7], ["10 KB", "100 KB", "1 MB", "10 MB"],
             (3e3, 8e7), f"{outdir}/a3_bytes", legend_loc="lower right",
             xaxis=A3_X_LOG, log=True)
        return

    draw(t, "Waktu sinkronisasi (ms)",
         [0, 50, 100, 150, 200, 250, 300],
         ["0", "50", "100", "150", "200", "250", "300"], (0, 300),
         f"{outdir}/a3_time", legend_loc="upper left", label_y=0.62,
         annotate={"rsync": "75 ms (tetap)"})
    draw(b, "Data terkirim ke replika",
         [0, 1e7, 2e7, 3e7, 4e7],
         ["0", "10 MB", "20 MB", "30 MB", "40 MB"], (0, 4.4e7),
         f"{outdir}/a3_bytes", legend_loc="upper left",
         annotate={"rsync": "19,6 KB (tetap)"})


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--log"]
    if not args:
        sys.exit("usage: plot_a3.py results/a3.csv [outdir] [--log]")
    main(args[0], args[1] if len(args) > 1 else "results",
         "log" if "--log" in sys.argv else "linear")
