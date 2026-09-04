#!/usr/bin/env python3
import csv
import math
import os
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FixedLocator, FixedFormatter, NullFormatter

BLUE, ORANGE = "#2a78d6", "#eb6834"
INK, MUTED, GRID = "#111111", "#666666", "#d8d8d2"

STYLE = {
    "rsync": dict(color=BLUE, marker="o", ls="-", label="rsync"),
    "ebpf": dict(color=ORANGE, marker="s", ls="--", label="eBPF"),
    "off":  dict(color=BLUE, marker="o", ls="-", label="tanpa perekam"),
}

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Nimbus Roman", "Times New Roman", "DejaVu Serif"],
    "font.size": 8,
    "axes.labelsize": 8,
    "axes.titlesize": 8,
    "xtick.labelsize": 7.5,
    "ytick.labelsize": 7.5,
    "legend.fontsize": 7.5,
    "axes.linewidth": 0.7,
    "xtick.major.width": 0.7,
    "ytick.major.width": 0.7,
    "xtick.major.size": 2.5,
    "ytick.major.size": 2.5,
    "lines.linewidth": 1.3,
    "lines.markersize": 4.2,
    "pdf.fonttype": 42,
    "figure.dpi": 300,
})

FIGSIZE = (3.35, 2.15)


def new_axes():
    fig, ax = plt.subplots(figsize=FIGSIZE)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color("#555555")
    ax.tick_params(colors=MUTED, direction="out")
    ax.grid(axis="y", which="major", color=GRID, lw=0.5, zorder=0)
    ax.set_axisbelow(True)
    return fig, ax


def save(fig, outdir, name):
    os.makedirs(outdir, exist_ok=True)
    fig.tight_layout(pad=0.25)
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(outdir, f"{name}.{ext}"), bbox_inches="tight",
                    pad_inches=0.02)
    plt.close(fig)
    print(f"  {name}.pdf / .png")


def bytes_label(v):
    for unit, div in (("MB", 1 << 20), ("KB", 1 << 10)):
        if v >= div:
            q = v / div
            return f"{q:.0f} {unit}" if q >= 10 else f"{q:.1f} {unit}"
    return f"{v:.0f} B"


def load_sweep(path, ycol):
    acc = defaultdict(lambda: defaultdict(list))
    for r in csv.DictReader(open(path)):
        if int(r["verify_mismatch"]) or int(r["capture_lost"]):
            continue
        acc[r["arm"]][float(r["x_value"])].append(float(r[ycol]))
    out = {}
    for arm, xs in acc.items():
        k = sorted(xs)
        out[arm] = (k,
                    [sum(xs[x]) / len(xs[x]) for x in k],
                    [min(xs[x]) for x in k],
                    [max(xs[x]) for x in k])
    return out


def draw_sweep(data, xlabel, ylabel, xticks, xlabels, yticks, ylabels,
               outdir, name, order=("rsync", "ebpf"), annotate=None):
    fig, ax = new_axes()
    for arm in order:
        if arm not in data:
            continue
        x, mean, lo, hi = data[arm]
        st = STYLE[arm]
        ax.errorbar(x, mean, yerr=[[m - l for m, l in zip(mean, lo)],
                                   [h - m for m, h in zip(mean, hi)]],
                    capsize=1.8, elinewidth=0.7, capthick=0.7,
                    markeredgecolor="white", markeredgewidth=0.5,
                    zorder=3, **st)
    lo = min(min(d[2]) for d in data.values())
    hi = max(max(d[3]) for d in data.values())
    pad = 0.11 * (math.log10(hi) - math.log10(lo))
    ax.set_ylim(lo / 10 ** pad, hi * 10 ** pad)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel(xlabel, color=INK)
    ax.set_ylabel(ylabel, color=INK)
    ax.xaxis.set_major_locator(FixedLocator(xticks))
    ax.xaxis.set_major_formatter(FixedFormatter(xlabels))
    ax.xaxis.set_minor_formatter(NullFormatter())
    ax.yaxis.set_major_locator(FixedLocator(yticks))
    ax.yaxis.set_major_formatter(FixedFormatter(ylabels))
    ax.yaxis.set_minor_formatter(NullFormatter())
    if annotate:
        annotate(ax, data)
    ax.legend(frameon=False, loc="best", handlelength=2.0, borderaxespad=0.3,
              labelcolor=INK)
    save(fig, outdir, name)


def crossover(x, y, level):
    for i in range(1, len(x)):
        if (y[i - 1] - level) * (y[i] - level) <= 0 and y[i] != y[i - 1]:
            t = (math.log10(level) - math.log10(y[i - 1])) / \
                (math.log10(y[i]) - math.log10(y[i - 1]))
            return 10 ** (math.log10(x[i - 1]) + t *
                          (math.log10(x[i]) - math.log10(x[i - 1])))
    return None


def load_cdf(path):
    d = defaultdict(list)
    for r in csv.DictReader(open(path)):
        d[r["cond"]].append(float(r["latency_us"]))
    for v in d.values():
        v.sort()
    return d


def draw_cdf(data, xlabel, outdir, name, xticks, xlabels, note_y=0.42):
    fig, ax = new_axes()
    stats = {}
    for cond in ("off", "ebpf"):
        v = data[cond]
        n = len(v)
        ys = [(i + 1) / n for i in range(n)]
        st = dict(STYLE[cond])
        st.pop("marker")
        ax.step(v, ys, where="post", zorder=3, **st)
        stats[cond] = (v[int(0.50 * n)], v[int(0.99 * n)])

    d50 = stats["ebpf"][0] - stats["off"][0]
    d99 = stats["ebpf"][1] - stats["off"][1]
    ax.text(0.97, note_y,
            f"$\\Delta$p50 = +{d50:.1f} $\\mu$s\n$\\Delta$p99 = +{d99:.1f} $\\mu$s",
            transform=ax.transAxes, ha="right", va="top", fontsize=7.2,
            color=INK, linespacing=1.4)

    lo = min(v[0] for v in data.values())
    hi = max(v[int(0.999 * len(v))] for v in data.values())
    ax.set_xlim(lo / 1.08, hi * 1.15)
    ax.set_xscale("log")
    ax.set_xlabel(xlabel, color=INK)
    ax.set_ylabel("CDF", color=INK)
    ax.set_ylim(0, 1.02)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["0", ".25", ".50", ".75", "1"])
    ax.xaxis.set_major_locator(FixedLocator(xticks))
    ax.xaxis.set_major_formatter(FixedFormatter(xlabels))
    ax.xaxis.set_minor_formatter(NullFormatter())
    ax.legend(frameon=False, loc="lower right", handlelength=2.0,
              borderaxespad=0.3, labelcolor=INK,
              bbox_to_anchor=(1.0, 0.02))
    save(fig, outdir, name)
    return stats


def main(resdir="results", outdir="results/not_zero"):
    print("A2:")
    t = load_sweep(f"{resdir}/a2.csv", "sync_ms")
    b = load_sweep(f"{resdir}/a2.csv", "bytes_sent")

    def a2_note(ax, d):
        xr, yr = d["rsync"][0], d["rsync"][1]
        xe, ye = d["ebpf"][0], d["ebpf"][1]
        ax.annotate(f"{yr[-1] / ye[-1]:.0f}$\\times$",
                    xy=(xr[-1], (yr[-1] * ye[-1]) ** 0.5),
                    xytext=(-14, 0), textcoords="offset points",
                    ha="right", va="center", fontsize=7.5, color=INK)
        ax.annotate("", xy=(xr[-1], yr[-1]), xytext=(xr[-1], ye[-1]),
                    arrowprops=dict(arrowstyle="<->", lw=0.7, color=MUTED))

    A2_X = ([10, 50, 200, 1000], ["10", "50", "200", "1.000"])
    draw_sweep(t, "Ukuran Berkas (MB)", "Waktu Sinkronisasi (ms)",
               *A2_X,
               [10, 30, 100, 300, 1000, 3000],
               ["10", "30", "100", "300", "1.000", "3.000"],
               outdir, "a2_time", annotate=a2_note)
    draw_sweep(b, "Ukuran Berkas (MB)", "Data Terkirim ke Replika (KB)",
               *A2_X,
               [4096, 16384, 65536], ["4", "16", "64"],
               outdir, "a2_bytes")

    print("A3:")
    t3 = load_sweep(f"{resdir}/a3.csv", "sync_ms")
    b3 = load_sweep(f"{resdir}/a3.csv", "bytes_sent")

    def mark_crossover(ax, d):
        r = crossover(d["ebpf"][0], d["ebpf"][1], d["rsync"][1][0])
        if not r:
            return
        ax.axvline(r, color=MUTED, lw=0.6, ls=":", zorder=1)
        rounded = round(r, -(len(str(int(r))) - 2)) if r >= 10 else round(r)
        x0, x1 = ax.get_xlim()
        frac = (math.log10(r) - math.log10(x0)) / (math.log10(x1) - math.log10(x0))
        side = -1 if frac > 0.5 else 1
        ax.annotate(f"titik potong $\\approx$ {rounded:,.0f}".replace(",", "."),
                    xy=(r, 0.03), xycoords=("data", "axes fraction"),
                    xytext=(4 * side, 0), textcoords="offset points",
                    fontsize=7, color=MUTED,
                    ha="right" if side < 0 else "left")

    draw_sweep(t3, "Jumlah Penulisan pada Rentang 4 KB yang Sama",
               "Waktu Sinkronisasi (ms)",
               [1, 10, 100, 1000, 10000], ["1", "10", "100", "1.000", "10.000"],
               [10, 30, 100, 300], ["10", "30", "100", "300"],
               outdir, "a3_time", annotate=mark_crossover)
    draw_sweep(b3, "Jumlah Penulisan pada Rentang 4 KB yang Sama",
               "Data Terkirim ke Replika",
               [1, 10, 100, 1000, 10000], ["1", "10", "100", "1.000", "10.000"],
               [4096, 65536, 1048576, 16777216, 67108864],
               ["4 KB", "64 KB", "1 MB", "16 MB", "64 MB"],
               outdir, "a3_bytes", annotate=mark_crossover)

    print("CDF:")
    draw_cdf(load_cdf(f"{resdir}/cdf_fs.csv"),
             "Latensi Satu $\\mathtt{pwrite}$ 4 KB ($\\mu$s)", outdir, "cdf_fs",
             [2, 3, 5, 8], ["2", "3", "5", "8"])
    draw_cdf(load_cdf(f"{resdir}/cdf_db.csv"),
             "Latensi Satu Permintaan POST ($\\mu$s)", outdir, "cdf_db",
             [150, 200, 300, 500, 700], ["150", "200", "300", "500", "700"],
             note_y=0.95)


if __name__ == "__main__":
    main(*(sys.argv[1:3] or ["results", "results/not_zero"]))
