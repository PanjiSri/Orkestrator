LEBAR = 66


def judul(teks):
    print()
    print("=" * LEBAR)
    print("  " + teks)
    print("=" * LEBAR)


def bagian(teks):
    print()
    print("-- " + teks + " " + "-" * max(0, LEBAR - len(teks) - 4))


def tahap(n, total, teks):
    print(f"  [{n}/{total}] {teks}")


def baris(teks):
    print(f"        {teks}")


def info(kunci, nilai):
    print(f"  {kunci:<34} {nilai}")


def ukur(teks):
    print()
    print(f"  >> {teks}")


def kotak(judul_kotak, isi, catatan=None):
    print()
    print("+" + "-" * (LEBAR - 2) + "+")
    print("| " + judul_kotak.ljust(LEBAR - 4) + " |")
    print("+" + "-" * (LEBAR - 2) + "+")
    for b in isi:
        print("| " + b.ljust(LEBAR - 4) + " |")
    print("+" + "-" * (LEBAR - 2) + "+")
    if catatan:
        for c in _bungkus(catatan, LEBAR - 4):
            print("  " + c)


def _bungkus(teks, lebar):
    kata, baris_ini, hasil = teks.split(), "", []
    for k in kata:
        if len(baris_ini) + len(k) + 1 > lebar:
            hasil.append(baris_ini)
            baris_ini = k
        else:
            baris_ini = (baris_ini + " " + k).strip()
    if baris_ini:
        hasil.append(baris_ini)
    return hasil


def ms(nilai):
    utuh, pecahan = f"{nilai:,.1f}".split(".")
    return f"{utuh.replace(',', '.')},{pecahan} ms"


def byte(n):
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f}".replace(".", ",") + " MB"
    if n >= 1 << 10:
        return f"{n / (1 << 10):.1f}".replace(".", ",") + " KB"
    return f"{n} B"


def galat(teks):
    print()
    print("  !! " + teks)
