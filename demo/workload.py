import math
import os
import random
import time

BLOCK = 4096
DATA_FILE = "data.bin"

POPULATE_WRITE_BYTES = 1 << 20

POPULATE_DRAIN_BYTES = 16 << 20


def data_path(src):
    return os.path.join(src, DATA_FILE)


def populate_file(src, size_bytes, recorder, seed):
    os.makedirs(src, exist_ok=True)
    rng = random.Random(seed)
    path = data_path(src)
    written = 0
    since_drain = 0
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        while written < size_bytes:
            n = min(POPULATE_WRITE_BYTES, size_bytes - written)
            os.write(fd, rng.randbytes(n))
            written += n
            since_drain += n
            if since_drain >= POPULATE_DRAIN_BYTES:
                os.fsync(fd)
                recorder.drain()
                since_drain = 0
        os.fsync(fd)
        recorder.drain()
    finally:
        os.close(fd)
    return path


def change_offset(file_size):
    return max(0, (file_size // 2) // BLOCK * BLOCK)


def write_change(path, offset, size, times, seed):
    before = os.stat(path).st_mtime
    boundary = math.floor(before) + 1 + 0.05
    now = time.time()
    if now < boundary:
        time.sleep(boundary - now)

    rng = random.Random(seed)
    fd = os.open(path, os.O_WRONLY)
    try:
        for _ in range(times):
            os.pwrite(fd, rng.randbytes(size), offset)
        os.fsync(fd)
    finally:
        os.close(fd)

    after = os.stat(path).st_mtime
    if math.floor(after) == math.floor(before):
        raise RuntimeError(
            "mtime did not advance a whole second across the change; rsync "
            "would skip the file and the measurement would be meaningless")
