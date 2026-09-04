#!/usr/bin/env bash
# Pasang dependensi demo di node4 (mesin ini) dan node3 (mesin cadangan).
# Aman dijalankan berulang: yang sudah ada dilewati.
set -uo pipefail

PEER=${1:-panjisri@10.10.1.4}
WORK=${2:-/var/tmp/demo}
SINI=$(cd "$(dirname "$0")" && pwd)
SSH="ssh -o StrictHostKeyChecking=no $PEER"

siapkan='
  set -u
  for p in PAKETLIST; do
    dpkg -s "$p" >/dev/null 2>&1 || KURANG="${KURANG:-} $p"
  done
  [ -n "${KURANG:-}" ] && { sudo apt-get update -qq; sudo apt-get install -y -qq $KURANG || true; }
  if ! sudo -n docker version >/dev/null 2>&1; then
    sudo apt-get install -y -qq docker.io || true
  fi
  if ! sudo -n docker compose version >/dev/null 2>&1; then
    sudo apt-get install -y -qq docker-compose-v2 || true
  fi
  sudo -n docker pull -q postgres:16-alpine >/dev/null 2>&1 || true
  sudo mkdir -p WORKDIR && sudo chmod 1777 WORKDIR
'

utama=${siapkan//WORKDIR/$WORK}
echo "== node4 =="
bash -c "${utama//PAKETLIST/clang llvm libelf-dev zlib1g-dev make gcc pkg-config libcap-dev rsync curl}"

echo "== node3 =="
$SSH "${utama//PAKETLIST/rsync curl}"

echo "== kunci SSH node4 -> node3 (tanpa agent) =="
if sudo -n env HOME="$HOME" ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
     "$PEER" true >/dev/null 2>&1; then
  echo "  sudah bisa"
else
  [ -f "$HOME/.ssh/id_demo" ] || ssh-keygen -t ed25519 -N '' -f "$HOME/.ssh/id_demo" -q
  $SSH 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys' \
    < "$HOME/.ssh/id_demo.pub"
  sudo -n env HOME="$HOME" ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
       "$PEER" true >/dev/null 2>&1 \
    && echo "  id_demo dibuat dan dipasang di node3" \
    || echo "  MASIH GAGAL, jalankan orkestrator dengan SSH_AUTH_SOCK=\$SSH_AUTH_SOCK"
fi

# Sengaja tanpa "make clean": kalau pembangunan ulang gagal, biner yang tadinya
# sudah jadi jangan sampai ikut hilang.
echo "== bangun penangkap eBPF di node4 =="
if [ -x "$SINI/ebpf/statediff_vfs" ] && [ -x "$SINI/ebpf/statediff_apply_vfs" ]; then
  echo "  sudah ada, dilewati (hapus binernya kalau mau bangun ulang)"
else
  make -C "$SINI/ebpf" || { echo "GAGAL membangun eBPF, lihat pesan di atas"; exit 1; }
fi

# statediff_vfs tidak dikirim: skeleton BPF-nya terikat BTF kernel pembangunnya.
echo "== kirim biner ke node3 =="
rsync -a "$SINI/ebpf/statediff_apply_vfs" "$PEER:$WORK/"
rsync -a "$SINI/services/todo-go/todo-go" "$PEER:$WORK/"

periksa='
  o(){ printf "  %-26s %s\n" "$1" "$2"; }
  d(){ sudo -n docker "$@" >/dev/null 2>&1 || docker "$@" >/dev/null 2>&1; }
  d version && o docker ok || o docker KURANG
  d compose version && o "docker compose" ok || o "docker compose" KURANG
  d image inspect postgres:16-alpine && o "citra postgres" ok || o "citra postgres" KURANG
  command -v rsync >/dev/null && o rsync ok || o rsync KURANG
  [ -d WORKDIR ] && o "direktori kerja" ok || o "direktori kerja" KURANG
'

echo
echo "== periksa node4 =="
bash -c "${periksa//WORKDIR/$WORK}"
test -x "$SINI/ebpf/statediff_vfs" \
  && printf "  %-26s %s\n" "penangkap eBPF" "ok" \
  || printf "  %-26s %s\n" "penangkap eBPF" "KURANG"

echo "== periksa node3 =="
$SSH "${periksa//WORKDIR/$WORK}
  [ -x $WORK/statediff_apply_vfs ] && o penerap ok || o penerap KURANG
  [ -x $WORK/todo-go ] && o todo-go ok || o todo-go KURANG"

echo
echo "kalau semua ok: sudo python3 orkestrator.py"
