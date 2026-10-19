#!/bin/sh
# install netlogger into ~/.local/bin (or $PREFIX/bin)
set -eu

SRC_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX=${PREFIX:-$HOME/.local}
BIN="$PREFIX/bin"

command -v python3 >/dev/null 2>&1 || {
    echo "error: python3 is required" >&2
    exit 1
}
python3 - <<'PY' || { echo "error: python 3.8+ is required" >&2; exit 1; }
import sys
if sys.version_info < (3, 8):
    raise SystemExit(1)
PY

mkdir -p "$BIN"
install -m 755 "$SRC_DIR/netlogger.py" "$BIN/netlogger"

echo "installed: $BIN/netlogger"
echo
echo "full URLs for every app (default, needs sudo to trust the CA):"
echo "    sudo $BIN/netlogger"
echo
echo "raw packet-capture view instead (DNS, QUIC, every interface):"
echo "    sudo $BIN/netlogger --capture"
echo
echo "no root needed for these:"
echo "    $BIN/netlogger --demo"
echo "    $BIN/netlogger --selftest"
echo
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "note: $BIN is not in your PATH" ;;
esac
