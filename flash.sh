#!/bin/sh
# On the atom: write sign.sh's signed files to the Heltec on its USB port, until the panel does it.
#
#   ./flash.sh <signed dir> [port, default /dev/ttyUSB0]
#
# The first time, this locks the board for good when it next starts (README, "Warning"). Files are
# checked against SHA256SUMS; the firmware goes first and the bootloader last (an interrupted write
# leaves a board that still starts its old bootloader); the signed bootloader's header is kept as it
# is (--flash_mode/freq/size keep: esptool would otherwise rewrite it and break its signature).
# neond must not hold the port: stop it first (sudo systemctl stop neond).
[ $# -ge 1 ] || { echo "usage: ./flash.sh signed-dir [port]" >&2; exit 2; }
set -eu
dir=$1; port=${2:-/dev/ttyUSB0}
ET=${ESPTOOL:-esptool.py}
(cd "$dir" && sha256sum -c --quiet SHA256SUMS) || { echo "the signed files do not match their SHA256SUMS" >&2; exit 1; }
unset ESPTOOL_FM ESPTOOL_FF ESPTOOL_FS
common="--chip esp32s3 --port $port --baud 460800 --before default_reset --after no_reset"
keep="--flash_mode keep --flash_freq keep --flash_size keep"
$ET $common write_flash $keep 0x10000 "$dir/firmware.bin" 0x8000 "$dir/partitions.bin" 0xe000 "$dir/boot_app0.bin"
$ET $common --after hard_reset write_flash $keep 0x0 "$dir/bootloader.bin"
echo "written; the board starts now (the first start locks it)"
