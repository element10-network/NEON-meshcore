#!/bin/sh
# On the atom: write sign.sh's signed files to the Heltec on its USB port, until the panel does it.
#
#   ./flash.sh app <signed dir> [port]    stage A: the firmware only, the board's own bootloader stays
#                                         (nothing is locked; the stock bootloader ignores the signature)
#   ./flash.sh lock <signed dir> [port]   stage B: the Neon bootloader too (locks the board for good at its
#                                         next start)
# port: /dev/ttyUSB0 by default.
#
# The first time, this locks the board for good when it next starts (README, "Warning"). Files are
# checked against SHA256SUMS, and before a lock the bootloader against the project's keys; the firmware goes first and the bootloader last (an interrupted write
# leaves a board that still starts its old bootloader); the signed bootloader's header is kept as it
# is (--flash_mode/freq/size keep: esptool would otherwise rewrite it and break its signature).
# neond must not hold the port: stop it first (sudo systemctl stop neond).
[ $# -ge 2 ] && { [ "$1" = app ] || [ "$1" = lock ]; } || { echo "usage: ./flash.sh app|lock signed-dir [port]" >&2; exit 2; }
set -eu
stage=$1; dir=$2; port=${3:-/dev/ttyUSB0}
ET=${ESPTOOL:-esptool.py}
(cd "$dir" && sha256sum -c --quiet SHA256SUMS) || { echo "the signed files do not match their SHA256SUMS" >&2; exit 1; }
# Before a lock: the bootloader must be this repository's release/bootloader.bin, checked to be signed
# by exactly the keys in neon/key-digests.hex (SHA256SUMS alone says nothing about who signed it,
# and the first start burns its keys for good).
if [ "$stage" = lock ]; then
    top=$(cd "$(dirname "$0")" && pwd)
    cmp -s "$dir/bootloader.bin" "$top/release/bootloader.bin" ||
        { echo "$dir/bootloader.bin is not release/bootloader.bin: not locking" >&2; exit 1; }
    (cd "$top" && python3 release/check-bootloader.py "${ESPSECURE:-espsecure.py}") ||
        { echo "the bootloader's signature keys are not the project's: not locking" >&2; exit 1; }
fi
unset ESPTOOL_FM ESPTOOL_FF ESPTOOL_FS
common="--chip esp32s3 --port $port --baud 460800 --before default_reset --after no_reset"
keep="--flash_mode keep --flash_freq keep --flash_size keep"
if [ "$stage" = app ]; then
    $ET $common --after hard_reset write_flash $keep 0x10000 "$dir/firmware.bin" 0x8000 "$dir/partitions.bin" 0xe000 "$dir/boot_app0.bin"
    echo "stage A written: the Neon firmware runs on the board's own bootloader, nothing locked"
    exit 0
fi
# Stage B: the firmware again (the same files), then the bootloader alone, then the board starts.
$ET $common write_flash $keep 0x10000 "$dir/firmware.bin" 0x8000 "$dir/partitions.bin" 0xe000 "$dir/boot_app0.bin"
$ET $common --after hard_reset write_flash $keep 0x0 "$dir/bootloader.bin"
echo "stage B written: the board starts now and locks itself on this first start"
