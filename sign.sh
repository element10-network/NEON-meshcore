#!/bin/sh
# On hq: sign the bootloader and the firmware with the project's firmware keys, and write the
# files atoms flash (with their SHA-256 list). The keys never leave hq (the backup key is brought
# from offline only for this).
#
#   sudo ./sign.sh <key.pem> <backup-key.pem> <unsigned dir (build.sh's out/)> <signed dir>
#
# The bootloader is signed with both keys (a secured radio trusts the backup too, to replace a lost
# or stolen key), the firmware with the project key. The keys must be the ones whose digests the
# firmware was built with (out/key-digests.hex, in that order): the firmware revokes every other
# secure boot slot, so a mismatch would leave a board that never starts again.
[ $# -eq 4 ] || { echo "usage: sudo ./sign.sh key.pem backup-key.pem unsigned-dir signed-dir" >&2; exit 2; }
set -eu
key=$1; backup=$2; in=$3; out=$4
ES=${ESPSECURE:-/root/esptool/bin/espsecure.py}
"$ES" version 2>/dev/null | grep -q "v4.8.1" || "$ES" --help 2>/dev/null | grep -q "v4.8.1" || { echo "$ES is not espsecure.py 4.8.1 (set ESPSECURE)" >&2; exit 2; }
for f in "$key" "$backup" "$in/bootloader.bin" "$in/firmware.bin" "$in/partitions.bin" "$in/boot_app0.bin" "$in/key-digests.hex" "$in/UNSIGNED.SHA256SUMS"; do
    [ -f "$f" ] || { echo "missing: $f" >&2; exit 2; }
done
# The unsigned files are build.sh's, unchanged.
(cd "$in" && sha256sum -c --quiet UNSIGNED.SHA256SUMS) || { echo "the unsigned files are not build.sh's output" >&2; exit 1; }
# No signature in them already (a second sector would be ignored by the chip, which reads the first).
for f in bootloader.bin firmware.bin; do
    if "$ES" signature_info_v2 "$in/$f" >/dev/null 2>&1; then echo "$in/$f is already signed" >&2; exit 1; fi
done
# The keys are the two the firmware trusts, in that order, and not the same key.
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
"$ES" digest_sbv2_public_key --keyfile "$key" --output "$tmp/k1" >/dev/null
"$ES" digest_sbv2_public_key --keyfile "$backup" --output "$tmp/k2" >/dev/null
k1=$(od -An -tx1 -v "$tmp/k1" | tr -d ' \n'); k2=$(od -An -tx1 -v "$tmp/k2" | tr -d ' \n')
[ "$k1" != "$k2" ] || { echo "the key and the backup key are the same key" >&2; exit 1; }
[ "$(printf '%s\n%s\n' "$k1" "$k2")" = "$(cat "$in/key-digests.hex")" ] || {
    echo "these keys are not the ones the firmware was built for (out/key-digests.hex): stop" >&2; exit 1; }
mkdir -p "$out"
"$ES" sign_data --version 2 --keyfile "$key" "$backup" --output "$out/bootloader.bin" "$in/bootloader.bin" >/dev/null
"$ES" sign_data --version 2 --keyfile "$key" --output "$out/firmware.bin" "$in/firmware.bin" >/dev/null
cp "$in/partitions.bin" "$in/boot_app0.bin" "$in/key-digests.hex" "$out/"
# The signed bootloader ends before the partition table at 0x8000.
[ "$(wc -c < "$out/bootloader.bin")" -le 32768 ] || { echo "signed bootloader too large" >&2; exit 1; }
check() { r=$("$ES" verify_signature --version 2 --keyfile "$1" "$2" 2>&1) || true; printf '%s' "$r" | grep -q "verification successful" || { echo "signature check failed: $2" >&2; exit 1; }; }
check "$key" "$out/bootloader.bin"
check "$backup" "$out/bootloader.bin"
check "$key" "$out/firmware.bin"
# Flash layout (flash.sh): offset file, the bootloader written last.
printf '0x10000 firmware.bin\n0x8000 partitions.bin\n0xe000 boot_app0.bin\n0x0 bootloader.bin\n' > "$out/layout.txt"
(cd "$out" && sha256sum bootloader.bin partitions.bin boot_app0.bin firmware.bin key-digests.hex layout.txt > SHA256SUMS)
echo "signed: $out"
