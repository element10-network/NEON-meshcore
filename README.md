# NEON-meshcore

The secured MeshCore radio of the [Neon Network](https://element10.network): MeshCore's companion
radio firmware (USB) for the **Heltec V3**, with one addition. Every packet the radio hears is
reported to the atom with a **signature made by the chip itself**, so MeshCore photons count only
receptions a real radio made (NEON `docs/MESHCORE.md`, "The secured radio").

## Warning: securing a Heltec is permanent

Flashing this firmware with the Neon bootloader **locks the board for good**:

- the chip's secure boot is turned on with the Neon firmware key: from then on it starts **only
  Neon-signed firmware**. Stock MeshCore, Meshtastic or anything else will never run on it again;
- JTAG is turned off and the USB download mode can only write flash;
- an eFuse key is burnt for the signing key.

eFuses cannot be unburnt. Use a Heltec you will keep for the atom. The board stays a normal MeshCore
companion radio for the atom (channels, direct messages, adverts), with Neon's updates.

## How it fits together

1. **The atom flashes it** (panel, to come): the signed bootloader, partition table and firmware, over
   the USB cable the Heltec is already on.
2. **First start:** the bootloader checks the firmware's signature, burns the digests of the Neon firmware
   key and its offline backup into the chip, revokes the third slot, turns secure boot on, turns JTAG off
   and limits USB download to flash writes. From here the board is locked.
3. **Provisioning** (`CMD_NEON`, `SUB_PROVISION`, once in the chip's life): the firmware checks that
   secure boot trusts only Neon's two keys (revoking any other slot), burns the remaining protections
   (soft JTAG, direct boot), makes an RSA-3072 key with the hardware random source on, saves its
   encrypted parameters to flash and reads them back, then burns a new HMAC key read-protected for the
   digital signature peripheral and locks read protection for good. A signature is checked before it
   answers. A chip that already has a key refuses (flash erased by the atom: the key cannot be remade).
4. **Every reception:** `PUSH_RX` (sequence, boot count, microsecond counter, RSSI, SNR, MeshCore's own
   packet hash at full length, the chip's MAC, the radio's frequency, bandwidth, spreading factor and
   coding rate, and the electrodes' latest freshness value set with `SUB_NONCE`) and its signature in
   three `PUSH_RX_SIG` frames. The atom passes them on unchanged; electrodes check them against the
   radio's public key, which the atom registers signed with its own key (one rewarded radio per atom),
   and refuse stale freshness values.

What it cannot prove: the chip has no factory attestation, so the network cannot tell a secured
Heltec from software pretending to be one at registration. A fake still needs a genuine hotspot, a
confirmed position, other operators' atoms hearing the same packets, and stays under the caps.
Older Neon-signed firmware can be written back over a newer one (no anti-rollback yet **(verify**
whether the Arduino build can carry a secure version**)**).

## Build

```
./build.sh            # MeshCore at MESHCORE_COMMIT + neon/ -> out/ (unsigned)
```

Needs PlatformIO (in a venv: `python3 -m venv ~/pio && ~/pio/bin/pip install platformio`). `neon/companion_radio.patch` is the only change to
MeshCore's own files (two hooks, behind `NEON_RADIO`); `neon/NeonRadio.cpp` is the rest. MeshCore's
private key import and export are compiled out.

## The firmware keys (hq)

Two keys, made once on hq: the project's key (stays on hq) and a backup key (moved offline at once,
brought back only to sign a bootloader). Every secured radio trusts exactly these two, for good.
esptool 4.8.1 in a venv:

```
sudo apt-get install -y python3-venv && sudo python3 -m venv /root/esptool && sudo /root/esptool/bin/pip install esptool==4.8.1
```

The keys (`generate_signing_key` refuses to overwrite one that exists):

```
sudo /root/esptool/bin/espsecure.py generate_signing_key --version 2 --scheme rsa3072 /root/neon-firmware-key.pem && sudo /root/esptool/bin/espsecure.py generate_signing_key --version 2 --scheme rsa3072 /root/neon-firmware-backup-key.pem && sudo chmod 600 /root/neon-firmware-key.pem /root/neon-firmware-backup-key.pem
```

Their digests (public), the project key first: these two lines go into `neon/key-digests.hex` on the
machine that runs build.sh. build.sh refuses without exactly two, and sign.sh refuses keys that are
not these two, in this order:

```
sudo sh -c 'set -e; for k in /root/neon-firmware-key.pem /root/neon-firmware-backup-key.pem; do /root/esptool/bin/espsecure.py digest_sbv2_public_key --keyfile $k -o /root/d.bin >/dev/null; od -An -tx1 -v /root/d.bin | tr -d " \n"; echo; done; rm -f /root/d.bin'
```

Signing a build (on hq, with build.sh's `out/` copied there):
`sudo ./sign.sh /root/neon-firmware-key.pem /root/neon-firmware-backup-key.pem out/ signed/`. It checks
the unsigned files against build.sh's list, refuses files signed before, checks both keys against
`key-digests.hex`, signs, verifies and writes the flash layout and SHA256SUMS. Then move the backup key
offline again.

## Releases (GitHub)

`Radio` workflow (`.github/workflows/radio.yml`, run by hand): builds, signs the firmware with the project key
(repository secret `NEON_FIRMWARE_KEY`), adds the bootloader signed once on hq (`release/bootloader.bin`, checked
by `release/check-bootloader.py` against `release/bootloader-unsigned.bin` and `key-digests.hex`) and publishes
a release with `SHA256SUMS` and `radio.txt`. The atom's panel flashes and locks the radio from it.

The bootloader is signed again only when `bootloader/` changes: build, commit the new
`release/bootloader-unsigned.bin`, sign it on hq with both keys (`sign.sh`), commit `release/bootloader.bin`.

## Flashing (until the panel does it)

On the atom, neond stopped for the whole procedure (it holds the port, and gives up on a radio that
did not answer until it is unplugged), esptool 4.8.1 in `/root/esptool` as on hq:

0. **Check and back up** (only possible before stage B): `sha256sum -c SHA256SUMS` in the signed
   folder; `espsecure.py signature_info_v2 bootloader.bin` shows two keys matching
   `key-digests.hex`; `espefuse.py --chip esp32s3 -p /dev/ttyUSB0 summary` shows `SECURE_BOOT_EN` 0,
   no key purposes, `WR_DIS_RD_DIS` 0; `esptool.py --chip esp32s3 -p /dev/ttyUSB0 read_flash 0 0x800000
   heltec-stock.bin` keeps the whole board.
1. **Stage A, nothing locked:** `./flash.sh app signed/`. The Neon firmware on the board's own
   bootloader: start neond, check the radio works as before (same MeshCore identity), stop neond,
   `neon-radio.py identity` answers (status 0x00).
2. **Stage B, locks the board for good:** `./flash.sh lock signed/`. Its first start burns the keys'
   digests and turns secure boot on. Wait 30 s, then `neon-radio.py identity` must show status
   **0x17**. Anything else: stop and ask.
3. **Provision:** `neon-radio.py provision` (minutes; nothing else on the port), then at once
   `neon-radio.py backup DIR` and copy DIR to hq: the key's parameters are useless off this chip and
   are the only way back if the radio's flash is ever wiped (`neon-radio.py restore DIR`).
4. Start neond again.

Never flash a merged MeshCore image or use a web flasher on a secured board: it overwrites the
parameters (restore them from the backup).

## Licence

MIT, like MeshCore (https://github.com/meshcore-dev/MeshCore), on which this is built.
