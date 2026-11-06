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

Needs PlatformIO (`pip install platformio`). `neon/companion_radio.patch` is the only change to
MeshCore's own files (two hooks, behind `NEON_RADIO`); `neon/NeonRadio.cpp` is the rest. MeshCore's
private key import and export are compiled out.

## The firmware keys (hq)

Two keys, made once on hq: the project's key (stays on hq) and a backup key (moved offline at once,
brought back only to sign a bootloader or to replace a lost or stolen project key). Every secured
radio trusts exactly these two, for good.

```
sudo /root/esptool/bin/espsecure.py generate_signing_key --version 2 --scheme rsa3072 /root/neon-firmware-backup-key.pem && sudo chmod 600 /root/neon-firmware-backup-key.pem
```

Their digests (public) go into `neon/key-digests.hex`, one per line; the build refuses without it:

```
for k in /root/neon-firmware-key.pem /root/neon-firmware-backup-key.pem; do sudo /root/esptool/bin/espsecure.py digest_sbv2_public_key --keyfile $k -o /tmp/d.bin >/dev/null && od -An -tx1 -v /tmp/d.bin | tr -d ' \n' && echo; done; rm -f /tmp/d.bin
```

Signing a build: `./sign.sh /root/neon-firmware-key.pem /root/neon-firmware-backup-key.pem out/ signed/`
(signs, verifies, writes the flash layout and SHA256SUMS).

## Licence

MIT, like MeshCore (https://github.com/meshcore-dev/MeshCore), on which this is built.
