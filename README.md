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

1. **The atom flashes it** (panel: Reach → MeshCore → Secure this radio): the signed bootloader,
   partition table and firmware, over the USB cable the Heltec is already on.
2. **First start:** the bootloader burns the digest of the Neon firmware key and turns secure boot
   on (it checks the firmware's signature first).
3. **Provisioning** (`CMD_NEON`, `SUB_PROVISION`, sent by the atom): the firmware turns JTAG and the
   full download mode off, makes an RSA-3072 key, encrypts it for the chip's digital signature
   peripheral with a new HMAC key and burns that key into a read-protected eFuse; the private key
   leaves RAM. It checks one signature before answering. A chip without secure boot refuses.
4. **Every reception:** `PUSH_RX` (sequence, boot count, microsecond counter, RSSI, SNR, the
   packet's SHA-256 fingerprint, the chip's MAC) and its signature in three `PUSH_RX_SIG` frames.
   The atom passes them on unchanged; electrodes check them against the radio's public key, which
   the atom registers signed with its own key (one rewarded radio per atom).

What it cannot prove: the chip has no factory attestation, so the network cannot tell a secured
Heltec from software pretending to be one at registration. A fake still needs a genuine hotspot, a
confirmed position, other operators' atoms hearing the same packets, and stays under the caps.

## Build

```
./build.sh            # MeshCore at MESHCORE_COMMIT + neon/ -> out/ (unsigned)
```

Needs PlatformIO (`pip install platformio`). `neon/companion_radio.patch` is the only change to
MeshCore's own files (two hooks, behind `NEON_RADIO`); `neon/NeonRadio.cpp` is the rest. MeshCore's
private key import and export are compiled out.

## The firmware key (hq)

Made once, on hq, and backed up offline (losing it ends updates for every secured radio):

```
pip install esptool==4.8.1 && espsecure.py generate_signing_key --version 2 --scheme rsa3072 /root/neon-firmware-key.pem && chmod 600 /root/neon-firmware-key.pem
```

Signing a build: `./sign.sh /root/neon-firmware-key.pem out/ signed/` (signs, verifies, writes the
flash layout and SHA256SUMS).

## Licence

MIT, like MeshCore (https://github.com/meshcore-dev/MeshCore), on which this is built.
