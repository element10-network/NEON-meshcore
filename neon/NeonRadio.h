// Neon's additions to MeshCore's companion radio firmware (USB): every packet the radio hears is
// reported with a signature made by the chip itself, so an atom cannot invent receptions.
//
// The signing key is RSA-3072 in the ESP32-S3's digital signature (DS) peripheral: its parameters
// are encrypted with an HMAC key burnt into a read-protected eFuse that only the DS peripheral can
// use. Secure boot (the Neon bootloader) lets only Neon-signed firmware run, so only this code can
// ask the chip to sign. Provisioning burns eFuses: it is permanent (README, "Warning").
#pragma once

#include <stdint.h>

class BaseSerialInterface;

namespace neon {

// Companion protocol additions (MeshCore's own codes stay below 0x70 and from 0x80 to 0x9F).
constexpr uint8_t CMD_NEON = 0xE0;     // [0xE0][sub]: SUB_IDENTITY, SUB_PROVISION
constexpr uint8_t SUB_IDENTITY = 1;    // answer: RESP_IDENTITY
constexpr uint8_t SUB_PROVISION = 2;   // lock the chip and make the key (once); answer: RESP_IDENTITY
constexpr uint8_t SUB_PUBKEY = 3;      // [sub][part 0..2]: answer RESP_PUBKEY with 128 bytes of the modulus
constexpr uint8_t SUB_NONCE = 4;       // [sub][16 bytes]: the electrodes' current freshness value, signed into
                                       // every reception from now on (receptions cannot be kept for later);
                                       // nothing is signed before the first one
// The key's parameters in flash (encrypted for this chip's eFuse key: useless anywhere else), so the
// atom can keep a copy and put it back after the radio's flash was wiped:
constexpr uint8_t SUB_BLOB_GET = 5;    // [sub][part]: RESP_BLOB [0xE3][part][parts][up to 128 bytes]
constexpr uint8_t SUB_BLOB_PUT = 6;    // [sub][part][128 bytes] (the last part shorter)
constexpr uint8_t SUB_BLOB_COMMIT = 7; // taken only if a signature with it verifies; answer RESP_IDENTITY
constexpr uint8_t RESP_BLOB = 0xE3;
constexpr uint8_t RESP_IDENTITY = 0xE1;
constexpr uint8_t RESP_PUBKEY = 0xE2;
constexpr uint8_t RESP_ERROR = 0xEF;   // [0xEF][code][text]
constexpr uint8_t PUSH_RX = 0xA0;      // a reception (RX_LEN bytes, below)
constexpr uint8_t PUSH_RX_SIG = 0xA1;  // [0xA1][seq u32][part 0..2][128 bytes of the signature]

// Status bits in RESP_IDENTITY.
constexpr uint8_t ST_SECURE_BOOT = 1;
constexpr uint8_t ST_JTAG_OFF = 2;
constexpr uint8_t ST_SECURE_DOWNLOAD = 4;
constexpr uint8_t ST_KEY = 8;          // provisioned: receptions are signed
constexpr uint8_t ST_DIGESTS = 16;     // secure boot trusts only Neon's keys (other digest slots revoked)
constexpr uint8_t ST_KEY_LOST = 32;    // the chip has its key but its parameters in flash are gone or wrong

constexpr int RSA_BYTES = 384;
// PUSH_RX: [0xA0][2][seq u32][boot u32][us u64][rssi i8][snr*4 i8][fp 32][mac 6]
//          [freq f32][bw f32][sf u8][cr u8][nonce 16][raw sha256 32]
// fp is MeshCore's packet hash (the same for every copy of a flood); raw is this copy's whole frame.
// boot and seq are not unique (flash can be rolled back): freshness comes from the nonce.
constexpr int RX_LEN = 116;

// A packet came in (Dispatcher::logRxRaw): push its signed reception when provisioned.
void onRx(float snr, float rssi, const uint8_t raw[], int len, BaseSerialInterface* serial);

// The radio's settings as the radio confirmed them (CustomSX1262Wrapper::setParams); they go into
// every signature, and nothing is signed while they are unknown (ok false).
void radioSet(float freq, float bw, uint8_t sf, uint8_t cr, bool ok);

// MeshCore's factory reset: NVS erased, the key's parameters kept.
bool eraseNvsKeepingKey();

// A CMD_NEON frame: writes the answer to `out` (at least 176 bytes) and returns its length.
int command(const uint8_t* frame, int len, uint8_t* out);

}  // namespace neon
