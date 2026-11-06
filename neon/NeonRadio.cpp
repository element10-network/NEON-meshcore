// See NeonRadio.h.
#include "NeonRadio.h"

#include <Arduino.h>
#include <Preferences.h>
#include <SHA256.h>
#include <string.h>

#include <Packet.h>
#include <helpers/BaseSerialInterface.h>

#include "KeyDigest.h"  // NEON_KEY_DIGESTS: the project's firmware keys (build.sh, from key-digests.hex)
#include "bootloader_random.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "nvs_flash.h"
#include "esp_random.h"
#include "esp_secure_boot.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "mbedtls/bignum.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/rsa.h"
#include "soc/esp32s3/esp_ds.h"
#include "soc/esp32s3/esp_hmac.h"

namespace neon {

namespace {

const char* NS = "neon";
const char* DOMAIN = "neon-mc-rx/2";

// The key. The chip's eFuses are the truth: the block with the DS purpose is the key; flash only
// holds its encrypted parameters and modulus, checked with a signature when loaded.
struct Key {
  bool loaded = false;
  bool present = false;  // usable: parameters loaded and checked
  bool lost = false;     // the chip has a DS key block, but no matching parameters
  esp_ds_data_t ds;
  uint8_t block = 0;     // HMAC key id (0..5: EFUSE_BLK_KEY0..5)
  uint8_t modulus[RSA_BYTES];  // big-endian
};
Key key;
uint32_t boot = 0;
uint32_t seq = 0;
uint8_t nonce[16] = {0};
bool nonceSet = false;
struct {
  bool ok = false;
  uint32_t changed_ms = 0;
  float freq = 0, bw = 0;
  uint8_t sf = 0, cr = 0;
} radio;
// Fingerprints signed in the last seconds: a flood's copies are signed once.
struct Recent {
  uint8_t fp[8];
  uint32_t ms;
};
Recent recent[16];
int recentNext = 0;
// The parameters blob (ds then modulus) being put back by the atom.
constexpr int BLOB_LEN = sizeof(esp_ds_data_t) + RSA_BYTES;
constexpr int BLOB_PARTS = (BLOB_LEN + 127) / 128;
uint8_t incoming[BLOB_LEN];
uint32_t incomingParts = 0;  // bit per part received

bool fuse(const esp_efuse_desc_t* field[]) { return esp_efuse_read_field_bit(field); }

bool burn(const esp_efuse_desc_t* field[]) {
  return fuse(field) || (esp_efuse_write_field_bit(field) == ESP_OK && fuse(field));
}

// The block holding a DS key, if any.
int dsBlock() {
  for (int b = EFUSE_BLK_KEY0; b < EFUSE_BLK_KEY_MAX; b++)
    if (esp_efuse_get_key_purpose((esp_efuse_block_t)b) == ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE) return b;
  return -1;
}

// Secure boot trusts only Neon's keys: each of the three digest slots holds one of
// NEON_KEY_DIGESTS or is revoked. `fix` revokes (for good) the other slots, but only when a slot
// that stays holds the project key's digest (the first one, the key this firmware is signed with):
// revoking every slot, or the one the firmware starts with, would leave a board that never starts.
bool digestsOk(bool fix) {
  static const uint8_t ALLOWED[][32] = NEON_KEY_DIGESTS;
  static_assert(sizeof(ALLOWED) / sizeof(ALLOWED[0]) == 2, "two key digests: the project key and its backup");
  // What each slot holds: -1 revoked, 0 neither of ours, 1 the project key, 2 the backup key.
  int holds[3];
  for (unsigned slot = 0; slot < 3; slot++) {
    holds[slot] = 0;
    if (esp_efuse_get_digest_revoke(slot)) {
      holds[slot] = -1;
      continue;
    }
    // As the ROM and the bootloader read it: the first block with this slot's purpose. A second
    // block with the same purpose is refused outright (a foreign key could hide behind ours).
    const esp_efuse_purpose_t purpose = (esp_efuse_purpose_t)(ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0 + slot);
    int count = 0;
    for (int b = EFUSE_BLK_KEY0; b < EFUSE_BLK_KEY_MAX; b++)
      if (esp_efuse_get_key_purpose((esp_efuse_block_t)b) == purpose) count++;
    if (count > 1) return false;
    esp_efuse_block_t blk;
    if (!esp_efuse_find_purpose(purpose, &blk)) continue;
    uint8_t d[32];
    if (esp_efuse_read_block(blk, d, 0, 256) != ESP_OK) continue;
    for (int k = 0; k < 2 && holds[slot] == 0; k++)
      if (memcmp(d, ALLOWED[k], 32) == 0) holds[slot] = k + 1;
  }
  bool project = false, foreign = false;
  for (int h : holds) {
    project |= h == 1;
    foreign |= h == 0;
  }
  if (!project) return false;  // never revoke anything then
  if (!foreign) return true;
  if (!fix) return false;
  for (unsigned slot = 0; slot < 3; slot++)
    if (holds[slot] == 0 && (esp_efuse_set_digest_revoke(slot) != ESP_OK || !esp_efuse_get_digest_revoke(slot)))
      return false;
  return true;
}

uint8_t status() {
  uint8_t s = 0;
  if (esp_secure_boot_enabled()) s |= ST_SECURE_BOOT;
  if (fuse(ESP_EFUSE_HARD_DIS_JTAG) && fuse(ESP_EFUSE_DIS_USB_JTAG)) s |= ST_JTAG_OFF;
  if (fuse(ESP_EFUSE_ENABLE_SECURITY_DOWNLOAD) || fuse(ESP_EFUSE_DIS_DOWNLOAD_MODE)) s |= ST_SECURE_DOWNLOAD;
  if (key.present) s |= ST_KEY;
  if (digestsOk(false)) s |= ST_DIGESTS;
  if (key.lost) s |= ST_KEY_LOST;
  return s;
}

void reverse(uint8_t* b, int n) {
  for (int i = 0; i < n / 2; i++) {
    uint8_t t = b[i];
    b[i] = b[n - 1 - i];
    b[n - 1 - i] = t;
  }
}

// PKCS#1 v1.5 for SHA-256, as the DS peripheral wants it: little-endian.
void encode(const uint8_t hash[32], uint8_t em[RSA_BYTES]) {
  static const uint8_t INFO[19] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                   0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
  int ps = RSA_BYTES - 3 - sizeof(INFO) - 32;
  em[0] = 0x00;
  em[1] = 0x01;
  memset(em + 2, 0xff, ps);
  em[2 + ps] = 0x00;
  memcpy(em + 3 + ps, INFO, sizeof(INFO));
  memcpy(em + 3 + ps + sizeof(INFO), hash, 32);
  reverse(em, RSA_BYTES);
}

// Sign a SHA-256 hash with the chip's key; the signature big-endian.
bool sign(const esp_ds_data_t& ds, uint8_t block, const uint8_t hash[32], uint8_t sig[RSA_BYTES]) {
  // The length the driver copies by sits outside the encrypted parameters: only RSA-3072 (any
  // other would overrun the 384-byte buffers).
  if (ds.rsa_length != ESP_DS_RSA_3072) return false;
  alignas(4) static uint8_t em[RSA_BYTES];
  encode(hash, em);
  if (esp_ds_sign(em, &ds, (hmac_key_id_t)block, sig) != ESP_OK) return false;
  reverse(sig, RSA_BYTES);
  return true;
}

// A fresh signature verifies with the modulus: the parameters and the chip's key belong together.
bool selfTest(const esp_ds_data_t& ds, uint8_t block, const uint8_t mod[RSA_BYTES]) {
  uint8_t hash[32];
  alignas(4) static uint8_t sig[RSA_BYTES];
  esp_fill_random(hash, 32);
  mbedtls_rsa_context pub;
  mbedtls_rsa_init(&pub, MBEDTLS_RSA_PKCS_V15, 0);
  mbedtls_mpi N, E;
  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&E);
  bool ok = sign(ds, block, hash, sig) && mbedtls_mpi_read_binary(&N, mod, RSA_BYTES) == 0 &&
            mbedtls_mpi_lset(&E, 65537) == 0 &&
            mbedtls_rsa_import(&pub, &N, nullptr, nullptr, nullptr, &E) == 0 && mbedtls_rsa_complete(&pub) == 0 &&
            mbedtls_rsa_pkcs1_verify(&pub, nullptr, nullptr, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 32, hash, sig) == 0;
  mbedtls_rsa_free(&pub);
  mbedtls_mpi_free(&N);
  mbedtls_mpi_free(&E);
  return ok;
}

void load() {
  if (key.loaded) return;
  key.loaded = true;
  Preferences p;
  p.begin(NS, false);
  boot = p.getUInt("boot", 0) + 1;
  p.putUInt("boot", boot);
  int blk = dsBlock();
  if (blk >= 0) {
    bool read = p.getBytesLength("ds") == sizeof(esp_ds_data_t) && p.getBytesLength("mod") == RSA_BYTES &&
                p.getBytes("ds", &key.ds, sizeof(key.ds)) == sizeof(key.ds) &&
                p.getBytes("mod", key.modulus, RSA_BYTES) == RSA_BYTES;
    key.block = blk - EFUSE_BLK_KEY0;
    key.present = read && esp_efuse_get_key_dis_read((esp_efuse_block_t)blk) &&
                  selfTest(key.ds, key.block, key.modulus);
    key.lost = !key.present;
    // A power cut between the key's burn and this lock: done now.
    if (key.present) burn(ESP_EFUSE_WR_DIS_RD_DIS);
  }
  p.end();
}

int rng(void*, unsigned char* out, size_t len) {
  esp_fill_random(out, len);
  return 0;
}

int error(uint8_t* out, uint8_t code, const char* text) {
  out[0] = RESP_ERROR;
  out[1] = code;
  int n = strlen(text);
  if (n > 160) n = 160;
  memcpy(out + 2, text, n);
  return 2 + n;
}

// RESP_IDENTITY: [0xE1][version 2][status][mac 6][boot u32][key block][modulus sha256 32]
int identity(uint8_t* out) {
  int i = 0;
  out[i++] = RESP_IDENTITY;
  out[i++] = 2;
  out[i++] = status();
  esp_efuse_mac_get_default(out + i);
  i += 6;
  memcpy(out + i, &boot, 4);
  i += 4;
  out[i++] = key.present ? key.block : 0xff;
  if (key.present) {
    SHA256 h;
    h.update(key.modulus, RSA_BYTES);
    h.finalize(out + i, 32);
  } else {
    memset(out + i, 0, 32);
  }
  return i + 32;
}

// Lock the chip and make the key, once in the chip's life. Only on a chip that starts Neon-signed
// firmware alone (secure boot, only Neon's key digests), with JTAG off and ROM download limited to
// flash writes, so no other code can ever use the key. Takes a minute or two (RSA-3072 key
// generation): the atom waits for the answer.
int provision(uint8_t* out) {
  if (key.present) return identity(out);
  if (key.lost) return error(out, 8, "this chip's key parameters are missing: put back the atom's copy (SUB_BLOB_PUT)");
  if (dsBlock() >= 0) return error(out, 8, "this chip already has a key");
  if (!esp_secure_boot_enabled())
    return error(out, 1, "secure boot is off: flash the Neon bootloader first");
  // Everything that can refuse is checked before anything is burnt.
  // Read protection must still be possible (the Neon bootloader leaves it so).
  if (fuse(ESP_EFUSE_WR_DIS_RD_DIS)) return error(out, 3, "read protection is locked on this chip: no key can be kept secret");
  esp_efuse_block_t blk = esp_efuse_find_unused_key_block();
  if (blk == EFUSE_BLK_KEY_MAX) return error(out, 3, "no free eFuse key block");
  if (!digestsOk(true)) return error(out, 9, "secure boot trusts a key that is not Neon's");
  // SOFT_DIS_JTAG is a 3-bit field (the Neon bootloader burns all three).
  uint8_t soft = 0;
  esp_efuse_read_field_blob(ESP_EFUSE_SOFT_DIS_JTAG, &soft, 3);
  if (soft == 0) {
    uint8_t all = 7;
    esp_efuse_write_field_blob(ESP_EFUSE_SOFT_DIS_JTAG, &all, 3);
    esp_efuse_read_field_blob(ESP_EFUSE_SOFT_DIS_JTAG, &soft, 3);
  }
  if (soft == 0 || !burn(ESP_EFUSE_HARD_DIS_JTAG) || !burn(ESP_EFUSE_DIS_USB_JTAG) || !burn(ESP_EFUSE_DIS_DIRECT_BOOT) ||
      !(fuse(ESP_EFUSE_DIS_DOWNLOAD_MODE) || burn(ESP_EFUSE_ENABLE_SECURITY_DOWNLOAD)))
    return error(out, 2, "could not turn JTAG, direct boot and full download mode off");

  static esp_ds_p_data_t p;
  memset(&p, 0, sizeof(p));
  uint8_t hmac[32], iv[ESP_DS_IV_LEN];
  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  mbedtls_mpi N, D, rr, inv, m32;
  mbedtls_mpi_init(&N); mbedtls_mpi_init(&D); mbedtls_mpi_init(&rr); mbedtls_mpi_init(&inv); mbedtls_mpi_init(&m32);
  // True random numbers: no Wi-Fi or Bluetooth runs in this build, so the RNG's entropy source is
  // turned on for the keys.
  bootloader_random_enable();
  bool ok = mbedtls_rsa_gen_key(&rsa, rng, nullptr, RSA_BYTES * 8, 65537) == 0;
  esp_fill_random(hmac, sizeof(hmac));
  esp_fill_random(iv, sizeof(iv));
  bootloader_random_disable();
  ok = ok && mbedtls_rsa_export(&rsa, &N, nullptr, nullptr, &D, nullptr) == 0 &&
       // Rb = 2^(2 * bits) mod N; M' = -N^-1 mod 2^32 (IDF's configure_ds.py).
       mbedtls_mpi_lset(&rr, 1) == 0 && mbedtls_mpi_shift_l(&rr, RSA_BYTES * 8 * 2) == 0 &&
       mbedtls_mpi_mod_mpi(&rr, &rr, &N) == 0 &&
       mbedtls_mpi_lset(&m32, 1) == 0 && mbedtls_mpi_shift_l(&m32, 32) == 0 &&
       mbedtls_mpi_inv_mod(&inv, &N, &m32) == 0 &&
       mbedtls_mpi_write_binary_le(&D, (unsigned char*)p.Y, RSA_BYTES) == 0 &&
       mbedtls_mpi_write_binary_le(&N, (unsigned char*)p.M, RSA_BYTES) == 0 &&
       mbedtls_mpi_write_binary_le(&rr, (unsigned char*)p.Rb, RSA_BYTES) == 0 &&
       mbedtls_mpi_write_binary(&N, key.modulus, RSA_BYTES) == 0;
  if (ok) {
    uint32_t i32 = 0;
    mbedtls_mpi_write_binary_le(&inv, (unsigned char*)&i32, 4);
    p.M_prime = (uint32_t)(0u - i32);
    p.length = ESP_DS_RSA_3072;
    ok = esp_ds_encrypt_params(&key.ds, iv, &p, hmac) == ESP_OK;
  }
  // The private exponent leaves RAM now, whatever happens below.
  mbedtls_platform_zeroize(&p, sizeof(p));
  mbedtls_rsa_free(&rsa);
  mbedtls_mpi_free(&N); mbedtls_mpi_free(&D); mbedtls_mpi_free(&rr); mbedtls_mpi_free(&inv); mbedtls_mpi_free(&m32);
  if (!ok) {
    mbedtls_platform_zeroize(hmac, sizeof(hmac));
    return error(out, 4, "key generation failed");
  }

  // Saved (and read back) before anything is burnt: a reset after the burn finds them.
  Preferences pr;
  pr.begin(NS, false);
  static esp_ds_data_t back;
  static uint8_t mod_back[RSA_BYTES];
  ok = pr.putBytes("ds", &key.ds, sizeof(key.ds)) == sizeof(key.ds) &&
       pr.putBytes("mod", key.modulus, RSA_BYTES) == RSA_BYTES &&
       pr.getBytes("ds", &back, sizeof(back)) == sizeof(back) && memcmp(&back, &key.ds, sizeof(back)) == 0 &&
       pr.getBytes("mod", mod_back, RSA_BYTES) == RSA_BYTES && memcmp(mod_back, key.modulus, RSA_BYTES) == 0;
  pr.end();
  if (!ok) {
    mbedtls_platform_zeroize(hmac, sizeof(hmac));
    return error(out, 5, "the key could not be saved");
  }

  // Burnt read-protected: only the DS peripheral can use it from now on.
  // esp_efuse_write_key burns the key, its purpose and their read and write protection in one go.
  ok = esp_efuse_write_key(blk, ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE, hmac, sizeof(hmac)) == ESP_OK;
  mbedtls_platform_zeroize(hmac, sizeof(hmac));
  if (!ok) return error(out, 6, "the key could not be burnt: restart the radio and try again");
  if (!esp_efuse_get_key_dis_read(blk)) {
    key.lost = true;
    return error(out, 6, "the key could not be stored read-protected in the chip");
  }
  // From now on no key can be read-protected or unprotected again.
  burn(ESP_EFUSE_WR_DIS_RD_DIS);
  key.block = blk - EFUSE_BLK_KEY0;
  if (!selfTest(key.ds, key.block, key.modulus)) {
    key.lost = true;
    return error(out, 7, "the chip's signature did not verify");
  }
  key.present = true;
  // A clean start in a few seconds, after the answer is sent (the random source's ADC settings
  // are left changed by bootloader_random_disable).
  static esp_timer_handle_t restart = nullptr;
  esp_timer_create_args_t a = {};
  a.callback = [](void*) { esp_restart(); };
  a.name = "neon-restart";
  if (esp_timer_create(&a, &restart) == ESP_OK) esp_timer_start_once(restart, 3000000);
  return identity(out);
}

}  // namespace

void radioSet(float freq, float bw, uint8_t sf, uint8_t cr, bool ok) {
  radio.changed_ms = millis();
  radio.ok = ok;
  radio.freq = ok ? freq : 0;
  radio.bw = ok ? bw : 0;
  radio.sf = ok ? sf : 0;
  radio.cr = ok ? cr : 0;
}

bool eraseNvsKeepingKey() {
  static esp_ds_data_t ds;
  static uint8_t mod[RSA_BYTES];
  Preferences p;
  p.begin(NS, true);
  bool had = p.getBytes("ds", &ds, sizeof(ds)) == sizeof(ds) && p.getBytes("mod", mod, RSA_BYTES) == RSA_BYTES;
  uint32_t b = p.getUInt("boot", 0);
  p.end();
  if (nvs_flash_erase() != ESP_OK || nvs_flash_init() != ESP_OK) return false;
  p.begin(NS, false);
  bool ok = p.putUInt("boot", b) == 4;
  if (had)
    ok = p.putBytes("ds", &ds, sizeof(ds)) == sizeof(ds) && p.putBytes("mod", mod, RSA_BYTES) == RSA_BYTES && ok;
  p.end();
  return ok;
}

void onRx(float snr, float rssi, const uint8_t raw[], int len, BaseSerialInterface* serial) {
  load();
  // Signed only with a key, settings the radio confirmed, and a freshness value from the electrodes.
  if (!key.present || !radio.ok || !nonceSet || serial == nullptr) return;
  // A packet heard before a change of settings can still be waiting to be read: none signed in the
  // two seconds after one.
  if (millis() - radio.changed_ms < 2000) return;
  mesh::Packet pkt;
  // Only what MeshCore itself would take (its parser refuses newer payload versions).
  if (len <= 0 || !pkt.readFrom(raw, len) || pkt.getPayloadVer() > PAYLOAD_VER_1) return;

  // The packet's fingerprint, exactly as MeshCore's own packet hash (payload type, the path length
  // as stored for traces, the payload), at full length.
  uint8_t fp[32];
  {
    SHA256 h;
    uint8_t t = pkt.getPayloadType();
    h.update(&t, 1);
    if (t == PAYLOAD_TYPE_TRACE) h.update(&pkt.path_len, sizeof(pkt.path_len));
    h.update(pkt.payload, pkt.payload_len);
    h.finalize(fp, 32);
  }
  uint32_t now = millis();
  for (const Recent& r : recent)
    if (memcmp(r.fp, fp, 8) == 0 && now - r.ms < 10000) return;
  memcpy(recent[recentNext].fp, fp, 8);
  recent[recentNext].ms = now;
  recentNext = (recentNext + 1) % 16;
  uint8_t rx[RX_LEN];
  int i = 0;
  rx[i++] = PUSH_RX;
  rx[i++] = 2;
  seq++;
  memcpy(rx + i, &seq, 4); i += 4;
  memcpy(rx + i, &boot, 4); i += 4;
  int64_t us = esp_timer_get_time();
  memcpy(rx + i, &us, 8); i += 8;
  rx[i++] = (uint8_t)(int8_t)(rssi < -128 ? -128 : rssi > 127 ? 127 : rssi);
  float s4 = snr * 4;
  rx[i++] = (uint8_t)(int8_t)(s4 < -128 ? -128 : s4 > 127 ? 127 : s4);
  memcpy(rx + i, fp, 32); i += 32;
  esp_efuse_mac_get_default(rx + i); i += 6;
  memcpy(rx + i, &radio.freq, 4); i += 4;
  memcpy(rx + i, &radio.bw, 4); i += 4;
  rx[i++] = radio.sf;
  rx[i++] = radio.cr;
  memcpy(rx + i, nonce, 16); i += 16;
  // The whole packet as heard (header, path, transport codes): which copy of a flood this was.
  {
    SHA256 h;
    h.update(raw, len);
    h.finalize(rx + i, 32);
    i += 32;
  }

  uint8_t hash[32];
  {
    SHA256 h;
    h.update(DOMAIN, strlen(DOMAIN));
    h.update(rx + 1, RX_LEN - 1);
    h.finalize(hash, 32);
  }
  alignas(4) static uint8_t sig[RSA_BYTES];
  if (!sign(key.ds, key.block, hash, sig)) return;
  serial->writeFrame(rx, RX_LEN);
  uint8_t part[6 + 128];
  for (uint8_t k = 0; k < 3; k++) {
    part[0] = PUSH_RX_SIG;
    memcpy(part + 1, &seq, 4);
    part[5] = k;
    memcpy(part + 6, sig + 128 * k, 128);
    serial->writeFrame(part, sizeof(part));
  }
}

int command(const uint8_t* frame, int len, uint8_t* out) {
  load();
  if (len < 2) return error(out, 0, "no subcommand");
  switch (frame[1]) {
    case SUB_IDENTITY:
      return identity(out);
    case SUB_PROVISION:
      return provision(out);
    case SUB_PUBKEY:
      if (!key.present) return error(out, 7, "no key");
      if (len < 3 || frame[2] > 2) return error(out, 0, "part 0 to 2");
      out[0] = RESP_PUBKEY;
      out[1] = frame[2];
      memcpy(out + 2, key.modulus + 128 * frame[2], 128);
      return 2 + 128;
    case SUB_NONCE:
      if (len < 18) return error(out, 0, "16 bytes");
      memcpy(nonce, frame + 2, 16);
      nonceSet = true;
      return identity(out);
    case SUB_BLOB_GET: {
      if (!key.present) return error(out, 7, "no key");
      if (len < 3 || frame[2] >= BLOB_PARTS) return error(out, 0, "no such part");
      int off = frame[2] * 128, n = BLOB_LEN - off < 128 ? BLOB_LEN - off : 128;
      out[0] = RESP_BLOB;
      out[1] = frame[2];
      out[2] = BLOB_PARTS;
      for (int k = 0; k < n; k++) {
        int at = off + k;
        out[3 + k] = at < (int)sizeof(esp_ds_data_t) ? ((const uint8_t*)&key.ds)[at] : key.modulus[at - sizeof(esp_ds_data_t)];
      }
      return 3 + n;
    }
    case SUB_BLOB_PUT: {
      if (len < 3 || frame[2] >= BLOB_PARTS) return error(out, 0, "no such part");
      int off = frame[2] * 128, n = BLOB_LEN - off < 128 ? BLOB_LEN - off : 128;
      if (len < 3 + n) return error(out, 0, "part too short");
      memcpy(incoming + off, frame + 3, n);
      incomingParts |= 1u << frame[2];
      return identity(out);
    }
    case SUB_BLOB_COMMIT: {
      if (key.present) return identity(out);
      int blk = dsBlock();
      if (blk < 0) return error(out, 7, "this chip has no key");
      if (!esp_efuse_get_key_dis_read((esp_efuse_block_t)blk)) return error(out, 6, "this chip's key is not read-protected");
      if (incomingParts != (1u << BLOB_PARTS) - 1) return error(out, 0, "parts missing");
      static esp_ds_data_t ds;
      static uint8_t mod[RSA_BYTES];
      memcpy(&ds, incoming, sizeof(ds));
      memcpy(mod, incoming + sizeof(ds), RSA_BYTES);
      incomingParts = 0;
      // Taken only if it belongs to this chip's key.
      if (!selfTest(ds, blk - EFUSE_BLK_KEY0, mod)) return error(out, 6, "these parameters are not this chip's");
      Preferences pr;
      pr.begin(NS, false);
      bool ok = pr.putBytes("ds", &ds, sizeof(ds)) == sizeof(ds) && pr.putBytes("mod", mod, RSA_BYTES) == RSA_BYTES;
      pr.end();
      if (!ok) return error(out, 5, "could not be saved");
      key.ds = ds;
      memcpy(key.modulus, mod, RSA_BYTES);
      key.block = blk - EFUSE_BLK_KEY0;
      key.present = true;
      key.lost = false;
      return identity(out);
    }
    default:
      return error(out, 0, "unknown subcommand");
  }
}

}  // namespace neon
