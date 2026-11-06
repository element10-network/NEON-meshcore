// See NeonRadio.h.
#include "NeonRadio.h"

#include <Arduino.h>
#include <Preferences.h>
#include <SHA256.h>
#include <string.h>

#include <Packet.h>
#include <helpers/BaseSerialInterface.h>

#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_random.h"
#include "esp_secure_boot.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"
#include "soc/esp32s3/esp_ds.h"
#include "soc/esp32s3/esp_hmac.h"

namespace neon {

namespace {

const char* NS = "neon";
const char* DOMAIN = "neon-mc-rx/1";

// The key: loaded once (DS parameters, their eFuse block, the modulus).
struct Key {
  bool loaded = false;
  bool present = false;
  esp_ds_data_t ds;
  uint8_t block = 0;           // HMAC key id (0..5: EFUSE_BLK_KEY0..5)
  uint8_t modulus[RSA_BYTES];  // big-endian
};
Key key;
uint32_t boot = 0;
uint32_t seq = 0;

bool fuse(const esp_efuse_desc_t* field[]) { return esp_efuse_read_field_bit(field); }

uint8_t status() {
  uint8_t s = 0;
  if (esp_secure_boot_enabled()) s |= ST_SECURE_BOOT;
  if (fuse(ESP_EFUSE_HARD_DIS_JTAG) && fuse(ESP_EFUSE_DIS_USB_JTAG)) s |= ST_JTAG_OFF;
  if (fuse(ESP_EFUSE_ENABLE_SECURITY_DOWNLOAD) || fuse(ESP_EFUSE_DIS_DOWNLOAD_MODE)) s |= ST_SECURE_DOWNLOAD;
  if (key.present) s |= ST_KEY;
  return s;
}

void load() {
  if (key.loaded) return;
  key.loaded = true;
  Preferences p;
  p.begin(NS, false);
  boot = p.getUInt("boot", 0) + 1;
  p.putUInt("boot", boot);
  key.present = p.getBytesLength("ds") == sizeof(esp_ds_data_t) && p.getBytesLength("mod") == RSA_BYTES &&
                p.getBytes("ds", &key.ds, sizeof(key.ds)) == sizeof(key.ds) &&
                p.getBytes("mod", key.modulus, RSA_BYTES) == RSA_BYTES;
  key.block = p.getUChar("blk", 0);
  p.end();
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
bool sign(const uint8_t hash[32], uint8_t sig[RSA_BYTES]) {
  static uint8_t em[RSA_BYTES];
  encode(hash, em);
  if (esp_ds_sign(em, &key.ds, (hmac_key_id_t)key.block, sig) != ESP_OK) return false;
  reverse(sig, RSA_BYTES);
  return true;
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

// RESP_IDENTITY: [0xE1][version][status][mac 6][boot u32][key block][modulus sha256 32]
int identity(uint8_t* out) {
  int i = 0;
  out[i++] = RESP_IDENTITY;
  out[i++] = 1;
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

bool burn(const esp_efuse_desc_t* field[]) {
  return fuse(field) || (esp_efuse_write_field_bit(field) == ESP_OK && fuse(field));
}

// Lock the chip and make the key. Only on a chip that boots Neon-signed firmware alone (secure
// boot), with JTAG off and ROM download limited to flash writes, so no other code can ever use
// the key. Takes a minute or two (RSA-3072 key generation).
int provision(uint8_t* out) {
  if (key.present) return identity(out);
  if (!esp_secure_boot_enabled())
    return error(out, 1, "secure boot is off: flash the Neon bootloader first");
  if (!burn(ESP_EFUSE_HARD_DIS_JTAG) || !burn(ESP_EFUSE_DIS_USB_JTAG) ||
      !(fuse(ESP_EFUSE_DIS_DOWNLOAD_MODE) || burn(ESP_EFUSE_ENABLE_SECURITY_DOWNLOAD)))
    return error(out, 2, "could not turn JTAG and full download mode off");
  esp_efuse_block_t blk = esp_efuse_find_unused_key_block();
  if (blk == EFUSE_BLK_KEY_MAX) return error(out, 3, "no free eFuse key block");

  static esp_ds_p_data_t p;
  memset(&p, 0, sizeof(p));
  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  mbedtls_mpi N, D, rr, inv, m32;
  mbedtls_mpi_init(&N); mbedtls_mpi_init(&D); mbedtls_mpi_init(&rr); mbedtls_mpi_init(&inv); mbedtls_mpi_init(&m32);
  bool ok = mbedtls_rsa_gen_key(&rsa, rng, nullptr, RSA_BYTES * 8, 65537) == 0 &&
            mbedtls_rsa_export(&rsa, &N, nullptr, nullptr, &D, nullptr) == 0 &&
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
  }
  // The private exponent leaves RAM now, whatever happens below.
  mbedtls_rsa_free(&rsa);
  mbedtls_mpi_free(&D); mbedtls_mpi_free(&rr); mbedtls_mpi_free(&inv); mbedtls_mpi_free(&m32);
  if (!ok) {
    mbedtls_mpi_free(&N);
    memset(&p, 0, sizeof(p));
    return error(out, 4, "key generation failed");
  }
  uint8_t hmac[32], iv[ESP_DS_IV_LEN];
  esp_fill_random(hmac, sizeof(hmac));
  esp_fill_random(iv, sizeof(iv));
  ok = esp_ds_encrypt_params(&key.ds, iv, &p, hmac) == ESP_OK;
  memset(&p, 0, sizeof(p));
  // Burnt read-protected: only the DS peripheral can use it from now on.
  ok = ok && esp_efuse_write_key(blk, ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE, hmac, sizeof(hmac)) == ESP_OK;
  memset(hmac, 0, sizeof(hmac));
  if (!ok) {
    mbedtls_mpi_free(&N);
    return error(out, 5, "the key could not be stored in the chip");
  }
  if (!esp_efuse_get_key_dis_read(blk)) esp_efuse_set_key_dis_read(blk);
  key.block = blk - EFUSE_BLK_KEY0;

  // Check: a signature made by the chip verifies with the public key.
  uint8_t hash[32], sig[RSA_BYTES];
  esp_fill_random(hash, 32);
  mbedtls_rsa_context pub;
  mbedtls_rsa_init(&pub, MBEDTLS_RSA_PKCS_V15, 0);
  mbedtls_mpi E;
  mbedtls_mpi_init(&E);
  mbedtls_mpi_lset(&E, 65537);
  ok = sign(hash, sig) && mbedtls_rsa_import(&pub, &N, nullptr, nullptr, nullptr, &E) == 0 &&
       mbedtls_rsa_complete(&pub) == 0 &&
       mbedtls_rsa_pkcs1_verify(&pub, nullptr, nullptr, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 32, hash, sig) == 0;
  mbedtls_rsa_free(&pub);
  mbedtls_mpi_free(&E);
  mbedtls_mpi_free(&N);
  if (!ok) return error(out, 6, "the chip's signature did not verify");

  Preferences pr;
  pr.begin(NS, false);
  pr.putBytes("ds", &key.ds, sizeof(key.ds));
  pr.putBytes("mod", key.modulus, RSA_BYTES);
  pr.putUChar("blk", key.block);
  pr.end();
  key.present = true;
  return identity(out);
}

}  // namespace

void onRx(float snr, float rssi, const uint8_t raw[], int len, BaseSerialInterface* serial) {
  load();
  if (!key.present || serial == nullptr || !serial->isConnected()) return;
  mesh::Packet pkt;
  if (len <= 0 || !pkt.readFrom(raw, len)) return;

  // The packet's fingerprint, as MeshCore's own packet hash (payload type, payload; the path
  // length for traces), at full length.
  uint8_t fp[32];
  {
    SHA256 h;
    uint8_t t = pkt.getPayloadType();
    h.update(&t, 1);
    if (t == PAYLOAD_TYPE_TRACE) h.update(&pkt.path_len, 1);
    h.update(pkt.payload, pkt.payload_len);
    h.finalize(fp, 32);
  }
  uint8_t rx[RX_LEN];
  int i = 0;
  rx[i++] = PUSH_RX;
  rx[i++] = 1;
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

  uint8_t hash[32];
  {
    SHA256 h;
    h.update(DOMAIN, strlen(DOMAIN));
    h.update(rx + 1, RX_LEN - 1);
    h.finalize(hash, 32);
  }
  static uint8_t sig[RSA_BYTES];
  if (!sign(hash, sig)) return;
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
      if (!key.present) return error(out, 7, "no key yet");
      if (len < 3 || frame[2] > 2) return error(out, 0, "part 0 to 2");
      out[0] = RESP_PUBKEY;
      out[1] = frame[2];
      memcpy(out + 2, key.modulus + 128 * frame[2], 128);
      return 2 + 128;
    default:
      return error(out, 0, "unknown subcommand");
  }
}

}  // namespace neon
