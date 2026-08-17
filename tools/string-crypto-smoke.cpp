//===- string-crypto-smoke.cpp - authenticated string primitive tests ----===//

#include "llvm/Transforms/Obfuscation/AuthenticatedStringCrypto.h"

#include <array>
#include <cstdint>

static int testChaChaVector() {
  const std::array<uint8_t, 32> Key = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  const std::array<uint8_t, 12> Nonce = {
      0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
      0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};
  const std::array<uint8_t, 64> Expected = {
      0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4,
      0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,
      0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09,0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
      0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e};
  std::array<uint8_t, 64> Output{};
  allvm_str_chacha_block(Output.data(), Key.data(), Nonce.data(), 1U);
  return Output == Expected ? 0 : 1;
}

static int testRecordRoundTrip() {
  std::array<uint8_t, 64> Key{};
  std::array<uint8_t, 64> ShareA{};
  std::array<uint8_t, 64> ShareB{};
  std::array<uint8_t, 12> Nonce{};
  std::array<uint8_t, 80> Plain{};
  std::array<uint8_t, 128> Record{};
  std::array<uint8_t, 80> Output{};
  for (unsigned I = 0; I < Key.size(); ++I) {
    Key[I] = static_cast<uint8_t>(I);
    ShareA[I] = static_cast<uint8_t>(I * 7U + 3U);
    ShareB[I] = static_cast<uint8_t>(Key[I] ^ ShareA[I]);
  }
  for (unsigned I = 0; I < Nonce.size(); ++I)
    Nonce[I] = static_cast<uint8_t>(0xa0U + I);
  for (unsigned I = 0; I < Plain.size(); ++I)
    Plain[I] = static_cast<uint8_t>(I * 3U + 1U);

  if (!allvm_str_seal_record(Record.data(), Record.size(), Plain.data(),
                              Plain.size(), Key.data(), Nonce.data(), 7U, 19U,
                              0U))
    return 1;
  if (allvm_str_load64_le(Record.data() + ALLVM_STR_TAG0_OFFSET) !=
      0xd9714fb47519b514ULL)
    return 2;
  if (allvm_str_load64_le(Record.data() + ALLVM_STR_TAG1_OFFSET) !=
      0xbf73ee4b45962282ULL)
    return 3;
  if (!allvm_str_open_record_split(
          Output.data(), Record.data(), Record.size(), ShareA.data(),
          ShareB.data(), 7U, 19U, 0U, Plain.size()))
    return 4;
  if (Output != Plain)
    return 5;

  Record[60] ^= 1U;
  Output.fill(0x55U);
  if (allvm_str_open_record_split(
          Output.data(), Record.data(), Record.size(), ShareA.data(),
          ShareB.data(), 7U, 19U, 0U, Plain.size()))
    return 6;
  for (uint8_t Byte : Output)
    if (Byte != 0U)
      return 7;
  return 0;
}

static int testHeaderBindingAndUtf16() {
  std::array<uint8_t, 64> Key{};
  std::array<uint8_t, 64> ShareA{};
  std::array<uint8_t, 64> ShareB{};
  std::array<uint8_t, 12> Nonce{};
  const std::array<uint8_t, 6> Plain = {0x41, 0x00, 0x42, 0x00, 0x00, 0x00};
  std::array<uint8_t, ALLVM_STR_HEADER_SIZE + Plain.size()> Record{};
  std::array<uint8_t, Plain.size()> Output{};
  for (unsigned I = 0; I < Key.size(); ++I) {
    Key[I] = static_cast<uint8_t>(0xffU - I);
    ShareA[I] = static_cast<uint8_t>(I * 5U + 11U);
    ShareB[I] = static_cast<uint8_t>(Key[I] ^ ShareA[I]);
  }
  for (unsigned I = 0; I < Nonce.size(); ++I)
    Nonce[I] = static_cast<uint8_t>(I * 9U + 1U);

  if (!allvm_str_seal_record(
          Record.data(), Record.size(), Plain.data(), Plain.size(), Key.data(),
          Nonce.data(), 3U, 64U, ALLVM_STR_FLAG_UTF16))
    return 1;
  if (!allvm_str_open_record_split(
          Output.data(), Record.data(), Record.size(), ShareA.data(),
          ShareB.data(), 3U, 64U, ALLVM_STR_FLAG_UTF16, Plain.size()))
    return 2;
  if (Output != Plain)
    return 3;

  Output.fill(0x66U);
  if (allvm_str_open_record_split(
          Output.data(), Record.data(), Record.size(), ShareA.data(),
          ShareB.data(), 4U, 64U, ALLVM_STR_FLAG_UTF16, Plain.size()))
    return 4;
  for (uint8_t Byte : Output)
    if (Byte != 0U)
      return 5;
  return 0;
}

int main() {
  if (int Result = testChaChaVector())
    return 10 + Result;
  if (int Result = testRecordRoundTrip())
    return 20 + Result;
  if (int Result = testHeaderBindingAndUtf16())
    return 30 + Result;
  return 0;
}
