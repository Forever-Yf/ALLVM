//===- string-poly1305-crypto-smoke.cpp - RFC 8439 record tests ----------===//

#include "llvm/Transforms/Obfuscation/AuthenticatedStringPoly1305Crypto.h"

#include <array>
#include <cstdint>
#include <cstdio>

template <size_t N>
static bool equalsWithDiagnostic(const uint8_t *Actual,
                                 const std::array<uint8_t, N> &Expected,
                                 const char *Name) {
  for (size_t I = 0; I < N; ++I) {
    if (Actual[I] == Expected[I])
      continue;
    std::fprintf(stderr, "%s mismatch\nexpected=", Name);
    for (uint8_t Byte : Expected)
      std::fprintf(stderr, "%02x", static_cast<unsigned>(Byte));
    std::fprintf(stderr, "\nactual  =");
    for (size_t J = 0; J < N; ++J)
      std::fprintf(stderr, "%02x", static_cast<unsigned>(Actual[J]));
    std::fprintf(stderr, "\n");
    return false;
  }
  return true;
}

static int testPoly1305Vector() {
  const std::array<uint8_t, 32> Key = {
      0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
      0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
      0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
      0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b};
  const std::array<uint8_t, 34> Message = {
      'C','r','y','p','t','o','g','r','a','p','h','i','c',' ',
      'F','o','r','u','m',' ','R','e','s','e','a','r','c','h',' ',
      'G','r','o','u','p'};
  const std::array<uint8_t, 16> Expected = {
      0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
      0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9};
  std::array<uint8_t, 16> Tag{};
  allvm_str_poly1305_auth(Tag.data(), Message.data(), Message.size(),
                          Key.data());
  return equalsWithDiagnostic(Tag.data(), Expected, "Poly1305 RFC vector")
             ? 0
             : 1;
}

static int testRecordRoundTrip() {
  std::array<uint8_t, 64> Root{};
  std::array<uint8_t, 64> ShareA{};
  std::array<uint8_t, 64> ShareB{};
  std::array<uint8_t, 12> Nonce{};
  std::array<uint8_t, 80> Plain{};
  std::array<uint8_t, 128> Record{};
  std::array<uint8_t, 80> Output{};
  constexpr uint32_t PlainSize = 80U;

  // Independently generated with RFC 8439 ChaCha20-Poly1305 using:
  // effective key = root[0..31] XOR root[32..63] = 32 bytes of 0x20,
  // nonce a0..ab, and record bytes 0..31 as AAD.
  const std::array<uint8_t, 16> ExpectedTag = {
      0x66,0x03,0xa6,0xf3,0x87,0x4a,0x00,0xab,
      0xb5,0x02,0x04,0x78,0x8b,0xfe,0x9c,0xec};
  const std::array<uint8_t, 16> ExpectedCipherPrefix = {
      0x24,0xdb,0xdb,0xc4,0x50,0xa0,0x44,0xad,
      0x38,0x63,0xd2,0x1d,0x15,0x41,0x26,0x1a};

  for (unsigned I = 0; I < Root.size(); ++I) {
    Root[I] = static_cast<uint8_t>(I);
    ShareA[I] = static_cast<uint8_t>(I * 7U + 3U);
    ShareB[I] = static_cast<uint8_t>(Root[I] ^ ShareA[I]);
  }
  for (unsigned I = 0; I < Nonce.size(); ++I)
    Nonce[I] = static_cast<uint8_t>(0xa0U + I);
  for (unsigned I = 0; I < Plain.size(); ++I)
    Plain[I] = static_cast<uint8_t>(I * 3U + 1U);

  if (!allvm_str_seal_record(Record.data(), Record.size(), Plain.data(),
                              PlainSize, Root.data(), Nonce.data(), 7U, 19U,
                              0U))
    return 1;
  if (allvm_str_load32_le(Record.data() + 4U) != ALLVM_STR_VERSION)
    return 2;
  if (!equalsWithDiagnostic(Record.data() + ALLVM_STR_TAG_OFFSET,
                            ExpectedTag, "record-v2 tag"))
    return 3;
  if (!equalsWithDiagnostic(
          Record.data() + ALLVM_STR_CIPHERTEXT_OFFSET,
          ExpectedCipherPrefix, "record-v2 ciphertext prefix"))
    return 4;
  if (!allvm_str_open_record_split(
          Output.data(), Record.data(), Record.size(), ShareA.data(),
          ShareB.data(), 7U, 19U, 0U, PlainSize))
    return 5;
  if (Output != Plain)
    return 6;

  Record[60] ^= 1U;
  Output.fill(0x55U);
  if (allvm_str_open_record_split(
          Output.data(), Record.data(), Record.size(), ShareA.data(),
          ShareB.data(), 7U, 19U, 0U, PlainSize))
    return 7;
  for (uint8_t Byte : Output)
    if (Byte != 0U)
      return 8;
  return 0;
}

static int testHeaderBindingAndUtf16() {
  std::array<uint8_t, 64> Root{};
  std::array<uint8_t, 64> ShareA{};
  std::array<uint8_t, 64> ShareB{};
  std::array<uint8_t, 12> Nonce{};
  const std::array<uint8_t, 6> Plain = {0x41, 0x00, 0x42, 0x00, 0x00, 0x00};
  std::array<uint8_t, ALLVM_STR_HEADER_SIZE + Plain.size()> Record{};
  std::array<uint8_t, Plain.size()> Output{};
  constexpr uint32_t PlainSize = 6U;

  for (unsigned I = 0; I < Root.size(); ++I) {
    Root[I] = static_cast<uint8_t>(0xffU - I);
    ShareA[I] = static_cast<uint8_t>(I * 5U + 11U);
    ShareB[I] = static_cast<uint8_t>(Root[I] ^ ShareA[I]);
  }
  for (unsigned I = 0; I < Nonce.size(); ++I)
    Nonce[I] = static_cast<uint8_t>(I * 9U + 1U);

  if (!allvm_str_seal_record(
          Record.data(), Record.size(), Plain.data(), PlainSize, Root.data(),
          Nonce.data(), 3U, 64U, ALLVM_STR_FLAG_UTF16))
    return 1;
  if (!allvm_str_open_record_split(
          Output.data(), Record.data(), Record.size(), ShareA.data(),
          ShareB.data(), 3U, 64U, ALLVM_STR_FLAG_UTF16, PlainSize))
    return 2;
  if (Output != Plain)
    return 3;

  Output.fill(0x66U);
  if (allvm_str_open_record_split(
          Output.data(), Record.data(), Record.size(), ShareA.data(),
          ShareB.data(), 4U, 64U, ALLVM_STR_FLAG_UTF16, PlainSize))
    return 4;
  for (uint8_t Byte : Output)
    if (Byte != 0U)
      return 5;

  Record[28] ^= 1U;
  Output.fill(0x77U);
  if (allvm_str_open_record_split(
          Output.data(), Record.data(), Record.size(), ShareA.data(),
          ShareB.data(), 3U, 64U, ALLVM_STR_FLAG_UTF16, PlainSize))
    return 6;
  for (uint8_t Byte : Output)
    if (Byte != 0U)
      return 7;
  return 0;
}

int main() {
  if (int Result = testPoly1305Vector())
    return 10 + Result;
  if (int Result = testRecordRoundTrip())
    return 20 + Result;
  if (int Result = testHeaderBindingAndUtf16())
    return 30 + Result;
  return 0;
}
