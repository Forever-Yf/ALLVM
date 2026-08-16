//===- SecureRandom.h - ALLVM build-time secure seeding -------*- C++ -*-===//
//
// Provides a small, dependency-free bridge from the operating system CSPRNG
// to the existing CryptoUtils AES-CTR generator.  A deterministic build can
// be requested explicitly with ALLVM_BUILD_SEED; normal builds use fresh OS
// entropy and domain-separated per-pass seeds.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_OBFUSCATION_SECURERANDOM_H
#define LLVM_TRANSFORMS_OBFUSCATION_SECURERANDOM_H

#include "llvm/CryptoUtils.h"
#include "llvm/Support/ErrorHandling.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace llvm {
namespace allvm {
namespace detail {

inline void secureZero(void *Ptr, std::size_t Size) {
  volatile std::uint8_t *Bytes =
      static_cast<volatile std::uint8_t *>(Ptr);
  while (Size-- != 0)
    *Bytes++ = 0;
}

inline char hexDigit(std::uint8_t Value) {
  return Value < 10 ? static_cast<char>('0' + Value)
                    : static_cast<char>('a' + (Value - 10));
}

inline std::string hexEncode(const std::uint8_t *Bytes, std::size_t Size) {
  std::string Result;
  Result.resize(Size * 2);
  for (std::size_t I = 0; I < Size; ++I) {
    Result[I * 2] = hexDigit(static_cast<std::uint8_t>(Bytes[I] >> 4));
    Result[I * 2 + 1] = hexDigit(static_cast<std::uint8_t>(Bytes[I] & 0x0f));
  }
  return Result;
}

inline bool isHexString(const std::string &Value) {
  for (char C : Value) {
    const bool IsDigit = C >= '0' && C <= '9';
    const bool IsLower = C >= 'a' && C <= 'f';
    const bool IsUpper = C >= 'A' && C <= 'F';
    if (!IsDigit && !IsLower && !IsUpper)
      return false;
  }
  return true;
}

#ifdef _WIN32
inline bool fillFromOs(std::uint8_t *Buffer, std::size_t Size) {
  while (Size != 0) {
    const std::size_t MaxChunk =
        static_cast<std::size_t>(std::numeric_limits<ULONG>::max());
    const ULONG Chunk =
        static_cast<ULONG>(Size > MaxChunk ? MaxChunk : Size);
    const NTSTATUS Status = BCryptGenRandom(
        nullptr, reinterpret_cast<PUCHAR>(Buffer), Chunk,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (Status != 0)
      return false;
    Buffer += Chunk;
    Size -= Chunk;
  }
  return true;
}
#else
inline bool fillFromOs(std::uint8_t *Buffer, std::size_t Size) {
  int Flags = O_RDONLY;
#ifdef O_CLOEXEC
  Flags |= O_CLOEXEC;
#endif

  int FD;
  do {
    FD = ::open("/dev/urandom", Flags);
  } while (FD < 0 && errno == EINTR);
  if (FD < 0)
    return false;

  std::size_t Offset = 0;
  while (Offset < Size) {
    const ssize_t ReadCount = ::read(FD, Buffer + Offset, Size - Offset);
    if (ReadCount > 0) {
      Offset += static_cast<std::size_t>(ReadCount);
      continue;
    }
    if (ReadCount < 0 && errno == EINTR)
      continue;
    ::close(FD);
    return false;
  }

  return ::close(FD) == 0;
}
#endif

inline std::string loadBuildSeedHex() {
  if (const char *EnvironmentSeed = std::getenv("ALLVM_BUILD_SEED")) {
    std::string Seed(EnvironmentSeed);
    if (Seed.size() == 66 && Seed[0] == '0' &&
        (Seed[1] == 'x' || Seed[1] == 'X'))
      Seed.erase(0, 2);

    if (Seed.size() != 64 || !isHexString(Seed))
      report_fatal_error(
          "ALLVM_BUILD_SEED must contain exactly 64 hexadecimal characters");
    return Seed;
  }

  std::array<std::uint8_t, 32> RandomBytes{};
  if (!fillFromOs(RandomBytes.data(), RandomBytes.size()))
    report_fatal_error("ALLVM could not obtain entropy from the operating system");

  std::string Seed = hexEncode(RandomBytes.data(), RandomBytes.size());
  secureZero(RandomBytes.data(), RandomBytes.size());
  return Seed;
}

inline const std::string &buildSeedHex() {
  static const std::string Seed = loadBuildSeedHex();
  return Seed;
}

} // namespace detail

inline void seedCryptoUtils(CryptoUtils &Engine, const char *Domain) {
  std::string Material("ALLVM-build-seed-v1|");
  Material += detail::buildSeedHex();
  Material += '|';
  Material += (Domain != nullptr && *Domain != '\0') ? Domain : "default";

  std::array<unsigned char, 32> Digest{};
  if (Engine.sha256(Material.c_str(), Digest.data()) != 0)
    report_fatal_error("ALLVM failed to derive a pass-specific random seed");

  std::string DerivedSeed = detail::hexEncode(Digest.data(), 16);
  detail::secureZero(Digest.data(), Digest.size());
  detail::secureZero(&Material[0], Material.size());

  Engine.prng_seed(DerivedSeed);
  detail::secureZero(&DerivedSeed[0], DerivedSeed.size());
}

} // namespace allvm
} // namespace llvm

#endif // LLVM_TRANSFORMS_OBFUSCATION_SECURERANDOM_H
