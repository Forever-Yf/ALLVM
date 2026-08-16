#!/usr/bin/env python3
"""Apply exact, one-time P0 hardening edits to large legacy source files.

This helper intentionally requires every original block to match exactly. It is
removed by the companion workflow after a successful patch, so it cannot drift
into a general-purpose source rewriter.
"""

from __future__ import annotations

from pathlib import Path


def replace_once(path_text: str, old: str, new: str) -> None:
    path = Path(path_text)
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"expected exactly one match in {path_text}, found {count}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")


def patch_crypto_utils() -> None:
    path = "llvm/lib/Transforms/Obfuscation/CryptoUtils.cpp"

    replace_once(
        path,
        '''#include "llvm/CryptoUtils.h"

#include <string>
#include <cstdlib>
#include <cassert>
#include <cstring>

#ifdef _WIN32
#include <random>
#include <chrono>
#else
#include <fstream>
#endif''',
        '''#include "llvm/CryptoUtils.h"
#include "llvm/Transforms/Obfuscation/SecureRandom.h"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <string>''',
    )

    replace_once(
        path,
        '''void CryptoUtils::prng_seed(const std::string _seed) {
  unsigned char s[16];
  unsigned int i = 0;

  if (!(_seed.size() == 32 || _seed.size() == 34)) {
    errs() <<
        Twine("The AES-CTR PRNG seeding mechanism is expecting a 16-byte value "
              "expressed in hexadecimal, like DEAD....BEEF") << "\\n";
  }

  seed = _seed;

  if (_seed.size() == 34) {
    i = 2;
  }

  for (; i < _seed.length(); i += 2) {
    std::string byte = _seed.substr(i, 2);
    s[i >> 1] = (unsigned char)(int)strtol(byte.c_str(), NULL, 16);
  }

  memcpy(key, s, 16);
  DEBUG_WITH_TYPE("cryptoutils", dbgs() << "CPNRG seeded with " << _seed << "\\n");

  memset(ctr, 0, 16);

  aes_compute_ks(ks, key);

  seeded = true;

  populate_pool();
}''',
        '''void CryptoUtils::prng_seed(const std::string _seed) {
  std::string HexSeed = _seed;
  if (HexSeed.size() == 34 && HexSeed[0] == '0' &&
      (HexSeed[1] == 'x' || HexSeed[1] == 'X')) {
    HexSeed.erase(0, 2);
  }

  if (HexSeed.size() != 32) {
    report_fatal_error(
        "The AES-CTR PRNG seed must contain exactly 32 hexadecimal characters");
  }

  auto DecodeNibble = [](char C) -> unsigned char {
    if (C >= '0' && C <= '9')
      return static_cast<unsigned char>(C - '0');
    if (C >= 'a' && C <= 'f')
      return static_cast<unsigned char>(C - 'a' + 10);
    if (C >= 'A' && C <= 'F')
      return static_cast<unsigned char>(C - 'A' + 10);
    report_fatal_error(
        "The AES-CTR PRNG seed contains a non-hexadecimal character");
  };

  unsigned char DecodedSeed[16] = {};
  for (std::size_t I = 0; I < sizeof(DecodedSeed); ++I) {
    DecodedSeed[I] = static_cast<unsigned char>(
        (DecodeNibble(HexSeed[I * 2]) << 4) |
        DecodeNibble(HexSeed[I * 2 + 1]));
  }

  memcpy(key, DecodedSeed, sizeof(key));
  allvm::secureClear(DecodedSeed, sizeof(DecodedSeed));
  seed.assign("explicit");
  DEBUG_WITH_TYPE(
      "cryptoutils",
      dbgs() << "CPRNG seeded from an explicit deterministic seed\\n");

  memset(ctr, 0, sizeof(ctr));
  aes_compute_ks(ks, key);
  seeded = true;
  populate_pool();
}''',
    )

    replace_once(
        path,
        '''CryptoUtils::~CryptoUtils() {
  memset(key, 0, 16);
  memset(ks, 0, 44 * sizeof(uint32_t));
  memset(ctr, 0, 16);
  memset(pool, 0, CryptoUtils_POOL_SIZE);

  idx = 0;
}''',
        '''CryptoUtils::~CryptoUtils() {
  allvm::secureClear(key, sizeof(key));
  allvm::secureClear(ks, sizeof(ks));
  allvm::secureClear(ctr, sizeof(ctr));
  allvm::secureClear(pool, sizeof(pool));
  allvm::secureClear(seed.data(), seed.size());
  seed.clear();

  idx = 0;
  seeded = false;
}''',
    )

    replace_once(
        path,
        '''void CryptoUtils::prng_seed() {
#ifdef _WIN32
  std::mt19937 mt(std::chrono::system_clock::now().time_since_epoch().count());
  for (size_t i = 0; i < 4; i++)
  {
    ((int*)key)[i] = mt();
  }
  memset(ctr, 0, 16);

  aes_compute_ks(ks, key);
  seeded = true;
#else
#if defined(__linux__)
  std::ifstream devrandom("/dev/urandom");
#else
  std::ifstream devrandom("/dev/random");
#endif

  if (devrandom) {

    devrandom.read(key, 16);

    if (devrandom.gcount() != 16) {
      errs() << Twine("Cannot read enough bytes in /dev/random") << "\\n";
    }

    devrandom.close();
    DEBUG_WITH_TYPE("cryptoutils", dbgs() << "cryptoutils seeded with /dev/random\\n");

    memset(ctr, 0, 16);

    aes_compute_ks(ks, key);

    seeded = true;
  } else {
    errs() << Twine("Cannot open /dev/random") << "\\n";
  }
#endif
}''',
        '''void CryptoUtils::prng_seed() {
  std::uint8_t SeedBytes[16] = {};
  if (!allvm::fillSecureRandom(SeedBytes, sizeof(SeedBytes))) {
    report_fatal_error(
        "CryptoUtils could not obtain entropy from the operating system");
  }

  memcpy(key, SeedBytes, sizeof(key));
  allvm::secureClear(SeedBytes, sizeof(SeedBytes));
  memset(ctr, 0, sizeof(ctr));
  aes_compute_ks(ks, key);
  seeded = true;

  DEBUG_WITH_TYPE(
      "cryptoutils",
      dbgs() << "CryptoUtils seeded from the operating-system CSPRNG\\n");
}''',
    )

    replace_once(
        path,
        '} while (sofar < (len - 1));',
        '} while (sofar < len);',
    )

    replace_once(
        path,
        '''uint32_t CryptoUtils::get_range(const uint32_t max) {
  uint32_t log, r, mask;

  statsGetRange++;

  if (max == 0) {
    return 0;
  } else {
    log = 32;
    int i = 0;
    while (!(max & masks[i++])) {
      log -= 1;
    }
    mask = (0x1UL << log) - 1;

    do {
      r = get_uint32_t() & mask;
    } while (r >= max);

    return r;
  }
}''',
        '''uint32_t CryptoUtils::get_range(const uint32_t max) {
  statsGetRange++;

  if (max == 0)
    return 0;

  // Rejection threshold avoids the previous shift-by-32 undefined behavior
  // while preserving a uniform distribution over [0, max).
  const uint32_t Threshold = static_cast<uint32_t>(-max) % max;
  uint32_t Value;
  do {
    Value = get_uint32_t();
  } while (Value < Threshold);

  return Value % max;
}''',
    )


def patch_legacy_vmp() -> None:
    path = "llvm/lib/Transforms/Obfuscation/aVMP.cpp"

    replace_once(
        path,
        '''#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/Support/CommandLine.h"''',
        '''#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/Transforms/Obfuscation/SecureRandom.h"
#include "llvm/Support/CommandLine.h"''',
    )

    replace_once(
        path,
        '''            this->pointer_size = modDataLayout->getPointerSize();  // 动态获取指针大小

            // construct function and global variables
            init();''',
        '''            this->pointer_size = modDataLayout->getPointerSize();  // 动态获取指针大小

            std::string RandomDomain = "legacy-vmp|";
            RandomDomain += this->Mod->getModuleIdentifier();
            RandomDomain += '|';
            RandomDomain += this->F->getName().str();
            allvm::seedCryptoUtils(RandomEngine, RandomDomain.c_str());

            // construct function and global variables
            init();''',
    )

    replace_once(
        path,
        '''        DataLayout * modDataLayout;
        unsigned pointer_size;  // 动态获取的指针大小,支持不同架构
''',
        '''        DataLayout * modDataLayout;
        unsigned pointer_size;  // 动态获取的指针大小,支持不同架构
        CryptoUtils RandomEngine;
''',
    )

    replace_once(
        path,
        '''        void init_xorshift32() {
            srand(time(0));
        }

        uint32_t gen_xorshift32_seed() {
            for (int _ = 0; _ < 10; _++) {
                xorshift32_seed ^= rand();
            }
            return xorshift32_seed;
        }''',
        '''        void init_xorshift32() {
            xorshift32_seed = gen_xorshift32_seed();
            xorshift32_state = xorshift32_seed;
        }

        uint32_t gen_xorshift32_seed() {
            uint32_t Seed = 0;
            do {
                Seed = RandomEngine.get_uint32_t();
            } while (Seed == 0);
            return Seed;
        }''',
    )


def verify() -> None:
    crypto = Path(
        "llvm/lib/Transforms/Obfuscation/CryptoUtils.cpp"
    ).read_text(encoding="utf-8")
    avmp = Path(
        "llvm/lib/Transforms/Obfuscation/aVMP.cpp"
    ).read_text(encoding="utf-8")

    for marker in (
        "fillSecureRandom",
        "secureClear",
        "explicit deterministic seed",
        "const uint32_t Threshold",
    ):
        if marker not in crypto:
            raise SystemExit(f"missing CryptoUtils marker: {marker}")

    for forbidden in ("std::mt19937", "std::chrono", "std::ifstream"):
        if forbidden in crypto:
            raise SystemExit(
                f"weak or obsolete CryptoUtils path remains: {forbidden}"
            )

    if "srand(time(0))" in avmp or "xorshift32_seed ^= rand()" in avmp:
        raise SystemExit("legacy VMP weak seed path remains")
    if "seedCryptoUtils(RandomEngine, RandomDomain.c_str())" not in avmp:
        raise SystemExit("legacy VMP domain-separated seed is missing")


def main() -> None:
    patch_crypto_utils()
    patch_legacy_vmp()
    verify()


if __name__ == "__main__":
    main()
