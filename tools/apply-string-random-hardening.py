#!/usr/bin/env python3
"""Apply exact, reviewable random-lifecycle hardening to StringEncryption.cpp."""

from pathlib import Path


PATH = Path("llvm/lib/Transforms/Obfuscation/StringEncryption.cpp")


def replace_once(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match, found {count}: {old[:100]!r}")
    return text.replace(old, new)


def main() -> None:
    text = PATH.read_text(encoding="utf-8")

    text = replace_once(
        text,
        '''#include "llvm/Transforms/Obfuscation/StringEncryption.h"
#include "llvm/Transforms/Obfuscation/Utils.h"''',
        '''#include "llvm/Transforms/Obfuscation/StringEncryption.h"
#include "llvm/Transforms/Obfuscation/SecureRandom.h"
#include "llvm/Transforms/Obfuscation/Utils.h"''',
    )

    text = replace_once(
        text,
        '''#include <map>
#include <set>
#include <iostream>
#include <algorithm>''',
        '''#include <algorithm>
#include <iostream>
#include <map>
#include <set>
#include <type_traits>
#include <vector>''',
    )

    text = replace_once(
        text,
        '''		bool doFinalization(Module &) override {
			for (CSPEntry *Entry : ConstantStringPool) {
				delete (Entry);
			}''',
        '''		bool doFinalization(Module &) override {
			for (CSPEntry *Entry : ConstantStringPool) {
				allvm::secureClear(Entry->Data.data(), Entry->Data.size() * sizeof(uint8_t));
				allvm::secureClear(Entry->EncKey.data(), Entry->EncKey.size() * sizeof(uint8_t));
				allvm::secureClear(Entry->Data16.data(), Entry->Data16.size() * sizeof(uint16_t));
				allvm::secureClear(Entry->EncKey16.data(), Entry->EncKey16.size() * sizeof(uint16_t));
				delete (Entry);
			}''',
    )

    text = replace_once(
        text,
        '''bool StringEncryption::runOnModule(Module &M) {
	if (!isLicenseValidated()) return false;

	if (isIRObfuscationDebugEnabled()) {''',
        '''bool StringEncryption::runOnModule(Module &M) {
	if (!isLicenseValidated()) return false;

	std::string RandomDomain = "string-encryption|";
	RandomDomain += M.getModuleIdentifier();
	allvm::seedCryptoUtils(RandomEngine, RandomDomain.c_str());

	if (isIRObfuscationDebugEnabled()) {''',
    )

    text = replace_once(
        text,
        '''template <typename T>
void StringEncryption::getRandomBytes(std::vector<T> &Bytes, uint32_t MinSize, uint32_t MaxSize) {
	uint32_t N = RandomEngine.get_uint32_t();
	uint32_t Len;

	assert(MaxSize >= MinSize);

	if (MinSize == MaxSize) {
		Len = MinSize;
	} else {
		Len = MinSize + (N % (MaxSize - MinSize));
	}

	char *Buffer = new char[Len * sizeof(T)];
	RandomEngine.get_bytes(Buffer, Len * sizeof(T));
	for (uint32_t i = 0; i < Len; ++i) {
		if constexpr (std::is_same_v<T, uint8_t>) {
			Bytes.push_back(static_cast<uint8_t>(Buffer[i]));
		} else {
			uint8_t b0 = static_cast<uint8_t>(Buffer[i * 2]);
			uint8_t b1 = static_cast<uint8_t>(Buffer[i * 2 + 1]);
			// little-endian combine
			uint16_t w = static_cast<uint16_t>(b0 | (b1 << 8));
			Bytes.push_back(w);
		}
	}

	delete[] Buffer;
}''',
        '''template <typename T>
void StringEncryption::getRandomBytes(std::vector<T> &Bytes, uint32_t MinSize, uint32_t MaxSize) {
	static_assert(std::is_same_v<T, uint8_t> || std::is_same_v<T, uint16_t>,
	              "StringEncryption only supports byte and UTF-16 key material");
	assert(MaxSize >= MinSize);

	uint32_t Len = MinSize;
	if (MaxSize > MinSize) {
		const uint32_t Span = MaxSize - MinSize + 1;
		Len += RandomEngine.get_range(Span);
	}

	const size_t ByteCount = static_cast<size_t>(Len) * sizeof(T);
	std::vector<uint8_t> Buffer(ByteCount);
	if (!Buffer.empty()) {
		RandomEngine.get_bytes(reinterpret_cast<char *>(Buffer.data()),
		                       static_cast<int>(Buffer.size()));
	}

	Bytes.reserve(Bytes.size() + Len);
	for (uint32_t i = 0; i < Len; ++i) {
		if constexpr (std::is_same_v<T, uint8_t>) {
			Bytes.push_back(Buffer[i]);
		} else {
			const uint8_t b0 = Buffer[i * 2];
			const uint8_t b1 = Buffer[i * 2 + 1];
			const uint16_t w = static_cast<uint16_t>(
			    static_cast<uint16_t>(b0) |
			    (static_cast<uint16_t>(b1) << 8));
			Bytes.push_back(w);
		}
	}

	allvm::secureClear(Buffer.data(), Buffer.size());
}''',
    )

    required = (
        'RandomDomain = "string-encryption|"',
        "seedCryptoUtils(RandomEngine, RandomDomain.c_str())",
        "RandomEngine.get_range(Span)",
        "secureClear(Buffer.data(), Buffer.size())",
        "static_assert(std::is_same_v<T, uint8_t>",
    )
    for marker in required:
        if marker not in text:
            raise SystemExit(f"missing hardened string marker: {marker}")
    if "new char[Len * sizeof(T)]" in text or "delete[] Buffer" in text:
        raise SystemExit("raw temporary random buffer remains")

    PATH.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
