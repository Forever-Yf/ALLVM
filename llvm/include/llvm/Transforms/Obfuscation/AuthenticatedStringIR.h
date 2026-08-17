#ifndef LLVM_TRANSFORMS_OBFUSCATION_AUTHENTICATEDSTRINGIR_H
#define LLVM_TRANSFORMS_OBFUSCATION_AUTHENTICATEDSTRINGIR_H

#include "llvm/IR/IRBuilder.h"

namespace llvm {
class Function;
class Module;

namespace allvm {
Function *getOrCreateAuthenticatedStringOpen(Module &M);
}
} // namespace llvm

// AuthenticatedStringIR.cpp also accepts dynamic Value offsets, uint64_t
// constants, and integer literals. This exact unsigned overload prevents loop
// indexes and unsigned record-offset macros from becoming ambiguous with the
// Value * overload under older LLVM/Clang toolchains.
namespace {
inline llvm::Value *bytePtr(llvm::IRBuilder<> &B, llvm::Value *Base,
                            unsigned Offset) {
  return B.CreateInBoundsGEP(B.getInt8Ty(), Base, B.getInt64(Offset));
}
} // namespace

#endif
