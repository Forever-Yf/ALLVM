#ifndef LLVM_TRANSFORMS_OBFUSCATION_AUTHENTICATEDSTRINGIR_H
#define LLVM_TRANSFORMS_OBFUSCATION_AUTHENTICATEDSTRINGIR_H

#include "llvm/IR/IRBuilder.h"

#include <type_traits>

namespace llvm {
class Function;
class Module;

namespace allvm {
Function *getOrCreateAuthenticatedStringOpen(Module &M);
}
} // namespace llvm

// The retained record-v1 runtime accepts dynamic offsets, uint64_t constants,
// and int literals in its translation unit. This constrained template gives
// unsigned loop indexes an exact match without colliding with the explicit
// non-template unsigned overload used by the record-v2 runtime.
namespace {
template <typename T,
          std::enable_if_t<std::is_same_v<T, unsigned>, int> = 0>
inline llvm::Value *bytePtr(llvm::IRBuilder<> &B, llvm::Value *Base,
                            T Offset) {
  return B.CreateInBoundsGEP(B.getInt8Ty(), Base, B.getInt64(Offset));
}
} // namespace

#endif
