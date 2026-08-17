#ifndef LLVM_TRANSFORMS_OBFUSCATION_AUTHENTICATEDSTRINGIR_H
#define LLVM_TRANSFORMS_OBFUSCATION_AUTHENTICATEDSTRINGIR_H

namespace llvm {
class Function;
class Module;

namespace allvm {
Function *getOrCreateAuthenticatedStringOpen(Module &M);
}
} // namespace llvm

#endif
