#ifndef OBFUSCATION_STRING_ENCRYPTION_H
#define OBFUSCATION_STRING_ENCRYPTION_H

namespace llvm {
class ModulePass;
class PassRegistry;
class ObfuscationOptions;

ModulePass *createStringEncryptionPass(ObfuscationOptions *ArgsOptions);
void initializeAuthenticatedStringEncryptionPass(PassRegistry &Registry);

// Preserve the historical initializer name used by callers while the
// INITIALIZE_PASS definition follows the concrete authenticated pass class.
inline void initializeStringEncryptionPass(PassRegistry &Registry) {
  initializeAuthenticatedStringEncryptionPass(Registry);
}

} // namespace llvm

#endif
