// Production string pass wrapper: expose record-v2 ChaCha20-Poly1305 aliases
// before compiling the canonical StringEncryption.cpp implementation.
#include "llvm/Transforms/Obfuscation/AuthenticatedStringPoly1305Crypto.h"
#include "StringEncryption.cpp"
