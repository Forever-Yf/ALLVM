//===- VMPCompatibility.h - legacy VMP preflight -------------*- C++ -*-===//
//
// Conservative, non-mutating capability and resource analysis for the legacy
// ALLVM VMP translator. Unsupported IR is rejected before the translator
// creates helper functions or rewrites a protected function.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_OBFUSCATION_VMPCOMPATIBILITY_H
#define LLVM_TRANSFORMS_OBFUSCATION_VMPCOMPATIBILITY_H

#include "llvm/ADT/SmallVector.h"

#include <cstdint>
#include <string>

namespace llvm {
class Function;

namespace allvm {

struct VMPResourceLimits {
  uint64_t MaxBasicBlocks = 4096;
  uint64_t MaxInstructions = 50000;
  uint64_t MaxCodeBytes = 16ULL * 1024ULL * 1024ULL;
  uint64_t MaxDataBytes = 16ULL * 1024ULL * 1024ULL;
};

struct VMPCompatibilityResult {
  bool Supported = true;
  uint64_t BasicBlockCount = 0;
  uint64_t InstructionCount = 0;
  uint64_t ConstantExpressionCount = 0;
  uint64_t EstimatedCodeBytes = 0;
  uint64_t EstimatedDataBytes = 0;
  SmallVector<std::string, 8> Reasons;
};

VMPCompatibilityResult
analyzeVMPFunction(const Function &F, const VMPResourceLimits &Limits = {});

} // namespace allvm
} // namespace llvm

#endif // LLVM_TRANSFORMS_OBFUSCATION_VMPCOMPATIBILITY_H
