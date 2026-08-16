//===- VMPCompatibility.h - legacy VMP preflight -------------*- C++ -*-===//
//
// Performs a conservative, non-mutating capability and resource analysis for
// the legacy ALLVM VMP translator.  The translator is intentionally limited to
// scalar values that fit in its uint64_t interpreter representation.  Rejecting
// unsupported IR before translation is safer than silently dropping an
// instruction and producing a semantically different binary.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_OBFUSCATION_VMPCOMPATIBILITY_H
#define LLVM_TRANSFORMS_OBFUSCATION_VMPCOMPATIBILITY_H

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/TypeSize.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>

namespace llvm {
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

  void reject(const Twine &Reason) {
    Supported = false;
    const std::string Text = Reason.str();
    if (std::find(Reasons.begin(), Reasons.end(), Text) == Reasons.end() &&
        Reasons.size() < 16)
      Reasons.push_back(Text);
  }
};

namespace vmp_detail {

inline bool checkedAdd(uint64_t &Total, uint64_t Value) {
  if (Value > std::numeric_limits<uint64_t>::max() - Total)
    return false;
  Total += Value;
  return true;
}

inline bool alignTo(uint64_t &Value, uint64_t Alignment) {
  if (Alignment <= 1)
    return true;
  const uint64_t Remainder = Value % Alignment;
  if (Remainder == 0)
    return true;
  return checkedAdd(Value, Alignment - Remainder);
}

inline bool fixedAllocSize(const DataLayout &DL, Type *Ty, uint64_t &Size) {
  if (Ty == nullptr || !Ty->isSized())
    return false;
  const TypeSize AllocSize = DL.getTypeAllocSize(Ty);
  if (AllocSize.isScalable())
    return false;
  Size = AllocSize.getFixedValue();
  return true;
}

inline bool isSupportedScalarType(const DataLayout &DL, Type *Ty,
                                  std::string &Reason) {
  if (Ty == nullptr) {
    Reason = "null LLVM type";
    return false;
  }
  if (Ty->isVoidTy())
    return true;
  if (Ty->isPointerTy()) {
    const auto *PtrTy = cast<PointerType>(Ty);
    if (PtrTy->getAddressSpace() != 0) {
      Reason = "non-zero pointer address space";
      return false;
    }
    if (DL.getPointerSize(PtrTy->getAddressSpace()) > 8) {
      Reason = "pointer width exceeds 64 bits";
      return false;
    }
    return true;
  }
  if (auto *IntTy = dyn_cast<IntegerType>(Ty)) {
    if (IntTy->getBitWidth() == 0 || IntTy->getBitWidth() > 64) {
      Reason = "integer width exceeds 64 bits";
      return false;
    }
    return true;
  }
  if (Ty->isFloatTy() || Ty->isDoubleTy())
    return true;

  if (Ty->isVectorTy())
    Reason = "vector or scalable-vector value";
  else if (Ty->isAggregateType())
    Reason = "aggregate value is not representable by the uint64 VMP ABI";
  else if (Ty->isTokenTy())
    Reason = "token value";
  else if (Ty->isMetadataTy())
    Reason = "metadata value";
  else
    Reason = "unsupported scalar type";
  return false;
}

inline bool isIgnoredIntrinsic(const Instruction &I) {
  return isa<DbgInfoIntrinsic>(&I) || isa<LifetimeIntrinsic>(&I) ||
         isa<AssumeInst>(&I);
}

inline bool isSupportedBinaryOpcode(unsigned Opcode) {
  switch (Opcode) {
  case Instruction::Add:
  case Instruction::FAdd:
  case Instruction::Sub:
  case Instruction::FSub:
  case Instruction::Mul:
  case Instruction::FMul:
  case Instruction::UDiv:
  case Instruction::FDiv:
  case Instruction::URem:
  case Instruction::Shl:
  case Instruction::LShr:
  case Instruction::And:
  case Instruction::Or:
  case Instruction::Xor:
    return true;
  default:
    return false;
  }
}

inline bool isSupportedCastOpcode(unsigned Opcode) {
  switch (Opcode) {
  case Instruction::Trunc:
  case Instruction::ZExt:
  case Instruction::BitCast:
  case Instruction::PtrToInt:
  case Instruction::IntToPtr:
    return true;
  default:
    return false;
  }
}

inline bool isSupportedICmpPredicate(CmpInst::Predicate Predicate) {
  switch (Predicate) {
  case CmpInst::ICMP_EQ:
  case CmpInst::ICMP_NE:
  case CmpInst::ICMP_UGT:
  case CmpInst::ICMP_UGE:
  case CmpInst::ICMP_ULT:
  case CmpInst::ICMP_ULE:
    return true;
  default:
    return false;
  }
}

inline bool isZeroIndex(Value *Index) {
  const auto *CI = dyn_cast<ConstantInt>(Index);
  return CI != nullptr && CI->isZero();
}

template <typename GEPTy>
inline bool checkSimpleGEP(const DataLayout &DL, const GEPTy &GEP,
                           std::string &Reason) {
  SmallVector<Value *, 4> Indices;
  for (auto It = GEP.idx_begin(); It != GEP.idx_end(); ++It)
    Indices.push_back(*It);

  Type *SourceTy = GEP.getSourceElementType();
  if (auto *StructTy = dyn_cast<StructType>(SourceTy)) {
    if (StructTy->isOpaque()) {
      Reason = "GEP into an opaque structure";
      return false;
    }
    if (Indices.size() != 2 || !isZeroIndex(Indices[0])) {
      Reason = "structure GEP must have exactly {0, constant-field} indices";
      return false;
    }
    const auto *Field = dyn_cast<ConstantInt>(Indices[1]);
    if (Field == nullptr || Field->getValue().getActiveBits() > 32) {
      Reason = "structure GEP field index is not a small constant";
      return false;
    }
    const uint64_t FieldIndex = Field->getZExtValue();
    if (FieldIndex >= StructTy->getNumElements()) {
      Reason = "structure GEP field index is out of range";
      return false;
    }
    (void)DL.getStructLayout(StructTy)->getElementOffset(FieldIndex);
    return true;
  }

  if (isa<ArrayType>(SourceTy)) {
    if (Indices.size() != 2 || !isZeroIndex(Indices[0])) {
      Reason = "array GEP must have exactly {0, index} indices";
      return false;
    }
  } else if (Indices.size() != 1) {
    Reason = "scalar GEP must have exactly one index";
    return false;
  }

  Type *ResultElementTy = GEP.getResultElementType();
  uint64_t ElementSize = 0;
  if (!fixedAllocSize(DL, ResultElementTy, ElementSize) ||
      ElementSize == 0 || ElementSize > 255) {
    Reason = "GEP element size is not a fixed value in 1..255 bytes";
    return false;
  }
  return true;
}

inline bool hasNestedConstantExpr(const ConstantExpr &CE) {
  for (const Use &Operand : CE.operands())
    if (isa<ConstantExpr>(Operand.get()))
      return true;
  return false;
}

inline bool isSupportedConstantExpr(const DataLayout &DL, const ConstantExpr &CE,
                                    std::string &Reason) {
  if (hasNestedConstantExpr(CE)) {
    Reason = "nested ConstantExpr requires recursive lowering";
    return false;
  }

  std::string TypeReason;
  if (!isSupportedScalarType(DL, CE.getType(), TypeReason)) {
    Reason = "ConstantExpr result uses " + TypeReason;
    return false;
  }

  if (const auto *GEP = dyn_cast<GEPOperator>(&CE))
    return checkSimpleGEP(DL, *GEP, Reason);
  if (CE.isCast()) {
    if (!isSupportedCastOpcode(CE.getOpcode())) {
      Reason = "unsupported ConstantExpr cast opcode";
      return false;
    }
    return true;
  }
  if (CE.isBinaryOp()) {
    if (!isSupportedBinaryOpcode(CE.getOpcode())) {
      Reason = "unsupported ConstantExpr binary opcode";
      return false;
    }
    return true;
  }

  Reason = "unsupported ConstantExpr opcode";
  return false;
}

inline bool isSupportedConstant(const DataLayout &DL, const Constant &C,
                                std::string &Reason) {
  if (isa<GlobalVariable>(&C))
    return true;
  if (isa<GlobalValue>(&C)) {
    Reason = "function, alias, or other GlobalValue used as a regular operand";
    return false;
  }
  if (const auto *CE = dyn_cast<ConstantExpr>(&C))
    return isSupportedConstantExpr(DL, *CE, Reason);
  if (const auto *CI = dyn_cast<ConstantInt>(&C)) {
    if (CI->getBitWidth() <= 64)
      return true;
    Reason = "integer constant wider than 64 bits";
    return false;
  }
  if (const auto *CFP = dyn_cast<ConstantFP>(&C)) {
    if (CFP->getType()->isFloatTy() || CFP->getType()->isDoubleTy())
      return true;
    Reason = "floating constant is not float or double";
    return false;
  }
  if (isa<ConstantPointerNull>(&C) || isa<UndefValue>(&C) ||
      isa<PoisonValue>(&C))
    return true;

  Reason = "unsupported constant kind";
  return false;
}

inline void collectGlobalVariables(const Value *V,
                                   SmallPtrSetImpl<const GlobalVariable *> &Out) {
  if (const auto *GV = dyn_cast<GlobalVariable>(V)) {
    Out.insert(GV);
    return;
  }
  const auto *C = dyn_cast<Constant>(V);
  if (C == nullptr || isa<GlobalValue>(C))
    return;
  for (const Use &Operand : C->operands())
    collectGlobalVariables(Operand.get(), Out);
}

inline uint64_t encodedValueUpperBound(const DataLayout &DL, Type *Ty) {
  uint64_t Size = 8;
  (void)fixedAllocSize(DL, Ty, Size);
  return 2 + std::max<uint64_t>(DL.getPointerSize(), std::min<uint64_t>(Size, 8));
}

inline bool addDataSlot(uint64_t &DataBytes, const DataLayout &DL, Type *Ty,
                        uint64_t PointerSize) {
  uint64_t Size = 0;
  if (!fixedAllocSize(DL, Ty, Size))
    return false;
  if (!alignTo(DataBytes, std::max<uint64_t>(1, std::min<uint64_t>(PointerSize, 8))))
    return false;
  return checkedAdd(DataBytes, Size);
}

inline bool addCode(uint64_t &CodeBytes, uint64_t Amount) {
  return checkedAdd(CodeBytes, Amount);
}

inline void rejectUnsupportedValue(VMPCompatibilityResult &Result,
                                   const DataLayout &DL, const Value *V,
                                   StringRef Context) {
  if (V == nullptr || isa<BasicBlock>(V))
    return;

  std::string TypeReason;
  if (!isSupportedScalarType(DL, V->getType(), TypeReason)) {
    Result.reject(Context + " uses " + TypeReason);
    return;
  }

  if (const auto *C = dyn_cast<Constant>(V)) {
    std::string ConstantReason;
    if (!isSupportedConstant(DL, *C, ConstantReason))
      Result.reject(Context + " uses " + ConstantReason);
    if (isa<ConstantExpr>(C))
      ++Result.ConstantExpressionCount;
  }
}

inline bool hasUnsupportedCallAttributes(const CallInst &Call) {
  const AttributeList Attrs = Call.getAttributes();
  for (unsigned I = 0; I < Call.arg_size(); ++I) {
    if (Attrs.hasParamAttr(I, Attribute::ByVal) ||
        Attrs.hasParamAttr(I, Attribute::StructRet) ||
        Attrs.hasParamAttr(I, Attribute::InAlloca) ||
        Attrs.hasParamAttr(I, Attribute::Preallocated) ||
        Attrs.hasParamAttr(I, Attribute::SwiftSelf) ||
        Attrs.hasParamAttr(I, Attribute::SwiftError) ||
        Attrs.hasParamAttr(I, Attribute::Nest))
      return true;
  }
  return false;
}

} // namespace vmp_detail

inline VMPCompatibilityResult
analyzeVMPFunction(const Function &F, const VMPResourceLimits &Limits) {
  using namespace vmp_detail;

  VMPCompatibilityResult Result;
  const Module *M = F.getParent();
  if (M == nullptr) {
    Result.reject("function is not attached to a module");
    return Result;
  }
  const DataLayout &DL = M->getDataLayout();
  const uint64_t PointerSize = DL.getPointerSize();

  if (F.isDeclaration() || F.empty())
    Result.reject("function has no body");
  if (F.isVarArg())
    Result.reject("variadic function definition");
  if (F.hasPersonalityFn())
    Result.reject("function has an exception personality");
  if (F.getCallingConv() != CallingConv::C)
    Result.reject("non-C function calling convention");
  if (F.hasFnAttribute(Attribute::Naked))
    Result.reject("naked function");
  if (PointerSize == 0 || PointerSize > 8)
    Result.reject("target pointer width is not supported by the uint64 VMP ABI");

  std::string TypeReason;
  if (!isSupportedScalarType(DL, F.getReturnType(), TypeReason))
    Result.reject(Twine("return type uses ") + TypeReason);
  for (const Argument &Arg : F.args()) {
    TypeReason.clear();
    if (!isSupportedScalarType(DL, Arg.getType(), TypeReason))
      Result.reject(Twine("argument '") + Arg.getName() + "' uses " + TypeReason);
  }

  uint64_t DataBytes = 0;
  if (!F.getReturnType()->isVoidTy() &&
      !addDataSlot(DataBytes, DL, F.getReturnType(), PointerSize))
    Result.reject("return slot size overflow");
  for (const Argument &Arg : F.args())
    if (!addDataSlot(DataBytes, DL, Arg.getType(), PointerSize))
      Result.reject(Twine("argument slot size overflow for '") + Arg.getName() + "'");
  DataBytes = std::max<uint64_t>(DataBytes, 16);
  if (!alignTo(DataBytes, std::max<uint64_t>(1, PointerSize)))
    Result.reject("initial data segment alignment overflow");

  uint64_t CodeBytes = 0;
  SmallPtrSet<const GlobalVariable *, 16> ReferencedGlobals;

  for (const BasicBlock &BB : F) {
    ++Result.BasicBlockCount;
    if (!addCode(CodeBytes, 8))
      Result.reject("VM code size overflow while adding basic-block seeds");

    for (const Instruction &I : BB) {
      ++Result.InstructionCount;

      if (isIgnoredIntrinsic(I))
        continue;

      for (const Use &Operand : I.operands())
        collectGlobalVariables(Operand.get(), ReferencedGlobals);

      if (const auto *AI = dyn_cast<AllocaInst>(&I)) {
        const auto *Count = dyn_cast<ConstantInt>(AI->getArraySize());
        if (Count == nullptr || !Count->equalsInt(1))
          Result.reject(Twine("dynamic or array alloca in ") + F.getName());
        uint64_t AllocatedSize = 0;
        if (!fixedAllocSize(DL, AI->getAllocatedType(), AllocatedSize))
          Result.reject("alloca uses an unsized or scalable type");
        if (!addDataSlot(DataBytes, DL, AI->getType(), PointerSize) ||
            !alignTo(DataBytes, std::max<uint64_t>(1, PointerSize)) ||
            !checkedAdd(DataBytes, AllocatedSize) ||
            !alignTo(DataBytes, std::max<uint64_t>(1, PointerSize)))
          Result.reject("alloca data segment estimate overflow");
        if (!addCode(CodeBytes, 1 + encodedValueUpperBound(DL, AI->getType()) +
                                    PointerSize))
          Result.reject("alloca code estimate overflow");
        continue;
      }

      if (const auto *LI = dyn_cast<LoadInst>(&I)) {
        if (LI->isAtomic() || LI->isVolatile())
          Result.reject("atomic or volatile load");
        rejectUnsupportedValue(Result, DL, LI, "load result");
        rejectUnsupportedValue(Result, DL, LI->getPointerOperand(), "load pointer");
        if (!addDataSlot(DataBytes, DL, LI->getType(), PointerSize))
          Result.reject("load result slot estimate overflow");
        if (!addCode(CodeBytes, 1 + encodedValueUpperBound(DL, LI->getType()) +
                                    encodedValueUpperBound(DL, LI->getPointerOperandType())))
          Result.reject("load code estimate overflow");
        continue;
      }

      if (const auto *SI = dyn_cast<StoreInst>(&I)) {
        if (SI->isAtomic() || SI->isVolatile())
          Result.reject("atomic or volatile store");
        rejectUnsupportedValue(Result, DL, SI->getValueOperand(), "stored value");
        rejectUnsupportedValue(Result, DL, SI->getPointerOperand(), "store pointer");
        if (!addCode(CodeBytes, 1 + encodedValueUpperBound(DL, SI->getValueOperand()->getType()) +
                                    encodedValueUpperBound(DL, SI->getPointerOperandType())))
          Result.reject("store code estimate overflow");
        continue;
      }

      if (const auto *BO = dyn_cast<BinaryOperator>(&I)) {
        if (!isSupportedBinaryOpcode(BO->getOpcode()))
          Result.reject(Twine("unsupported binary opcode '") + BO->getOpcodeName() + "'");
        rejectUnsupportedValue(Result, DL, BO, "binary result");
        rejectUnsupportedValue(Result, DL, BO->getOperand(0), "binary operand");
        rejectUnsupportedValue(Result, DL, BO->getOperand(1), "binary operand");
        if (!addDataSlot(DataBytes, DL, BO->getType(), PointerSize))
          Result.reject("binary result slot estimate overflow");
        if (!addCode(CodeBytes, 2 + encodedValueUpperBound(DL, BO->getType()) +
                                    encodedValueUpperBound(DL, BO->getOperand(0)->getType()) +
                                    encodedValueUpperBound(DL, BO->getOperand(1)->getType())))
          Result.reject("binary code estimate overflow");
        continue;
      }

      if (const auto *Cmp = dyn_cast<CmpInst>(&I)) {
        const auto *ICmp = dyn_cast<ICmpInst>(Cmp);
        if (ICmp == nullptr)
          Result.reject("floating-point comparison is not implemented by the legacy interpreter");
        else if (!isSupportedICmpPredicate(ICmp->getPredicate()))
          Result.reject("signed or otherwise unsupported integer comparison predicate");
        rejectUnsupportedValue(Result, DL, Cmp, "comparison result");
        rejectUnsupportedValue(Result, DL, Cmp->getOperand(0), "comparison operand");
        rejectUnsupportedValue(Result, DL, Cmp->getOperand(1), "comparison operand");
        if (!addDataSlot(DataBytes, DL, Cmp->getType(), PointerSize))
          Result.reject("comparison result slot estimate overflow");
        if (!addCode(CodeBytes, 2 + encodedValueUpperBound(DL, Cmp->getType()) +
                                    encodedValueUpperBound(DL, Cmp->getOperand(0)->getType()) +
                                    encodedValueUpperBound(DL, Cmp->getOperand(1)->getType())))
          Result.reject("comparison code estimate overflow");
        continue;
      }

      if (const auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
        std::string GEPReason;
        if (!checkSimpleGEP(DL, *GEP, GEPReason))
          Result.reject(Twine("unsupported GEP: ") + GEPReason);
        rejectUnsupportedValue(Result, DL, GEP, "GEP result");
        rejectUnsupportedValue(Result, DL, GEP->getPointerOperand(), "GEP base");
        for (Value *Index : GEP->indices())
          rejectUnsupportedValue(Result, DL, Index, "GEP index");
        if (!addDataSlot(DataBytes, DL, GEP->getType(), PointerSize))
          Result.reject("GEP result slot estimate overflow");
        if (!addCode(CodeBytes, 3 + encodedValueUpperBound(DL, GEP->getType()) +
                                    encodedValueUpperBound(DL, GEP->getPointerOperandType()) +
                                    2 * (2 + std::max<uint64_t>(PointerSize, 8))))
          Result.reject("GEP code estimate overflow");
        continue;
      }

      if (const auto *Cast = dyn_cast<CastInst>(&I)) {
        if (!isSupportedCastOpcode(Cast->getOpcode()))
          Result.reject(Twine("unsupported cast opcode '") + Cast->getOpcodeName() + "'");
        rejectUnsupportedValue(Result, DL, Cast, "cast result");
        rejectUnsupportedValue(Result, DL, Cast->getOperand(0), "cast operand");
        if (!addDataSlot(DataBytes, DL, Cast->getType(), PointerSize))
          Result.reject("cast result slot estimate overflow");
        if (!addCode(CodeBytes, 1 + encodedValueUpperBound(DL, Cast->getType()) +
                                    encodedValueUpperBound(DL, Cast->getOperand(0)->getType())))
          Result.reject("cast code estimate overflow");
        continue;
      }

      if (const auto *Branch = dyn_cast<BranchInst>(&I)) {
        if (Branch->isConditional())
          rejectUnsupportedValue(Result, DL, Branch->getCondition(), "branch condition");
        const uint64_t BranchBytes = Branch->isConditional()
                                         ? 2 + encodedValueUpperBound(
                                                   DL, Branch->getCondition()->getType()) +
                                               2 * PointerSize
                                         : 2 + PointerSize;
        if (!addCode(CodeBytes, BranchBytes))
          Result.reject("branch code estimate overflow");
        continue;
      }

      if (const auto *Ret = dyn_cast<ReturnInst>(&I)) {
        if (Ret->getReturnValue() != nullptr)
          rejectUnsupportedValue(Result, DL, Ret->getReturnValue(), "return value");
        if (!addCode(CodeBytes,
                     1 + (Ret->getReturnValue() != nullptr
                              ? encodedValueUpperBound(DL, Ret->getReturnValue()->getType())
                              : 2 + PointerSize)))
          Result.reject("return code estimate overflow");
        continue;
      }

      if (const auto *Call = dyn_cast<CallInst>(&I)) {
        if (Call->isInlineAsm())
          Result.reject("inline assembly call");
        if (Call->isMustTailCall())
          Result.reject("musttail call");
        if (Call->getNumOperandBundles() != 0)
          Result.reject("call with operand bundles");
        if (Call->getCallingConv() != CallingConv::C)
          Result.reject("call with non-C calling convention");
        if (hasUnsupportedCallAttributes(*Call))
          Result.reject("call uses byval/sret/inalloca or another unsupported ABI attribute");
        if (!Call->getType()->isVoidTy()) {
          rejectUnsupportedValue(Result, DL, Call, "call result");
          if (!addDataSlot(DataBytes, DL, Call->getType(), PointerSize))
            Result.reject("call result slot estimate overflow");
        }
        for (const Use &Arg : Call->args())
          rejectUnsupportedValue(Result, DL, Arg.get(), "call argument");
        if (!addCode(CodeBytes, 1 + PointerSize))
          Result.reject("call code estimate overflow");
        continue;
      }

      if (const auto *Switch = dyn_cast<SwitchInst>(&I)) {
        rejectUnsupportedValue(Result, DL, Switch->getCondition(), "switch condition");
        const auto *ConditionTy = dyn_cast<IntegerType>(Switch->getCondition()->getType());
        if (ConditionTy == nullptr || ConditionTy->getBitWidth() > 64)
          Result.reject("switch condition is not an integer of at most 64 bits");
        uint64_t CaseSize = 0;
        if (!fixedAllocSize(DL, Switch->getCondition()->getType(), CaseSize) ||
            CaseSize == 0 || CaseSize > 8)
          Result.reject("switch case value size is not in 1..8 bytes");
        uint64_t SwitchBytes = 1 + encodedValueUpperBound(
                                      DL, Switch->getCondition()->getType()) +
                               8 + PointerSize;
        const uint64_t PerCase = CaseSize + PointerSize;
        if (Switch->getNumCases() > 0 &&
            PerCase > (std::numeric_limits<uint64_t>::max() - SwitchBytes) /
                          Switch->getNumCases())
          Result.reject("switch code estimate overflow");
        else if (!addCode(SwitchBytes, PerCase * Switch->getNumCases()) ||
                 !addCode(CodeBytes, SwitchBytes))
          Result.reject("switch code estimate overflow");
        continue;
      }

      if (isa<PHINode>(&I))
        Result.reject("PHI node; run a semantics-preserving PHI lowering pass first");
      else if (isa<SelectInst>(&I))
        Result.reject("select instruction");
      else if (isa<InvokeInst>(&I) || isa<CallBrInst>(&I) ||
               isa<IndirectBrInst>(&I))
        Result.reject("invoke/callbr/indirectbr control flow");
      else if (isa<LandingPadInst>(&I) || isa<ResumeInst>(&I) ||
               isa<CatchSwitchInst>(&I) || isa<CatchPadInst>(&I) ||
               isa<CleanupPadInst>(&I) || isa<CatchReturnInst>(&I) ||
               isa<CleanupReturnInst>(&I))
        Result.reject("exception-handling instruction");
      else if (isa<AtomicCmpXchgInst>(&I) || isa<AtomicRMWInst>(&I) ||
               isa<FenceInst>(&I))
        Result.reject("atomic instruction");
      else if (isa<VAArgInst>(&I))
        Result.reject("va_arg instruction");
      else if (isa<ExtractValueInst>(&I) || isa<InsertValueInst>(&I))
        Result.reject("aggregate extract/insert instruction");
      else if (isa<UnreachableInst>(&I))
        Result.reject("unreachable terminator is not represented by the legacy VM format");
      else
        Result.reject(Twine("unsupported instruction '") + I.getOpcodeName() + "'");
    }
  }

  if (!checkedAdd(DataBytes, ReferencedGlobals.size() * PointerSize))
    Result.reject("global-variable slot estimate overflow");
  if (!checkedAdd(DataBytes,
                  Result.ConstantExpressionCount *
                      std::max<uint64_t>(PointerSize, 8)))
    Result.reject("ConstantExpr data estimate overflow");
  if (!checkedAdd(CodeBytes, Result.ConstantExpressionCount * 64))
    Result.reject("ConstantExpr code estimate overflow");

  Result.EstimatedCodeBytes = CodeBytes;
  Result.EstimatedDataBytes = DataBytes;

  if (Limits.MaxBasicBlocks != 0 &&
      Result.BasicBlockCount > Limits.MaxBasicBlocks)
    Result.reject(Twine("basic block count ") + Twine(Result.BasicBlockCount) +
                  " exceeds limit " + Twine(Limits.MaxBasicBlocks));
  if (Limits.MaxInstructions != 0 &&
      Result.InstructionCount > Limits.MaxInstructions)
    Result.reject(Twine("instruction count ") + Twine(Result.InstructionCount) +
                  " exceeds limit " + Twine(Limits.MaxInstructions));
  if (Limits.MaxCodeBytes != 0 && CodeBytes > Limits.MaxCodeBytes)
    Result.reject(Twine("estimated VM code bytes ") + Twine(CodeBytes) +
                  " exceeds limit " + Twine(Limits.MaxCodeBytes));
  if (Limits.MaxDataBytes != 0 && DataBytes > Limits.MaxDataBytes)
    Result.reject(Twine("estimated VM data bytes ") + Twine(DataBytes) +
                  " exceeds limit " + Twine(Limits.MaxDataBytes));
  if (DataBytes > static_cast<uint64_t>(std::numeric_limits<int>::max()))
    Result.reject("estimated VM data segment exceeds the translator's signed-int offset range");
  if (CodeBytes > static_cast<uint64_t>(std::numeric_limits<int>::max()))
    Result.reject("estimated VM code segment exceeds the translator's signed-int branch range");

  return Result;
}

} // namespace allvm
} // namespace llvm

#endif // LLVM_TRANSFORMS_OBFUSCATION_VMPCOMPATIBILITY_H
