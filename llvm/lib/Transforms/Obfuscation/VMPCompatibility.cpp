//===- VMPCompatibility.cpp - legacy VMP preflight ----------------------===//
//
// Rejects IR that the current uint64-based VMP interpreter cannot preserve.
// This analysis intentionally prefers a clear skip report over silently
// dropping an instruction and emitting a semantically different program.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/VMPCompatibility.h"
#include "../../../../aVMPInterpreter/VMPIntegrity.h"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/TypeSize.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>

using namespace llvm;

namespace llvm {
namespace allvm {
namespace {

void reject(VMPCompatibilityResult &Result, const Twine &Reason) {
  Result.Supported = false;
  const std::string Text = Reason.str();
  if (std::find(Result.Reasons.begin(), Result.Reasons.end(), Text) ==
          Result.Reasons.end() &&
      Result.Reasons.size() < 16)
    Result.Reasons.push_back(Text);
}

bool checkedAdd(uint64_t &Total, uint64_t Value) {
  if (Value > std::numeric_limits<uint64_t>::max() - Total)
    return false;
  Total += Value;
  return true;
}

bool checkedMultiply(uint64_t Left, uint64_t Right, uint64_t &Product) {
  if (Left != 0 && Right > std::numeric_limits<uint64_t>::max() / Left)
    return false;
  Product = Left * Right;
  return true;
}

bool alignTo(uint64_t &Value, uint64_t Alignment) {
  if (Alignment <= 1)
    return true;
  const uint64_t Remainder = Value % Alignment;
  return Remainder == 0 || checkedAdd(Value, Alignment - Remainder);
}

bool fixedAllocSize(const DataLayout &DL, Type *Ty, uint64_t &Size) {
  if (Ty == nullptr || !Ty->isSized())
    return false;
  const TypeSize AllocSize = DL.getTypeAllocSize(Ty);
  if (AllocSize.isScalable())
    return false;
  Size = AllocSize.getFixedValue();
  return true;
}

bool supportedValueType(const DataLayout &DL, Type *Ty, std::string &Reason) {
  if (Ty == nullptr) {
    Reason = "空 LLVM 类型";
    return false;
  }
  if (Ty->isVoidTy())
    return true;
  if (auto *PointerTy = dyn_cast<PointerType>(Ty)) {
    if (PointerTy->getAddressSpace() != 0) {
      Reason = "非零地址空间指针";
      return false;
    }
    if (DL.getPointerSize(PointerTy->getAddressSpace()) > 8) {
      Reason = "超过 64 位的指针";
      return false;
    }
    return true;
  }
  if (auto *IntegerTy = dyn_cast<IntegerType>(Ty)) {
    if (IntegerTy->getBitWidth() == 0 || IntegerTy->getBitWidth() > 64) {
      Reason = "超过 64 位的整数";
      return false;
    }
    return true;
  }
  if (Ty->isFloatTy() || Ty->isDoubleTy())
    return true;

  if (Ty->isVectorTy())
    Reason = "向量或可伸缩向量值";
  else if (Ty->isAggregateType())
    Reason = "无法放入 uint64 VMP ABI 的聚合值";
  else if (Ty->isTokenTy())
    Reason = "token 值";
  else if (Ty->isMetadataTy())
    Reason = "metadata 值";
  else
    Reason = "当前解释器不支持的值类型";
  return false;
}

bool ignoredIntrinsic(const Instruction &I) {
  return isa<DbgInfoIntrinsic>(&I) || isa<LifetimeIntrinsic>(&I);
}

bool supportedBinaryOpcode(unsigned Opcode) {
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

bool supportedCastOpcode(unsigned Opcode) {
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

bool supportedICmpPredicate(CmpInst::Predicate Predicate) {
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

bool isZeroIndex(const Value *Index) {
  const auto *CI = dyn_cast<ConstantInt>(Index);
  return CI != nullptr && CI->isZero();
}

template <typename GEPTy>
bool checkSimpleGEP(const DataLayout &DL, const GEPTy &GEP,
                    std::string &Reason) {
  SmallVector<const Value *, 4> Indices;
  for (auto It = GEP.idx_begin(); It != GEP.idx_end(); ++It)
    Indices.push_back(*It);

  if (GEP.getPointerAddressSpace() != 0) {
    Reason = "GEP 使用非零地址空间";
    return false;
  }

  Type *SourceTy = GEP.getSourceElementType();
  if (auto *StructTy = dyn_cast<StructType>(SourceTy)) {
    if (StructTy->isOpaque()) {
      Reason = "GEP 指向 opaque 结构体";
      return false;
    }
    if (Indices.size() != 2 || !isZeroIndex(Indices[0])) {
      Reason = "结构体 GEP 必须是 {0, 常量字段} 两级索引";
      return false;
    }
    const auto *Field = dyn_cast<ConstantInt>(Indices[1]);
    if (Field == nullptr || Field->isNegative() ||
        Field->getValue().getActiveBits() > 32) {
      Reason = "结构体字段索引不是小型非负常量";
      return false;
    }
    const uint64_t FieldIndex = Field->getZExtValue();
    if (FieldIndex >= StructTy->getNumElements()) {
      Reason = "结构体字段索引越界";
      return false;
    }
    (void)DL.getStructLayout(StructTy)->getElementOffset(FieldIndex);
    return true;
  }

  if (isa<ArrayType>(SourceTy)) {
    if (Indices.size() != 2 || !isZeroIndex(Indices[0])) {
      Reason = "数组 GEP 必须是 {0, index} 两级索引";
      return false;
    }
  } else if (Indices.size() != 1) {
    Reason = "标量 GEP 必须只有一个索引";
    return false;
  }

  Type *ElementTy = GEP.getResultElementType();
  uint64_t ElementSize = 0;
  if (!fixedAllocSize(DL, ElementTy, ElementSize) || ElementSize == 0 ||
      ElementSize > 255) {
    Reason = "GEP 元素大小不是 1..255 字节的固定值";
    return false;
  }
  return true;
}

bool hasNestedConstantExpr(const ConstantExpr &CE) {
  for (const Use &Operand : CE.operands())
    if (isa<ConstantExpr>(Operand.get()))
      return true;
  return false;
}

bool supportedConstant(const DataLayout &DL, const Constant &C,
                       std::string &Reason);

bool supportedConstantExpr(const DataLayout &DL, const ConstantExpr &CE,
                           std::string &Reason) {
  if (hasNestedConstantExpr(CE)) {
    Reason = "嵌套 ConstantExpr 需要递归 lowering";
    return false;
  }

  std::string TypeReason;
  if (!supportedValueType(DL, CE.getType(), TypeReason)) {
    Reason = "ConstantExpr 结果使用" + TypeReason;
    return false;
  }

  if (const auto *GEP = dyn_cast<GEPOperator>(&CE)) {
    if (!checkSimpleGEP(DL, *GEP, Reason))
      return false;
  } else if (!supportedCastOpcode(CE.getOpcode()) &&
             !supportedBinaryOpcode(CE.getOpcode())) {
    Reason = "不支持的 ConstantExpr opcode";
    return false;
  }

  for (const Use &Operand : CE.operands()) {
    const auto *ConstantOperand = dyn_cast<Constant>(Operand.get());
    if (ConstantOperand == nullptr) {
      Reason = "ConstantExpr 包含非常量操作数";
      return false;
    }
    if (!supportedConstant(DL, *ConstantOperand, Reason))
      return false;
  }
  return true;
}

bool supportedConstant(const DataLayout &DL, const Constant &C,
                       std::string &Reason) {
  if (isa<GlobalVariable>(&C))
    return true;
  if (isa<GlobalValue>(&C)) {
    Reason = "函数、别名或其他 GlobalValue 被当作普通值";
    return false;
  }
  if (const auto *CE = dyn_cast<ConstantExpr>(&C))
    return supportedConstantExpr(DL, *CE, Reason);
  if (const auto *CI = dyn_cast<ConstantInt>(&C)) {
    if (CI->getBitWidth() <= 64)
      return true;
    Reason = "超过 64 位的整数常量";
    return false;
  }
  if (const auto *CFP = dyn_cast<ConstantFP>(&C)) {
    if (CFP->getType()->isFloatTy() || CFP->getType()->isDoubleTy())
      return true;
    Reason = "不是 float/double 的浮点常量";
    return false;
  }
  if (isa<ConstantPointerNull>(&C))
    return true;
  if (isa<UndefValue>(&C) || isa<PoisonValue>(&C)) {
    Reason = "undef/poison 值不能在 VMP 中稳定具体化";
    return false;
  }

  Reason = "当前 pack_const_value 不支持的常量种类";
  return false;
}

void collectGlobalVariables(const Value *V,
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

void checkValue(VMPCompatibilityResult &Result, const DataLayout &DL,
                const Value *V, StringRef Context) {
  if (V == nullptr || isa<BasicBlock>(V))
    return;

  std::string TypeReason;
  if (!supportedValueType(DL, V->getType(), TypeReason)) {
    reject(Result, Twine(Context) + "使用" + TypeReason);
    return;
  }

  if (const auto *C = dyn_cast<Constant>(V)) {
    std::string ConstantReason;
    if (!supportedConstant(DL, *C, ConstantReason))
      reject(Result, Twine(Context) + "使用" + ConstantReason);
    if (isa<ConstantExpr>(C))
      ++Result.ConstantExpressionCount;
  }
}

bool reserveData(VMPCompatibilityResult &Result, const DataLayout &DL, Type *Ty,
                 uint64_t &DataBytes, StringRef Context) {
  uint64_t Size = 0;
  if (!fixedAllocSize(DL, Ty, Size)) {
    reject(Result, Twine(Context) + "大小不是固定值");
    return false;
  }
  const uint64_t Alignment = std::min<uint64_t>(DL.getABITypeAlign(Ty).value(), 16);
  if (!alignTo(DataBytes, std::max<uint64_t>(1, Alignment)) ||
      !checkedAdd(DataBytes, Size)) {
    reject(Result, Twine(Context) + "导致数据段大小溢出");
    return false;
  }
  return true;
}

bool unsupportedFunctionParamAttribute(const Function &F, unsigned Index) {
  return F.hasParamAttribute(Index, Attribute::ByVal) ||
         F.hasParamAttribute(Index, Attribute::StructRet) ||
         F.hasParamAttribute(Index, Attribute::InAlloca) ||
         F.hasParamAttribute(Index, Attribute::Preallocated);
}

bool unsupportedCallParamAttribute(const CallInst &Call, unsigned Index) {
  return Call.paramHasAttr(Index, Attribute::ByVal) ||
         Call.paramHasAttr(Index, Attribute::StructRet) ||
         Call.paramHasAttr(Index, Attribute::InAlloca) ||
         Call.paramHasAttr(Index, Attribute::Preallocated);
}

void addInstructionCodeEstimate(VMPCompatibilityResult &Result,
                                uint64_t Extra = 0) {
  if (!checkedAdd(Result.EstimatedCodeBytes, 128) ||
      !checkedAdd(Result.EstimatedCodeBytes, Extra))
    reject(Result, "VM 代码大小估算溢出");
}

void checkCast(VMPCompatibilityResult &Result, const DataLayout &DL,
               const CastInst &Cast) {
  if (!supportedCastOpcode(Cast.getOpcode())) {
    reject(Result, Twine("不支持的 cast opcode '") + Cast.getOpcodeName() + "'");
    return;
  }

  Type *SourceTy = Cast.getOperand(0)->getType();
  Type *DestinationTy = Cast.getType();
  if (Cast.getOpcode() == Instruction::Trunc ||
      Cast.getOpcode() == Instruction::ZExt) {
    if (!SourceTy->isIntegerTy() || !DestinationTy->isIntegerTy())
      reject(Result, "trunc/zext 的两端必须是整数");
    return;
  }
  if (Cast.getOpcode() == Instruction::BitCast) {
    uint64_t SourceSize = 0;
    uint64_t DestinationSize = 0;
    if (!fixedAllocSize(DL, SourceTy, SourceSize) ||
        !fixedAllocSize(DL, DestinationTy, DestinationSize) ||
        SourceSize != DestinationSize)
      reject(Result, "bitcast 两端必须具有相同固定大小");
    return;
  }
  if (Cast.getOpcode() == Instruction::PtrToInt &&
      (!SourceTy->isPointerTy() || !DestinationTy->isIntegerTy()))
    reject(Result, "ptrtoint 类型组合无效");
  if (Cast.getOpcode() == Instruction::IntToPtr &&
      (!SourceTy->isIntegerTy() || !DestinationTy->isPointerTy()))
    reject(Result, "inttoptr 类型组合无效");
}

} // namespace

VMPCompatibilityResult
analyzeVMPFunction(const Function &F, const VMPResourceLimits &Limits) {
  VMPCompatibilityResult Result;
  const Module *M = F.getParent();
  if (M == nullptr) {
    reject(Result, "函数未附加到 Module");
    return Result;
  }

  const DataLayout &DL = M->getDataLayout();
  const uint64_t PointerSize = DL.getPointerSize();

  if (F.isDeclaration() || F.empty())
    reject(Result, "函数没有可转换的定义体");
  if (F.isVarArg())
    reject(Result, "可变参数函数定义");
  if (F.hasPersonalityFn())
    reject(Result, "函数带有异常 personality");
  if (F.getCallingConv() != CallingConv::C)
    reject(Result, "函数使用非 C 调用约定");
  if (F.hasFnAttribute(Attribute::Naked))
    reject(Result, "naked 函数");
  if (F.hasFnAttribute(Attribute::ReturnsTwice))
    reject(Result, "returns_twice 函数");
  if (PointerSize != 8)
    reject(Result,
           "当前嵌入解释器的 uintptr_t ABI 仅支持 64 位目标");

  std::string TypeReason;
  if (!supportedValueType(DL, F.getReturnType(), TypeReason))
    reject(Result, Twine("返回类型使用") + TypeReason);

  unsigned ArgumentIndex = 0;
  for (const Argument &Arg : F.args()) {
    TypeReason.clear();
    if (!supportedValueType(DL, Arg.getType(), TypeReason))
      reject(Result, Twine("参数 '") + Arg.getName() + "' 使用" + TypeReason);
    if (unsupportedFunctionParamAttribute(F, ArgumentIndex))
      reject(Result, Twine("参数 '") + Arg.getName() +
                         "' 使用 byval/sret/inalloca/preallocated ABI 属性");
    ++ArgumentIndex;
  }

  uint64_t DataBytes = 0;
  if (!F.getReturnType()->isVoidTy())
    reserveData(Result, DL, F.getReturnType(), DataBytes, "返回值槽");
  for (const Argument &Arg : F.args())
    reserveData(Result, DL, Arg.getType(), DataBytes, "参数槽");
  DataBytes = std::max<uint64_t>(DataBytes, 16);
  if (!alignTo(DataBytes, std::max<uint64_t>(1, PointerSize)))
    reject(Result, "初始数据段对齐溢出");

  SmallPtrSet<const GlobalVariable *, 16> ReferencedGlobals;

  for (const BasicBlock &BB : F) {
    ++Result.BasicBlockCount;
    if (!checkedAdd(Result.EstimatedCodeBytes,
                    VMP_BLOCK_HEADER_SIZE))
      reject(Result, "基本块认证头导致代码大小溢出");

    for (const Instruction &I : BB) {
      ++Result.InstructionCount;

      if (ignoredIntrinsic(I))
        continue;

      for (const Use &Operand : I.operands())
        collectGlobalVariables(Operand.get(), ReferencedGlobals);

      if (const auto *Intrinsic = dyn_cast<IntrinsicInst>(&I)) {
        reject(Result, Twine("不支持的 LLVM intrinsic '") +
                           Intrinsic->getCalledFunction()->getName() + "'");
        continue;
      }

      if (const auto *AI = dyn_cast<AllocaInst>(&I)) {
        if (AI->getAddressSpace() != 0)
          reject(Result, "alloca 使用非零地址空间");
        const auto *Count = dyn_cast<ConstantInt>(AI->getArraySize());
        if (Count == nullptr || !Count->equalsInt(1))
          reject(Result, "动态或数组 alloca");
        uint64_t AllocatedSize = 0;
        if (!fixedAllocSize(DL, AI->getAllocatedType(), AllocatedSize))
          reject(Result, "alloca 使用 unsized 或 scalable 类型");
        if (DL.getABITypeAlign(AI->getAllocatedType()).value() > 16)
          reject(Result, "alloca 对齐超过当前 16 字节数据段基线");
        reserveData(Result, DL, AI->getType(), DataBytes, "alloca 指针槽");
        if (!alignTo(DataBytes, std::max<uint64_t>(1, DL.getABITypeAlign(
                                                        AI->getAllocatedType())
                                                        .value())) ||
            !checkedAdd(DataBytes, AllocatedSize))
          reject(Result, "alloca 区域导致数据段大小溢出");
        addInstructionCodeEstimate(Result);
        continue;
      }

      if (const auto *LI = dyn_cast<LoadInst>(&I)) {
        if (!LI->isSimple())
          reject(Result, "atomic 或 volatile load");
        checkValue(Result, DL, LI, "load 结果");
        checkValue(Result, DL, LI->getPointerOperand(), "load 指针");
        reserveData(Result, DL, LI->getType(), DataBytes, "load 结果槽");
        addInstructionCodeEstimate(Result);
        continue;
      }

      if (const auto *SI = dyn_cast<StoreInst>(&I)) {
        if (!SI->isSimple())
          reject(Result, "atomic 或 volatile store");
        checkValue(Result, DL, SI->getValueOperand(), "store 值");
        checkValue(Result, DL, SI->getPointerOperand(), "store 指针");
        addInstructionCodeEstimate(Result);
        continue;
      }

      if (const auto *BO = dyn_cast<BinaryOperator>(&I)) {
        if (!supportedBinaryOpcode(BO->getOpcode()))
          reject(Result, Twine("不支持的二元 opcode '") + BO->getOpcodeName() + "'");
        checkValue(Result, DL, BO, "二元结果");
        checkValue(Result, DL, BO->getOperand(0), "二元操作数");
        checkValue(Result, DL, BO->getOperand(1), "二元操作数");
        reserveData(Result, DL, BO->getType(), DataBytes, "二元结果槽");
        addInstructionCodeEstimate(Result);
        continue;
      }

      if (const auto *Cmp = dyn_cast<CmpInst>(&I)) {
        const auto *ICmp = dyn_cast<ICmpInst>(Cmp);
        if (ICmp == nullptr)
          reject(Result, "旧版解释器没有实现浮点比较");
        else if (!supportedICmpPredicate(ICmp->getPredicate()))
          reject(Result, "旧版解释器不能保持有符号或其他比较谓词语义");
        checkValue(Result, DL, Cmp, "比较结果");
        checkValue(Result, DL, Cmp->getOperand(0), "比较操作数");
        checkValue(Result, DL, Cmp->getOperand(1), "比较操作数");
        reserveData(Result, DL, Cmp->getType(), DataBytes, "比较结果槽");
        addInstructionCodeEstimate(Result);
        continue;
      }

      if (const auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
        std::string GEPReason;
        if (!checkSimpleGEP(DL, *GEP, GEPReason))
          reject(Result, Twine("不支持的 GEP：") + GEPReason);
        checkValue(Result, DL, GEP, "GEP 结果");
        checkValue(Result, DL, GEP->getPointerOperand(), "GEP 基址");
        for (auto It = GEP->idx_begin(); It != GEP->idx_end(); ++It)
          checkValue(Result, DL, *It, "GEP 索引");
        reserveData(Result, DL, GEP->getType(), DataBytes, "GEP 结果槽");
        addInstructionCodeEstimate(Result);
        continue;
      }

      if (const auto *Cast = dyn_cast<CastInst>(&I)) {
        checkCast(Result, DL, *Cast);
        checkValue(Result, DL, Cast, "cast 结果");
        checkValue(Result, DL, Cast->getOperand(0), "cast 操作数");
        reserveData(Result, DL, Cast->getType(), DataBytes, "cast 结果槽");
        addInstructionCodeEstimate(Result);
        continue;
      }

      if (const auto *Branch = dyn_cast<BranchInst>(&I)) {
        if (Branch->isConditional())
          checkValue(Result, DL, Branch->getCondition(), "分支条件");
        addInstructionCodeEstimate(Result);
        continue;
      }

      if (const auto *Ret = dyn_cast<ReturnInst>(&I)) {
        if (Ret->getReturnValue() != nullptr)
          checkValue(Result, DL, Ret->getReturnValue(), "返回值");
        addInstructionCodeEstimate(Result);
        continue;
      }

      if (const auto *Call = dyn_cast<CallInst>(&I)) {
        if (Call->isInlineAsm())
          reject(Result, "inline assembly 调用");
        if (Call->isMustTailCall())
          reject(Result, "musttail 调用");
        if (Call->hasOperandBundles())
          reject(Result, "带 operand bundle 的调用");
        if (Call->getCallingConv() != CallingConv::C)
          reject(Result, "使用非 C 调用约定的调用");
        if (Call->getFunctionType()->isVarArg())
          reject(Result, "可变参数调用不受旧版 VM ABI 支持");
        if (Call->hasFnAttr(Attribute::ReturnsTwice))
          reject(Result, "returns_twice 调用");
        if (Call->getCalledFunction() == &F)
          reject(Result, "直接递归会复用同一全局 VM 状态");
        for (unsigned Index = 0; Index < Call->arg_size(); ++Index) {
          if (unsupportedCallParamAttribute(*Call, Index))
            reject(Result, "调用参数使用 byval/sret/inalloca/preallocated ABI 属性");
          checkValue(Result, DL, Call->getArgOperand(Index), "调用参数");
        }
        if (Call->isIndirectCall()) {
          const Value *CalledOperand = Call->getCalledOperand();
          checkValue(Result, DL, CalledOperand, "间接调用目标");
          if (isa<Constant>(CalledOperand))
            reject(Result, "常量形式的间接调用目标无法可靠映射到 VM 数据槽");
        }
        if (!Call->getType()->isVoidTy()) {
          checkValue(Result, DL, Call, "调用结果");
          reserveData(Result, DL, Call->getType(), DataBytes, "调用结果槽");
        }
        addInstructionCodeEstimate(Result);
        continue;
      }

      if (const auto *Switch = dyn_cast<SwitchInst>(&I)) {
        checkValue(Result, DL, Switch->getCondition(), "switch 条件");
        const auto *ConditionTy = dyn_cast<IntegerType>(
            Switch->getCondition()->getType());
        if (ConditionTy == nullptr || ConditionTy->getBitWidth() > 64)
          reject(Result, "switch 条件不是至多 64 位整数");
        uint64_t CaseSize = 0;
        if (!fixedAllocSize(DL, Switch->getCondition()->getType(), CaseSize) ||
            CaseSize == 0 || CaseSize > 8)
          reject(Result, "switch case 值大小不在 1..8 字节范围");
        uint64_t Extra = 0;
        if (!checkedMultiply(Switch->getNumCases(), CaseSize + PointerSize,
                             Extra))
          reject(Result, "switch case 表大小溢出");
        addInstructionCodeEstimate(Result, Extra);
        continue;
      }

      if (isa<PHINode>(&I))
        reject(Result, "PHI 节点；应先运行保持语义的 PHI lowering");
      else if (isa<SelectInst>(&I))
        reject(Result, "select 指令");
      else if (isa<InvokeInst>(&I) || isa<CallBrInst>(&I) ||
               isa<IndirectBrInst>(&I))
        reject(Result, "invoke/callbr/indirectbr 控制流");
      else if (isa<LandingPadInst>(&I) || isa<ResumeInst>(&I) ||
               isa<CatchSwitchInst>(&I) || isa<CatchPadInst>(&I) ||
               isa<CleanupPadInst>(&I) || isa<CatchReturnInst>(&I) ||
               isa<CleanupReturnInst>(&I))
        reject(Result, "异常处理指令");
      else if (isa<AtomicCmpXchgInst>(&I) || isa<AtomicRMWInst>(&I) ||
               isa<FenceInst>(&I))
        reject(Result, "原子指令");
      else if (isa<VAArgInst>(&I))
        reject(Result, "va_arg 指令");
      else if (isa<ExtractValueInst>(&I) || isa<InsertValueInst>(&I))
        reject(Result, "聚合 extract/insert 指令");
      else if (isa<UnreachableInst>(&I))
        reject(Result, "旧版 VM 格式不能正确表示 unreachable terminator");
      else
        reject(Result, Twine("不支持的指令 '") + I.getOpcodeName() + "'");
    }
  }

  uint64_t GlobalBytes = 0;
  if (!checkedMultiply(ReferencedGlobals.size(), PointerSize, GlobalBytes) ||
      !checkedAdd(DataBytes, GlobalBytes))
    reject(Result, "全局变量数据槽估算溢出");

  uint64_t ConstantExprBytes = 0;
  if (!checkedMultiply(Result.ConstantExpressionCount,
                       std::max<uint64_t>(PointerSize, 8), ConstantExprBytes) ||
      !checkedAdd(DataBytes, ConstantExprBytes))
    reject(Result, "ConstantExpr 数据槽估算溢出");
  if (!checkedMultiply(Result.ConstantExpressionCount, 128,
                       ConstantExprBytes) ||
      !checkedAdd(Result.EstimatedCodeBytes, ConstantExprBytes))
    reject(Result, "ConstantExpr 代码估算溢出");

  Result.EstimatedDataBytes = DataBytes;

  if (Limits.MaxBasicBlocks != 0 &&
      Result.BasicBlockCount > Limits.MaxBasicBlocks)
    reject(Result, Twine("基本块数量 ") + Twine(Result.BasicBlockCount) +
                       " 超过限制 " + Twine(Limits.MaxBasicBlocks));
  if (Limits.MaxInstructions != 0 &&
      Result.InstructionCount > Limits.MaxInstructions)
    reject(Result, Twine("指令数量 ") + Twine(Result.InstructionCount) +
                       " 超过限制 " + Twine(Limits.MaxInstructions));
  if (Limits.MaxCodeBytes != 0 &&
      Result.EstimatedCodeBytes > Limits.MaxCodeBytes)
    reject(Result, Twine("估算 VM 代码大小 ") +
                       Twine(Result.EstimatedCodeBytes) + " 超过限制 " +
                       Twine(Limits.MaxCodeBytes));
  if (Limits.MaxDataBytes != 0 && DataBytes > Limits.MaxDataBytes)
    reject(Result, Twine("估算 VM 数据大小 ") + Twine(DataBytes) +
                       " 超过限制 " + Twine(Limits.MaxDataBytes));
  if (DataBytes > static_cast<uint64_t>(std::numeric_limits<int>::max()))
    reject(Result, "估算数据段超过 translator 的 signed-int offset 范围");
  if (Result.EstimatedCodeBytes >
      static_cast<uint64_t>(std::numeric_limits<int>::max()))
    reject(Result, "估算代码段超过 translator 的 signed-int branch 范围");

  return Result;
}

} // namespace allvm
} // namespace llvm
