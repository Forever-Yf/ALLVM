//===- AuthenticatedStringPoly1305IR.cpp - RFC 8439 runtime IR ----------===//

#include "llvm/Transforms/Obfuscation/AuthenticatedStringIR.h"
#include "llvm/Transforms/Obfuscation/AuthenticatedStringPoly1305Crypto.h"

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <array>
#include <cstdint>

using namespace llvm;

namespace {

constexpr StringLiteral Load32Name("__allvm_str_load32_v2");
constexpr StringLiteral Store32Name("__allvm_str_store32_v2");
constexpr StringLiteral Load64Name("__allvm_str_load64_v2");
constexpr StringLiteral Store64Name("__allvm_str_store64_v2");
constexpr StringLiteral Load128Name("__allvm_str_load128_v2");
constexpr StringLiteral Store128Name("__allvm_str_store128_v2");
constexpr StringLiteral BlockName("__allvm_str_chacha_block_v2");
constexpr StringLiteral XorName("__allvm_str_chacha_xor_v2");
constexpr StringLiteral PolyBlockName("__allvm_str_poly_block_v2");
constexpr StringLiteral TagName("__allvm_str_poly1305_tag_v2");
constexpr StringLiteral OpenName("__allvm_string_open_v2");

void markRuntimeFunction(Function &F) {
  F.setLinkage(GlobalValue::PrivateLinkage);
  F.setDSOLocal(true);
  F.addFnAttr(Attribute::NoUnwind);
  F.addFnAttr("allvm.runtime");
  F.removeFnAttr(Attribute::AlwaysInline);
  F.addFnAttr(Attribute::NoInline);
  F.addFnAttr(Attribute::OptimizeNone);
  F.setMetadata("noobf", MDNode::get(F.getContext(), {}));
}

Value *bytePtr(IRBuilder<> &B, Value *Base, Value *Offset) {
  return B.CreateInBoundsGEP(B.getInt8Ty(), Base, Offset);
}
Value *bytePtr(IRBuilder<> &B, Value *Base, uint64_t Offset) {
  return bytePtr(B, Base, B.getInt64(Offset));
}
Value *bytePtr(IRBuilder<> &B, Value *Base, unsigned Offset) {
  return bytePtr(B, Base, static_cast<uint64_t>(Offset));
}

Value *arrayElem(IRBuilder<> &B, AllocaInst *Array, unsigned Index) {
  return B.CreateInBoundsGEP(Array->getAllocatedType(), Array,
                             {B.getInt32(0), B.getInt32(Index)});
}
Value *rotl32(IRBuilder<> &B, Value *V, unsigned Shift) {
  return B.CreateOr(B.CreateShl(V, B.getInt32(Shift)),
                    B.CreateLShr(V, B.getInt32(32U - Shift)));
}

Function *createLoadN(Module &M, StringRef Name, unsigned Bits) {
  if (Function *F = M.getFunction(Name))
    return F;
  LLVMContext &C = M.getContext();
  Type *PtrTy = PointerType::getUnqual(C);
  IntegerType *ResultTy = IntegerType::get(C, Bits);
  Function *F = Function::Create(
      FunctionType::get(ResultTy, {PtrTy}, false),
      GlobalValue::PrivateLinkage, Name, M);
  markRuntimeFunction(*F);
  Argument *P = F->getArg(0);
  IRBuilder<> B(BasicBlock::Create(C, "entry", F));
  Value *Result = ConstantInt::get(ResultTy, 0);
  for (unsigned I = 0; I < Bits / 8U; ++I) {
    LoadInst *Byte = B.CreateLoad(B.getInt8Ty(), bytePtr(B, P, I));
    Byte->setAlignment(Align(1));
    Value *Part = B.CreateZExt(Byte, ResultTy);
    if (I != 0)
      Part = B.CreateShl(Part, ConstantInt::get(ResultTy, I * 8U));
    Result = B.CreateOr(Result, Part);
  }
  B.CreateRet(Result);
  return F;
}

Function *createStoreN(Module &M, StringRef Name, unsigned Bits) {
  if (Function *F = M.getFunction(Name))
    return F;
  LLVMContext &C = M.getContext();
  Type *PtrTy = PointerType::getUnqual(C);
  IntegerType *ValueTy = IntegerType::get(C, Bits);
  Function *F = Function::Create(
      FunctionType::get(Type::getVoidTy(C), {PtrTy, ValueTy}, false),
      GlobalValue::PrivateLinkage, Name, M);
  markRuntimeFunction(*F);
  Argument *P = F->getArg(0);
  Argument *V = F->getArg(1);
  IRBuilder<> B(BasicBlock::Create(C, "entry", F));
  for (unsigned I = 0; I < Bits / 8U; ++I) {
    Value *Part = I == 0
                      ? static_cast<Value *>(V)
                      : B.CreateLShr(V, ConstantInt::get(ValueTy, I * 8U));
    StoreInst *S = B.CreateStore(B.CreateTrunc(Part, B.getInt8Ty()),
                                 bytePtr(B, P, I));
    S->setAlignment(Align(1));
  }
  B.CreateRetVoid();
  return F;
}

Value *wordPtr(IRBuilder<> &B, AllocaInst *Array, unsigned Index) {
  return arrayElem(B, Array, Index);
}
Value *loadWord(IRBuilder<> &B, AllocaInst *Array, unsigned Index) {
  LoadInst *L = B.CreateLoad(B.getInt32Ty(), wordPtr(B, Array, Index));
  L->setAlignment(Align(4));
  return L;
}
void storeWord(IRBuilder<> &B, AllocaInst *Array, unsigned Index, Value *V) {
  StoreInst *S = B.CreateStore(V, wordPtr(B, Array, Index));
  S->setAlignment(Align(4));
}
void emitQuarterRound(IRBuilder<> &B, AllocaInst *X, unsigned A, unsigned BI,
                      unsigned C, unsigned D) {
  Value *VA = loadWord(B, X, A);
  Value *VB = loadWord(B, X, BI);
  Value *VC = loadWord(B, X, C);
  Value *VD = loadWord(B, X, D);
  VA = B.CreateAdd(VA, VB);
  VD = rotl32(B, B.CreateXor(VD, VA), 16U);
  VC = B.CreateAdd(VC, VD);
  VB = rotl32(B, B.CreateXor(VB, VC), 12U);
  VA = B.CreateAdd(VA, VB);
  VD = rotl32(B, B.CreateXor(VD, VA), 8U);
  VC = B.CreateAdd(VC, VD);
  VB = rotl32(B, B.CreateXor(VB, VC), 7U);
  storeWord(B, X, A, VA);
  storeWord(B, X, BI, VB);
  storeWord(B, X, C, VC);
  storeWord(B, X, D, VD);
}

Function *createBlock(Module &M, Function *Load32, Function *Store32) {
  if (Function *F = M.getFunction(BlockName))
    return F;
  LLVMContext &C = M.getContext();
  Type *PtrTy = PointerType::getUnqual(C);
  Type *I32 = Type::getInt32Ty(C);
  Function *F = Function::Create(
      FunctionType::get(Type::getVoidTy(C),
                        {PtrTy, PtrTy, PtrTy, PtrTy, I32}, false),
      GlobalValue::PrivateLinkage, BlockName, M);
  markRuntimeFunction(*F);
  auto AI = F->arg_begin();
  Argument *Out = AI++;
  Argument *KeyA = AI++;
  Argument *KeyB = AI++;
  Argument *Nonce = AI++;
  Argument *Counter = AI++;
  IRBuilder<> B(BasicBlock::Create(C, "entry", F));
  ArrayType *StateTy = ArrayType::get(I32, 16);
  AllocaInst *Initial = B.CreateAlloca(StateTy, nullptr, "initial");
  AllocaInst *X = B.CreateAlloca(StateTy, nullptr, "x");
  Initial->setAlignment(Align(16));
  X->setAlignment(Align(16));
  const std::array<uint32_t, 4> Constants = {
      0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U};
  for (unsigned I = 0; I < Constants.size(); ++I)
    storeWord(B, Initial, I, B.getInt32(Constants[I]));
  for (unsigned I = 0; I < 8U; ++I) {
    Value *Offset0 = B.getInt64(I * 4U);
    Value *Offset1 = B.getInt64(32U + I * 4U);
    Value *Combined = B.CreateXor(
        B.CreateXor(B.CreateCall(Load32, {bytePtr(B, KeyA, Offset0)}),
                    B.CreateCall(Load32, {bytePtr(B, KeyB, Offset0)})),
        B.CreateXor(B.CreateCall(Load32, {bytePtr(B, KeyA, Offset1)}),
                    B.CreateCall(Load32, {bytePtr(B, KeyB, Offset1)})));
    storeWord(B, Initial, 4U + I, Combined);
  }
  storeWord(B, Initial, 12U, Counter);
  for (unsigned I = 0; I < 3U; ++I)
    storeWord(B, Initial, 13U + I,
              B.CreateCall(Load32, {bytePtr(B, Nonce, I * 4U)}));
  for (unsigned I = 0; I < 16U; ++I)
    storeWord(B, X, I, loadWord(B, Initial, I));
  for (unsigned Round = 0; Round < 10U; ++Round) {
    emitQuarterRound(B, X, 0, 4, 8, 12);
    emitQuarterRound(B, X, 1, 5, 9, 13);
    emitQuarterRound(B, X, 2, 6, 10, 14);
    emitQuarterRound(B, X, 3, 7, 11, 15);
    emitQuarterRound(B, X, 0, 5, 10, 15);
    emitQuarterRound(B, X, 1, 6, 11, 12);
    emitQuarterRound(B, X, 2, 7, 8, 13);
    emitQuarterRound(B, X, 3, 4, 9, 14);
  }
  for (unsigned I = 0; I < 16U; ++I)
    B.CreateCall(Store32,
                 {bytePtr(B, Out, I * 4U),
                  B.CreateAdd(loadWord(B, X, I), loadWord(B, Initial, I))});
  B.CreateMemSet(Initial, B.getInt8(0), 64, Align(16), true);
  B.CreateMemSet(X, B.getInt8(0), 64, Align(16), true);
  B.CreateRetVoid();
  return F;
}

Function *createXor(Module &M, Function *Block) {
  if (Function *F = M.getFunction(XorName))
    return F;
  LLVMContext &C = M.getContext();
  Type *PtrTy = PointerType::getUnqual(C);
  Type *I32 = Type::getInt32Ty(C);
  Function *F = Function::Create(
      FunctionType::get(Type::getInt1Ty(C),
                        {PtrTy, PtrTy, I32, PtrTy, PtrTy, PtrTy}, false),
      GlobalValue::PrivateLinkage, XorName, M);
  markRuntimeFunction(*F);
  auto AI = F->arg_begin();
  Argument *Out = AI++;
  Argument *In = AI++;
  Argument *Size = AI++;
  Argument *KeyA = AI++;
  Argument *KeyB = AI++;
  Argument *Nonce = AI++;
  BasicBlock *Entry = BasicBlock::Create(C, "entry", F);
  BasicBlock *OuterCond = BasicBlock::Create(C, "outer.cond", F);
  BasicBlock *Generate = BasicBlock::Create(C, "generate", F);
  BasicBlock *InnerCond = BasicBlock::Create(C, "inner.cond", F);
  BasicBlock *InnerBody = BasicBlock::Create(C, "inner.body", F);
  BasicBlock *OuterUpdate = BasicBlock::Create(C, "outer.update", F);
  BasicBlock *Success = BasicBlock::Create(C, "success", F);
  BasicBlock *Failure = BasicBlock::Create(C, "failure", F);
  IRBuilder<> B(Entry);
  ArrayType *BlockTy = ArrayType::get(B.getInt8Ty(), 64);
  AllocaInst *KeyStream = B.CreateAlloca(BlockTy, nullptr, "keystream");
  AllocaInst *Offset = B.CreateAlloca(I32, nullptr, "offset");
  AllocaInst *Counter = B.CreateAlloca(I32, nullptr, "counter");
  AllocaInst *Count = B.CreateAlloca(I32, nullptr, "count");
  AllocaInst *Inner = B.CreateAlloca(I32, nullptr, "inner");
  KeyStream->setAlignment(Align(16));
  B.CreateStore(B.getInt32(0), Offset);
  B.CreateStore(B.getInt32(1), Counter);
  B.CreateBr(OuterCond);
  B.SetInsertPoint(OuterCond);
  Value *CurrentOffset = B.CreateLoad(I32, Offset);
  B.CreateCondBr(B.CreateICmpUGE(CurrentOffset, Size), Success, Generate);
  B.SetInsertPoint(Generate);
  Value *CurrentCounter = B.CreateLoad(I32, Counter);
  BasicBlock *GenerateBody = BasicBlock::Create(C, "generate.body", F,
                                                InnerCond);
  B.CreateCondBr(B.CreateICmpNE(CurrentCounter, B.getInt32(0)), GenerateBody,
                 Failure);
  B.SetInsertPoint(GenerateBody);
  Value *Remaining = B.CreateSub(Size, CurrentOffset);
  Value *Chunk = B.CreateSelect(B.CreateICmpULT(Remaining, B.getInt32(64)),
                                Remaining, B.getInt32(64));
  B.CreateStore(Chunk, Count);
  Value *KeyStreamPtr = B.CreateInBoundsGEP(
      BlockTy, KeyStream, {B.getInt32(0), B.getInt32(0)});
  B.CreateCall(Block, {KeyStreamPtr, KeyA, KeyB, Nonce, CurrentCounter});
  B.CreateStore(B.getInt32(0), Inner);
  B.CreateBr(InnerCond);
  B.SetInsertPoint(InnerCond);
  Value *InnerValue = B.CreateLoad(I32, Inner);
  Value *CurrentCount = B.CreateLoad(I32, Count);
  B.CreateCondBr(B.CreateICmpULT(InnerValue, CurrentCount), InnerBody,
                 OuterUpdate);
  B.SetInsertPoint(InnerBody);
  Value *Index = B.CreateAdd(CurrentOffset, InnerValue);
  Value *Index64 = B.CreateZExt(Index, B.getInt64Ty());
  LoadInst *InputByte = B.CreateLoad(B.getInt8Ty(), bytePtr(B, In, Index64));
  InputByte->setAlignment(Align(1));
  Value *KSBytePtr = B.CreateInBoundsGEP(
      BlockTy, KeyStream, {B.getInt32(0), InnerValue});
  LoadInst *KSByte = B.CreateLoad(B.getInt8Ty(), KSBytePtr);
  KSByte->setAlignment(Align(1));
  StoreInst *OutputByte = B.CreateStore(B.CreateXor(InputByte, KSByte),
                                        bytePtr(B, Out, Index64));
  OutputByte->setAlignment(Align(1));
  B.CreateStore(B.CreateAdd(InnerValue, B.getInt32(1)), Inner);
  B.CreateBr(InnerCond);
  B.SetInsertPoint(OuterUpdate);
  B.CreateStore(B.CreateAdd(CurrentOffset, CurrentCount), Offset);
  B.CreateStore(B.CreateAdd(CurrentCounter, B.getInt32(1)), Counter);
  B.CreateBr(OuterCond);
  B.SetInsertPoint(Success);
  B.CreateMemSet(KeyStream, B.getInt8(0), 64, Align(16), true);
  B.CreateRet(B.getTrue());
  B.SetInsertPoint(Failure);
  B.CreateMemSet(KeyStream, B.getInt8(0), 64, Align(16), true);
  B.CreateRet(B.getFalse());
  return F;
}

Function *createPolyBlock(Module &M, Function *Load128) {
  if (Function *F = M.getFunction(PolyBlockName))
    return F;
  LLVMContext &C = M.getContext();
  Type *PtrTy = PointerType::getUnqual(C);
  IntegerType *I128 = IntegerType::get(C, 128);
  IntegerType *I130 = IntegerType::get(C, 130);
  IntegerType *I256 = IntegerType::get(C, 256);
  Function *F = Function::Create(
      FunctionType::get(Type::getVoidTy(C), {PtrTy, I128, PtrTy}, false),
      GlobalValue::PrivateLinkage, PolyBlockName, M);
  markRuntimeFunction(*F);
  auto AI = F->arg_begin();
  Argument *HPtr = AI++;
  Argument *R = AI++;
  Argument *Block = AI++;
  IRBuilder<> B(BasicBlock::Create(C, "entry", F));
  LoadInst *H = B.CreateLoad(I130, HPtr);
  H->setAlignment(Align(16));
  Value *BlockValue = B.CreateCall(Load128, {Block});
  APInt Hibit = APInt::getOneBitSet(130, 128);
  Value *N = B.CreateOr(B.CreateZExt(BlockValue, I130),
                        ConstantInt::get(I130, Hibit));
  Value *Sum = B.CreateAdd(H, N);
  Value *Product = B.CreateMul(B.CreateZExt(Sum, I256),
                               B.CreateZExt(R, I256));
  APInt Mask = APInt::getLowBitsSet(256, 130);
  Value *MaskC = ConstantInt::get(I256, Mask);
  Value *Low = B.CreateAnd(Product, MaskC);
  Value *High = B.CreateLShr(Product, ConstantInt::get(I256, 130));
  Value *Fold1 = B.CreateAdd(Low, B.CreateMul(High, ConstantInt::get(I256, 5)));
  Value *Low2 = B.CreateAnd(Fold1, MaskC);
  Value *High2 = B.CreateLShr(Fold1, ConstantInt::get(I256, 130));
  Value *Fold2 = B.CreateAdd(Low2, B.CreateMul(High2, ConstantInt::get(I256, 5)));
  APInt P = APInt::getOneBitSet(256, 130) - 5U;
  Value *PC = ConstantInt::get(I256, P);
  Value *Reduced = B.CreateSelect(B.CreateICmpUGE(Fold2, PC),
                                  B.CreateSub(Fold2, PC), Fold2);
  StoreInst *S = B.CreateStore(B.CreateTrunc(Reduced, I130), HPtr);
  S->setAlignment(Align(16));
  B.CreateRetVoid();
  return F;
}

Function *createTag(Module &M, Function *Load128, Function *Store64,
                    Function *Store128, Function *Block,
                    Function *PolyBlock) {
  if (Function *F = M.getFunction(TagName))
    return F;
  LLVMContext &C = M.getContext();
  Type *PtrTy = PointerType::getUnqual(C);
  Type *I32 = Type::getInt32Ty(C);
  Type *I64 = Type::getInt64Ty(C);
  IntegerType *I128 = IntegerType::get(C, 128);
  IntegerType *I130 = IntegerType::get(C, 130);
  Function *F = Function::Create(
      FunctionType::get(Type::getVoidTy(C),
                        {PtrTy, PtrTy, I32, PtrTy, PtrTy}, false),
      GlobalValue::PrivateLinkage, TagName, M);
  markRuntimeFunction(*F);
  auto AI = F->arg_begin();
  Argument *Out = AI++;
  Argument *Record = AI++;
  Argument *Size = AI++;
  Argument *KeyA = AI++;
  Argument *KeyB = AI++;
  BasicBlock *Entry = BasicBlock::Create(C, "entry", F);
  BasicBlock *FullCond = BasicBlock::Create(C, "full.cond", F);
  BasicBlock *FullBody = BasicBlock::Create(C, "full.body", F);
  BasicBlock *PartialCheck = BasicBlock::Create(C, "partial.check", F);
  BasicBlock *PartialBody = BasicBlock::Create(C, "partial.body", F);
  BasicBlock *Finish = BasicBlock::Create(C, "finish", F);
  IRBuilder<> B(Entry);
  ArrayType *Block64Ty = ArrayType::get(B.getInt8Ty(), 64);
  ArrayType *Block16Ty = ArrayType::get(B.getInt8Ty(), 16);
  AllocaInst *Block0 = B.CreateAlloca(Block64Ty, nullptr, "block0");
  AllocaInst *Partial = B.CreateAlloca(Block16Ty, nullptr, "partial");
  AllocaInst *Lengths = B.CreateAlloca(Block16Ty, nullptr, "lengths");
  AllocaInst *H = B.CreateAlloca(I130, nullptr, "h");
  AllocaInst *Index = B.CreateAlloca(I32, nullptr, "index");
  Block0->setAlignment(Align(16));
  Partial->setAlignment(Align(16));
  Lengths->setAlignment(Align(16));
  H->setAlignment(Align(16));
  Value *Block0Ptr = B.CreateInBoundsGEP(
      Block64Ty, Block0, {B.getInt32(0), B.getInt32(0)});
  Value *PartialPtr = B.CreateInBoundsGEP(
      Block16Ty, Partial, {B.getInt32(0), B.getInt32(0)});
  Value *LengthsPtr = B.CreateInBoundsGEP(
      Block16Ty, Lengths, {B.getInt32(0), B.getInt32(0)});
  Value *Nonce = bytePtr(B, Record, ALLVM_STR_NONCE_OFFSET);
  B.CreateCall(Block, {Block0Ptr, KeyA, KeyB, Nonce, B.getInt32(0)});
  Value *RawR = B.CreateCall(Load128, {Block0Ptr});
  APInt Clamp(128, "0ffffffc0ffffffc0ffffffc0fffffff", 16);
  Value *R = B.CreateAnd(RawR, ConstantInt::get(I128, Clamp));
  Value *S = B.CreateCall(Load128, {bytePtr(B, Block0Ptr, 16U)});
  StoreInst *ZeroH = B.CreateStore(ConstantInt::get(I130, 0), H);
  ZeroH->setAlignment(Align(16));
  B.CreateCall(PolyBlock, {H, R, Record});
  B.CreateCall(PolyBlock, {H, R, bytePtr(B, Record, 16U)});
  B.CreateStore(B.getInt32(0), Index);
  B.CreateBr(FullCond);
  B.SetInsertPoint(FullCond);
  Value *I = B.CreateLoad(I32, Index);
  Value *FullCount = B.CreateUDiv(Size, B.getInt32(16));
  B.CreateCondBr(B.CreateICmpULT(I, FullCount), FullBody, PartialCheck);
  B.SetInsertPoint(FullBody);
  Value *CipherOffset = B.CreateAdd(
      B.getInt32(ALLVM_STR_CIPHERTEXT_OFFSET), B.CreateMul(I, B.getInt32(16)));
  B.CreateCall(PolyBlock,
               {H, R, bytePtr(B, Record, B.CreateZExt(CipherOffset, I64))});
  B.CreateStore(B.CreateAdd(I, B.getInt32(1)), Index);
  B.CreateBr(FullCond);
  B.SetInsertPoint(PartialCheck);
  Value *Remainder = B.CreateURem(Size, B.getInt32(16));
  B.CreateCondBr(B.CreateICmpNE(Remainder, B.getInt32(0)), PartialBody,
                 Finish);
  B.SetInsertPoint(PartialBody);
  B.CreateMemSet(PartialPtr, B.getInt8(0), 16, Align(16), true);
  Value *TailOffset = B.CreateAdd(
      B.getInt32(ALLVM_STR_CIPHERTEXT_OFFSET),
      B.CreateMul(FullCount, B.getInt32(16)));
  B.CreateMemCpy(PartialPtr, Align(1),
                 bytePtr(B, Record, B.CreateZExt(TailOffset, I64)), Align(1),
                 B.CreateZExt(Remainder, I64));
  B.CreateCall(PolyBlock, {H, R, PartialPtr});
  B.CreateBr(Finish);
  B.SetInsertPoint(Finish);
  B.CreateCall(Store64, {LengthsPtr, B.getInt64(ALLVM_STR_AAD_SIZE)});
  B.CreateCall(Store64,
               {bytePtr(B, LengthsPtr, 8U), B.CreateZExt(Size, I64)});
  B.CreateCall(PolyBlock, {H, R, LengthsPtr});
  LoadInst *FinalH = B.CreateLoad(I130, H);
  FinalH->setAlignment(Align(16));
  Value *Tag = B.CreateAdd(B.CreateTrunc(FinalH, I128), S);
  B.CreateCall(Store128, {Out, Tag});
  B.CreateMemSet(Block0Ptr, B.getInt8(0), 64, Align(16), true);
  B.CreateMemSet(PartialPtr, B.getInt8(0), 16, Align(16), true);
  B.CreateMemSet(LengthsPtr, B.getInt8(0), 16, Align(16), true);
  StoreInst *WipeH = B.CreateStore(ConstantInt::get(I130, 0), H, true);
  WipeH->setAlignment(Align(16));
  B.CreateRetVoid();
  return F;
}

Function *createOpen(Module &M, Function *Load32, Function *Load128,
                     Function *Tag, Function *Xor) {
  if (Function *F = M.getFunction(OpenName))
    return F;
  LLVMContext &C = M.getContext();
  Type *PtrTy = PointerType::getUnqual(C);
  Type *I32 = Type::getInt32Ty(C);
  Type *I64 = Type::getInt64Ty(C);
  Function *F = Function::Create(
      FunctionType::get(I32,
                        {PtrTy, PtrTy, I64, PtrTy, PtrTy, I32, I32, I32, I32},
                        false),
      GlobalValue::PrivateLinkage, OpenName, M);
  markRuntimeFunction(*F);
  auto AI = F->arg_begin();
  Argument *Out = AI++;
  Argument *Record = AI++;
  Argument *RecordSize = AI++;
  Argument *KeyA = AI++;
  Argument *KeyB = AI++;
  Argument *ExpectedID = AI++;
  Argument *ExpectedOffset = AI++;
  Argument *ExpectedFlags = AI++;
  Argument *ExpectedSize = AI++;
  BasicBlock *Entry = BasicBlock::Create(C, "entry", F);
  BasicBlock *Header = BasicBlock::Create(C, "header", F);
  BasicBlock *Authenticate = BasicBlock::Create(C, "authenticate", F);
  BasicBlock *Decrypt = BasicBlock::Create(C, "decrypt", F);
  BasicBlock *Success = BasicBlock::Create(C, "success", F);
  BasicBlock *Failure = BasicBlock::Create(C, "failure", F);
  IRBuilder<> B(Entry);
  ArrayType *TagTy = ArrayType::get(B.getInt8Ty(), ALLVM_STR_TAG_SIZE);
  AllocaInst *Computed = B.CreateAlloca(TagTy, nullptr, "computed_tag");
  Computed->setAlignment(Align(16));
  Value *ComputedPtr = B.CreateInBoundsGEP(
      TagTy, Computed, {B.getInt32(0), B.getInt32(0)});
  Value *Required = B.CreateAdd(B.CreateZExt(ExpectedSize, I64),
                                B.getInt64(ALLVM_STR_HEADER_SIZE));
  B.CreateCondBr(B.CreateICmpEQ(RecordSize, Required), Header, Failure);
  B.SetInsertPoint(Header);
  Value *Magic = B.CreateCall(Load32, {Record});
  Value *VersionFlags = B.CreateCall(Load32, {bytePtr(B, Record, 4U)});
  Value *ID = B.CreateCall(Load32, {bytePtr(B, Record, 8U)});
  Value *PlainSize = B.CreateCall(Load32, {bytePtr(B, Record, 12U)});
  Value *Offset = B.CreateCall(Load32, {bytePtr(B, Record, 28U)});
  Value *Version = B.CreateAnd(VersionFlags, B.getInt32(0xffff));
  Value *Flags = B.CreateLShr(VersionFlags, B.getInt32(16));
  Value *HeaderOK = B.CreateAnd(
      B.CreateAnd(B.CreateICmpEQ(Magic, B.getInt32(ALLVM_STR_MAGIC)),
                  B.CreateICmpEQ(Version, B.getInt32(ALLVM_STR_VERSION))),
      B.CreateAnd(
          B.CreateAnd(B.CreateICmpEQ(ID, ExpectedID),
                      B.CreateICmpEQ(PlainSize, ExpectedSize)),
          B.CreateAnd(B.CreateICmpEQ(Offset, ExpectedOffset),
                      B.CreateICmpEQ(Flags, ExpectedFlags))));
  B.CreateCondBr(HeaderOK, Authenticate, Failure);
  B.SetInsertPoint(Authenticate);
  B.CreateCall(Tag, {ComputedPtr, Record, ExpectedSize, KeyA, KeyB});
  Value *Stored = B.CreateCall(Load128,
                               {bytePtr(B, Record, ALLVM_STR_TAG_OFFSET)});
  Value *Calculated = B.CreateCall(Load128, {ComputedPtr});
  B.CreateCondBr(B.CreateICmpEQ(Stored, Calculated), Decrypt, Failure);
  B.SetInsertPoint(Decrypt);
  Value *Opened = B.CreateCall(
      Xor, {Out, bytePtr(B, Record, ALLVM_STR_CIPHERTEXT_OFFSET),
            ExpectedSize, KeyA, KeyB,
            bytePtr(B, Record, ALLVM_STR_NONCE_OFFSET)});
  B.CreateCondBr(Opened, Success, Failure);
  B.SetInsertPoint(Success);
  B.CreateMemSet(ComputedPtr, B.getInt8(0), ALLVM_STR_TAG_SIZE, Align(16), true);
  B.CreateRet(B.getInt32(1));
  B.SetInsertPoint(Failure);
  B.CreateMemSet(Out, B.getInt8(0), B.CreateZExt(ExpectedSize, I64), Align(1),
                 true);
  B.CreateMemSet(ComputedPtr, B.getInt8(0), ALLVM_STR_TAG_SIZE, Align(16), true);
  B.CreateRet(B.getInt32(0));
  return F;
}

} // namespace

Function *llvm::allvm::getOrCreateAuthenticatedStringOpen(Module &M) {
  if (Function *Existing = M.getFunction(OpenName))
    return Existing;
  Function *Load32 = createLoadN(M, Load32Name, 32);
  Function *Store32 = createStoreN(M, Store32Name, 32);
  Function *Load64 = createLoadN(M, Load64Name, 64);
  Function *Store64 = createStoreN(M, Store64Name, 64);
  Function *Load128 = createLoadN(M, Load128Name, 128);
  Function *Store128 = createStoreN(M, Store128Name, 128);
  Function *Block = createBlock(M, Load32, Store32);
  Function *Xor = createXor(M, Block);
  Function *PolyBlock = createPolyBlock(M, Load128);
  Function *Tag = createTag(M, Load128, Store64, Store128, Block, PolyBlock);
  return createOpen(M, Load32, Load128, Tag, Xor);
}
