//===- AuthenticatedStringIR.cpp - authenticated string runtime IR -------===//

#include "llvm/Transforms/Obfuscation/AuthenticatedStringIR.h"
#include "llvm/Transforms/Obfuscation/AuthenticatedStringCrypto.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"

#include <array>
#include <cstdint>

using namespace llvm;

namespace {

constexpr StringLiteral Load32Name("__allvm_str_load32_v1");
constexpr StringLiteral Load64Name("__allvm_str_load64_v1");
constexpr StringLiteral Store32Name("__allvm_str_store32_v1");
constexpr StringLiteral TagName("__allvm_str_tag_v1");
constexpr StringLiteral BlockName("__allvm_str_chacha_block_v1");
constexpr StringLiteral XorName("__allvm_str_chacha_xor_v1");
constexpr StringLiteral OpenName("__allvm_string_open_v1");

void markRuntimeFunction(Function &F) {
  F.setLinkage(GlobalValue::PrivateLinkage);
  F.setDSOLocal(true);
  F.addFnAttr(Attribute::NoUnwind);
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

Value *bytePtr(IRBuilder<> &B, Value *Base, int Offset) {
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

Value *rotl64(IRBuilder<> &B, Value *V, unsigned Shift) {
  return B.CreateOr(B.CreateShl(V, B.getInt64(Shift)),
                    B.CreateLShr(V, B.getInt64(64U - Shift)));
}

Function *createLoad32(Module &M) {
  if (Function *F = M.getFunction(Load32Name))
    return F;
  LLVMContext &C = M.getContext();
  Type *PtrTy = PointerType::getUnqual(C);
  Function *F = Function::Create(
      FunctionType::get(Type::getInt32Ty(C), {PtrTy}, false),
      GlobalValue::PrivateLinkage, Load32Name, M);
  markRuntimeFunction(*F);
  Argument *P = F->getArg(0);
  IRBuilder<> B(BasicBlock::Create(C, "entry", F));
  Value *Result = B.getInt32(0);
  for (unsigned I = 0; I < 4U; ++I) {
    LoadInst *Byte = B.CreateLoad(B.getInt8Ty(), bytePtr(B, P, I));
    Byte->setAlignment(Align(1));
    Value *Part = B.CreateZExt(Byte, B.getInt32Ty());
    if (I != 0)
      Part = B.CreateShl(Part, B.getInt32(I * 8U));
    Result = B.CreateOr(Result, Part);
  }
  B.CreateRet(Result);
  return F;
}

Function *createLoad64(Module &M) {
  if (Function *F = M.getFunction(Load64Name))
    return F;
  LLVMContext &C = M.getContext();
  Type *PtrTy = PointerType::getUnqual(C);
  Function *F = Function::Create(
      FunctionType::get(Type::getInt64Ty(C), {PtrTy}, false),
      GlobalValue::PrivateLinkage, Load64Name, M);
  markRuntimeFunction(*F);
  Argument *P = F->getArg(0);
  IRBuilder<> B(BasicBlock::Create(C, "entry", F));
  Value *Result = B.getInt64(0);
  for (unsigned I = 0; I < 8U; ++I) {
    LoadInst *Byte = B.CreateLoad(B.getInt8Ty(), bytePtr(B, P, I));
    Byte->setAlignment(Align(1));
    Value *Part = B.CreateZExt(Byte, B.getInt64Ty());
    if (I != 0)
      Part = B.CreateShl(Part, B.getInt64(I * 8U));
    Result = B.CreateOr(Result, Part);
  }
  B.CreateRet(Result);
  return F;
}

Function *createStore32(Module &M) {
  if (Function *F = M.getFunction(Store32Name))
    return F;
  LLVMContext &C = M.getContext();
  Type *PtrTy = PointerType::getUnqual(C);
  Function *F = Function::Create(
      FunctionType::get(Type::getVoidTy(C), {PtrTy, Type::getInt32Ty(C)},
                        false),
      GlobalValue::PrivateLinkage, Store32Name, M);
  markRuntimeFunction(*F);
  Argument *P = F->getArg(0);
  Argument *V = F->getArg(1);
  IRBuilder<> B(BasicBlock::Create(C, "entry", F));
  for (unsigned I = 0; I < 4U; ++I) {
    Value *Part = I == 0 ? V : B.CreateLShr(V, B.getInt32(I * 8U));
    StoreInst *Store = B.CreateStore(B.CreateTrunc(Part, B.getInt8Ty()),
                                     bytePtr(B, P, I));
    Store->setAlignment(Align(1));
  }
  B.CreateRetVoid();
  return F;
}

struct SipAllocas {
  AllocaInst *V0;
  AllocaInst *V1;
  AllocaInst *V2;
  AllocaInst *V3;
};

void store64(IRBuilder<> &B, AllocaInst *P, Value *V) {
  StoreInst *S = B.CreateStore(V, P);
  S->setAlignment(Align(8));
}

Value *load64(IRBuilder<> &B, AllocaInst *P) {
  LoadInst *L = B.CreateLoad(B.getInt64Ty(), P);
  L->setAlignment(Align(8));
  return L;
}

void emitSipRound(IRBuilder<> &B, const SipAllocas &S) {
  Value *V0 = load64(B, S.V0);
  Value *V1 = load64(B, S.V1);
  Value *V2 = load64(B, S.V2);
  Value *V3 = load64(B, S.V3);
  V0 = B.CreateAdd(V0, V1);
  V1 = B.CreateXor(rotl64(B, V1, 13U), V0);
  V0 = rotl64(B, V0, 32U);
  V2 = B.CreateAdd(V2, V3);
  V3 = B.CreateXor(rotl64(B, V3, 16U), V2);
  V0 = B.CreateAdd(V0, V3);
  V3 = B.CreateXor(rotl64(B, V3, 21U), V0);
  V2 = B.CreateAdd(V2, V1);
  V1 = B.CreateXor(rotl64(B, V1, 17U), V2);
  V2 = rotl64(B, V2, 32U);
  store64(B, S.V0, V0);
  store64(B, S.V1, V1);
  store64(B, S.V2, V2);
  store64(B, S.V3, V3);
}

void emitSipCompress(IRBuilder<> &B, const SipAllocas &S, Value *Word) {
  store64(B, S.V3, B.CreateXor(load64(B, S.V3), Word));
  emitSipRound(B, S);
  emitSipRound(B, S);
  store64(B, S.V0, B.CreateXor(load64(B, S.V0), Word));
}

Function *createTag(Module &M, Function *Load64) {
  if (Function *F = M.getFunction(TagName))
    return F;
  LLVMContext &C = M.getContext();
  Type *PtrTy = PointerType::getUnqual(C);
  Type *I32 = Type::getInt32Ty(C);
  Type *I64 = Type::getInt64Ty(C);
  Function *F = Function::Create(
      FunctionType::get(I64, {PtrTy, I32, I64, I64, I64}, false),
      GlobalValue::PrivateLinkage, TagName, M);
  markRuntimeFunction(*F);
  auto AI = F->arg_begin();
  Argument *Record = AI++;
  Argument *PlainSize = AI++;
  Argument *K0 = AI++;
  Argument *K1 = AI++;
  Argument *Domain = AI++;

  BasicBlock *Entry = BasicBlock::Create(C, "entry", F);
  BasicBlock *WordCond = BasicBlock::Create(C, "word.cond", F);
  BasicBlock *WordBody = BasicBlock::Create(C, "word.body", F);
  BasicBlock *TailSetup = BasicBlock::Create(C, "tail.setup", F);
  BasicBlock *TailCond = BasicBlock::Create(C, "tail.cond", F);
  BasicBlock *TailBody = BasicBlock::Create(C, "tail.body", F);
  BasicBlock *Finish = BasicBlock::Create(C, "finish", F);

  IRBuilder<> B(Entry);
  SipAllocas S{B.CreateAlloca(I64, nullptr, "v0"),
               B.CreateAlloca(I64, nullptr, "v1"),
               B.CreateAlloca(I64, nullptr, "v2"),
               B.CreateAlloca(I64, nullptr, "v3")};
  AllocaInst *WordIndex = B.CreateAlloca(I32, nullptr, "word_index");
  AllocaInst *TailIndex = B.CreateAlloca(I32, nullptr, "tail_index");
  AllocaInst *Tail = B.CreateAlloca(I64, nullptr, "tail");
  store64(B, S.V0, B.CreateXor(B.getInt64(0x736f6d6570736575ULL), K0));
  store64(B, S.V1, B.CreateXor(B.getInt64(0x646f72616e646f6dULL), K1));
  store64(B, S.V2, B.CreateXor(B.getInt64(0x6c7967656e657261ULL), K0));
  store64(B, S.V3, B.CreateXor(B.getInt64(0x7465646279746573ULL), K1));
  emitSipCompress(B, S, Domain);
  for (unsigned Offset : {0U, 8U, 16U, 24U})
    emitSipCompress(B, S,
                    B.CreateCall(Load64, {bytePtr(B, Record, Offset)}));
  B.CreateStore(B.getInt32(0), WordIndex);
  B.CreateBr(WordCond);

  B.SetInsertPoint(WordCond);
  Value *WI = B.CreateLoad(I32, WordIndex);
  Value *FullWords = B.CreateUDiv(PlainSize, B.getInt32(8));
  B.CreateCondBr(B.CreateICmpULT(WI, FullWords), WordBody, TailSetup);

  B.SetInsertPoint(WordBody);
  Value *WordOffset = B.CreateAdd(B.getInt32(ALLVM_STR_CIPHERTEXT_OFFSET),
                                  B.CreateMul(WI, B.getInt32(8)));
  Value *WordPtr = bytePtr(B, Record, B.CreateZExt(WordOffset, I64));
  emitSipCompress(B, S, B.CreateCall(Load64, {WordPtr}));
  B.CreateStore(B.CreateAdd(WI, B.getInt32(1)), WordIndex);
  B.CreateBr(WordCond);

  B.SetInsertPoint(TailSetup);
  B.CreateStore(B.getInt64(0), Tail);
  B.CreateStore(B.getInt32(0), TailIndex);
  B.CreateBr(TailCond);

  B.SetInsertPoint(TailCond);
  Value *TI = B.CreateLoad(I32, TailIndex);
  Value *TailBytes = B.CreateURem(PlainSize, B.getInt32(8));
  B.CreateCondBr(B.CreateICmpULT(TI, TailBytes), TailBody, Finish);

  B.SetInsertPoint(TailBody);
  Value *BaseOffset = B.CreateAdd(
      B.getInt32(ALLVM_STR_CIPHERTEXT_OFFSET),
      B.CreateMul(FullWords, B.getInt32(8)));
  Value *TailOffset = B.CreateAdd(BaseOffset, TI);
  LoadInst *Byte = B.CreateLoad(
      B.getInt8Ty(), bytePtr(B, Record, B.CreateZExt(TailOffset, I64)));
  Byte->setAlignment(Align(1));
  Value *Shift = B.CreateMul(B.CreateZExt(TI, I64), B.getInt64(8));
  Value *Part = B.CreateShl(B.CreateZExt(Byte, I64), Shift);
  B.CreateStore(B.CreateOr(B.CreateLoad(I64, Tail), Part), Tail);
  B.CreateStore(B.CreateAdd(TI, B.getInt32(1)), TailIndex);
  B.CreateBr(TailCond);

  B.SetInsertPoint(Finish);
  Value *Total = B.CreateAdd(B.CreateZExt(PlainSize, I64), B.getInt64(40));
  Value *LengthByte = B.CreateShl(B.CreateAnd(Total, B.getInt64(0xff)),
                                  B.getInt64(56));
  Value *FinalWord = B.CreateOr(LengthByte, B.CreateLoad(I64, Tail));
  emitSipCompress(B, S, FinalWord);
  store64(B, S.V2, B.CreateXor(load64(B, S.V2), B.getInt64(0xff)));
  for (unsigned I = 0; I < 4U; ++I)
    emitSipRound(B, S);
  Value *Result = B.CreateXor(
      B.CreateXor(load64(B, S.V0), load64(B, S.V1)),
      B.CreateXor(load64(B, S.V2), load64(B, S.V3)));
  B.CreateRet(Result);
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
    Value *Offset = B.getInt64(I * 4U);
    Value *AWord = B.CreateCall(Load32, {bytePtr(B, KeyA, Offset)});
    Value *BWord = B.CreateCall(Load32, {bytePtr(B, KeyB, Offset)});
    storeWord(B, Initial, 4U + I, B.CreateXor(AWord, BWord));
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
  for (unsigned I = 0; I < 16U; ++I) {
    Value *Word = B.CreateAdd(loadWord(B, X, I), loadWord(B, Initial, I));
    B.CreateCall(Store32, {bytePtr(B, Out, I * 4U), Word});
  }
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
  BasicBlock *CounterOk = BasicBlock::Create(C, "counter.ok", F);
  BasicBlock *InnerCond = BasicBlock::Create(C, "inner.cond", F);
  BasicBlock *InnerBody = BasicBlock::Create(C, "inner.body", F);
  BasicBlock *OuterUpdate = BasicBlock::Create(C, "outer.update", F);
  BasicBlock *Success = BasicBlock::Create(C, "success", F);
  BasicBlock *Failure = BasicBlock::Create(C, "failure", F);

  IRBuilder<> B(Entry);
  ArrayType *BlockTy = ArrayType::get(B.getInt8Ty(), 64);
  AllocaInst *KeyStream = B.CreateAlloca(BlockTy, nullptr, "keystream");
  KeyStream->setAlignment(Align(16));
  AllocaInst *Offset = B.CreateAlloca(I32, nullptr, "offset");
  AllocaInst *Counter = B.CreateAlloca(I32, nullptr, "counter");
  AllocaInst *Count = B.CreateAlloca(I32, nullptr, "count");
  AllocaInst *Inner = B.CreateAlloca(I32, nullptr, "inner");
  B.CreateStore(B.getInt32(0), Offset);
  B.CreateStore(B.getInt32(1), Counter);
  B.CreateBr(OuterCond);

  B.SetInsertPoint(OuterCond);
  Value *CurrentOffset = B.CreateLoad(I32, Offset);
  B.CreateCondBr(B.CreateICmpUGE(CurrentOffset, Size), Success, CounterOk);

  B.SetInsertPoint(CounterOk);
  Value *CurrentCounter = B.CreateLoad(I32, Counter);
  BasicBlock *Generate = BasicBlock::Create(C, "generate", F, InnerCond);
  B.CreateCondBr(B.CreateICmpNE(CurrentCounter, B.getInt32(0)), Generate,
                 Failure);

  B.SetInsertPoint(Generate);
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

Function *createOpen(Module &M, Function *Load32, Function *Load64,
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
  Value *Required = B.CreateAdd(B.CreateZExt(ExpectedSize, I64),
                                B.getInt64(ALLVM_STR_HEADER_SIZE));
  B.CreateCondBr(B.CreateICmpEQ(RecordSize, Required), Header, Failure);

  B.SetInsertPoint(Header);
  Value *Magic = B.CreateCall(Load32, {bytePtr(B, Record, 0)});
  Value *VersionFlags = B.CreateCall(Load32, {bytePtr(B, Record, 4)});
  Value *ID = B.CreateCall(Load32, {bytePtr(B, Record, 8)});
  Value *PlainSize = B.CreateCall(Load32, {bytePtr(B, Record, 12)});
  Value *Offset = B.CreateCall(Load32, {bytePtr(B, Record, 28)});
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
  Value *Stored0 =
      B.CreateCall(Load64, {bytePtr(B, Record, ALLVM_STR_TAG0_OFFSET)});
  Value *Stored1 =
      B.CreateCall(Load64, {bytePtr(B, Record, ALLVM_STR_TAG1_OFFSET)});
  auto SplitKey64 = [&](unsigned OffsetBytes) {
    Value *AWord = B.CreateCall(Load64, {bytePtr(B, KeyA, OffsetBytes)});
    Value *BWord = B.CreateCall(Load64, {bytePtr(B, KeyB, OffsetBytes)});
    return B.CreateXor(AWord, BWord);
  };
  Value *Computed0 = B.CreateCall(
      Tag, {Record, ExpectedSize, SplitKey64(32), SplitKey64(40),
            B.getInt64(0x305254534d564c41ULL)});
  Value *Computed1 = B.CreateCall(
      Tag, {Record, ExpectedSize, SplitKey64(48), SplitKey64(56),
            B.getInt64(0x315254534d564c41ULL)});
  Value *TagDiff = B.CreateOr(B.CreateXor(Stored0, Computed0),
                              B.CreateXor(Stored1, Computed1));
  B.CreateCondBr(B.CreateICmpEQ(TagDiff, B.getInt64(0)), Decrypt, Failure);

  B.SetInsertPoint(Decrypt);
  Value *Ciphertext = bytePtr(B, Record, ALLVM_STR_CIPHERTEXT_OFFSET);
  Value *Nonce = bytePtr(B, Record, ALLVM_STR_NONCE_OFFSET);
  Value *Opened = B.CreateCall(
      Xor, {Out, Ciphertext, ExpectedSize, KeyA, KeyB, Nonce});
  B.CreateCondBr(Opened, Success, Failure);

  B.SetInsertPoint(Success);
  B.CreateRet(B.getInt32(1));

  B.SetInsertPoint(Failure);
  B.CreateMemSet(Out, B.getInt8(0), B.CreateZExt(ExpectedSize, I64), Align(1),
                 true);
  B.CreateRet(B.getInt32(0));
  return F;
}

} // namespace

Function *llvm::allvm::getOrCreateAuthenticatedStringOpen(Module &M) {
  if (Function *Existing = M.getFunction(OpenName))
    return Existing;
  Function *Load32 = createLoad32(M);
  Function *Load64 = createLoad64(M);
  Function *Store32 = createStore32(M);
  Function *Tag = createTag(M, Load64);
  Function *Block = createBlock(M, Load32, Store32);
  Function *Xor = createXor(M, Block);
  return createOpen(M, Load32, Load64, Tag, Xor);
}
