//===- string-poly1305-runtime-ir-smoke.cpp - execute record-v2 runtime --===//

#include "llvm/Transforms/Obfuscation/AuthenticatedStringPoly1305Crypto.h"
#include "llvm/Transforms/Obfuscation/AuthenticatedStringIR.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

#include <array>
#include <cstdint>
#include <system_error>

using namespace llvm;

static GlobalVariable *bytesGlobal(Module &M, StringRef Name,
                                   ArrayRef<uint8_t> Bytes, bool IsConstant) {
  Constant *Init = ConstantDataArray::get(M.getContext(), Bytes);
  auto *GV = new GlobalVariable(M, Init->getType(), IsConstant,
                                GlobalValue::PrivateLinkage, Init, Name);
  GV->setAlignment(Align(16));
  return GV;
}

static Value *firstByte(IRBuilder<> &B, GlobalVariable *GV) {
  return B.CreateInBoundsGEP(GV->getValueType(), GV,
                             {B.getInt32(0), B.getInt32(0)});
}

int main(int argc, char **argv) {
  if (argc != 2)
    return 2;

  std::array<uint8_t, 64> Root{};
  std::array<uint8_t, 64> ShareA{};
  std::array<uint8_t, 64> ShareB{};
  std::array<uint8_t, 12> Nonce{};
  std::array<uint8_t, 80> Plain{};
  std::array<uint8_t, 128> ValidRecord{};
  for (unsigned I = 0; I < Root.size(); ++I) {
    Root[I] = static_cast<uint8_t>(I);
    ShareA[I] = static_cast<uint8_t>(I * 7U + 3U);
    ShareB[I] = static_cast<uint8_t>(Root[I] ^ ShareA[I]);
  }
  for (unsigned I = 0; I < Nonce.size(); ++I)
    Nonce[I] = static_cast<uint8_t>(0xa0U + I);
  for (unsigned I = 0; I < Plain.size(); ++I)
    Plain[I] = static_cast<uint8_t>(I * 3U + 1U);
  if (!allvm_str_seal_record(
          ValidRecord.data(), ValidRecord.size(), Plain.data(), 80U,
          Root.data(), Nonce.data(), 7U, 19U, 0U))
    return 3;
  std::array<uint8_t, 128> TamperedRecord = ValidRecord;
  TamperedRecord[60] ^= 1U;
  std::array<uint8_t, 80> Zero{};

  LLVMContext C;
  Module M("poly1305-string-runtime-smoke", C);
  Function *Open = allvm::getOrCreateAuthenticatedStringOpen(M);
  GlobalVariable *Valid = bytesGlobal(M, "valid", ValidRecord, true);
  GlobalVariable *Tampered = bytesGlobal(M, "tampered", TamperedRecord, true);
  GlobalVariable *A = bytesGlobal(M, "share_a", ShareA, true);
  GlobalVariable *BShare = bytesGlobal(M, "share_b", ShareB, true);
  GlobalVariable *Out = bytesGlobal(M, "out", Zero, false);
  GlobalVariable *OutTampered = bytesGlobal(M, "out_tampered", Zero, false);

  Function *Main = Function::Create(
      FunctionType::get(Type::getInt32Ty(C), false),
      GlobalValue::ExternalLinkage, "main", M);
  IRBuilder<> IRB(BasicBlock::Create(C, "entry", Main));
  Value *Opened = IRB.CreateCall(
      Open, {firstByte(IRB, Out), firstByte(IRB, Valid), IRB.getInt64(128),
             firstByte(IRB, A), firstByte(IRB, BShare), IRB.getInt32(7),
             IRB.getInt32(19), IRB.getInt32(0), IRB.getInt32(80)});
  Value *Rejected = IRB.CreateCall(
      Open, {firstByte(IRB, OutTampered), firstByte(IRB, Tampered),
             IRB.getInt64(128), firstByte(IRB, A), firstByte(IRB, BShare),
             IRB.getInt32(7), IRB.getInt32(19), IRB.getInt32(0),
             IRB.getInt32(80)});

  LoadInst *First = IRB.CreateLoad(IRB.getInt8Ty(), firstByte(IRB, Out));
  Value *LastPtr = IRB.CreateInBoundsGEP(
      Out->getValueType(), Out, {IRB.getInt32(0), IRB.getInt32(79)});
  LoadInst *Last = IRB.CreateLoad(IRB.getInt8Ty(), LastPtr);
  LoadInst *TamperedFirst =
      IRB.CreateLoad(IRB.getInt8Ty(), firstByte(IRB, OutTampered));
  Value *OK = IRB.CreateAnd(
      IRB.CreateAnd(IRB.CreateICmpEQ(Opened, IRB.getInt32(1)),
                    IRB.CreateICmpEQ(Rejected, IRB.getInt32(0))),
      IRB.CreateAnd(
          IRB.CreateICmpEQ(First, IRB.getInt8(Plain.front())),
          IRB.CreateAnd(IRB.CreateICmpEQ(Last, IRB.getInt8(Plain.back())),
                        IRB.CreateICmpEQ(TamperedFirst, IRB.getInt8(0)))));
  IRB.CreateRet(IRB.CreateSelect(OK, IRB.getInt32(0), IRB.getInt32(1)));

  if (verifyModule(M, &errs()))
    return 4;
  std::error_code EC;
  raw_fd_ostream OS(argv[1], EC, sys::fs::OF_None);
  if (EC)
    return 5;
  WriteBitcodeToFile(M, OS);
  OS.flush();
  return 0;
}
