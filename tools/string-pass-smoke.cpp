//===- string-pass-smoke.cpp - complete authenticated string pass test ----===//

#include "llvm/Transforms/Obfuscation/LicenseManager.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/Transforms/Obfuscation/StringEncryption.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

#include <memory>
#include <string>
#include <system_error>

using namespace llvm;

// The full compiler defines this in ObfuscationPassManager.cpp. The standalone
// integration test keeps debug logging disabled without linking every unrelated
// protection pass.
bool llvm::isIRObfuscationDebugEnabled() { return false; }

static bool containsPlaintext(const GlobalVariable &GV, StringRef Plaintext) {
  if (!GV.hasInitializer())
    return false;
  const auto *CDS = dyn_cast<ConstantDataSequential>(GV.getInitializer());
  return CDS != nullptr && CDS->getRawDataValues().contains(Plaintext);
}

int main(int argc, char **argv) {
  if (argc != 2)
    return 2;

  LLVMContext C;
  Module M("authenticated-string-pass-smoke", C);
  M.setTargetTriple("x86_64-unknown-linux-gnu");
  M.setDataLayout("e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128");

  Constant *HelloInit = ConstantDataArray::getString(C, "hello", true);
  auto *Hello = new GlobalVariable(
      M, HelloInit->getType(), true, GlobalValue::PrivateLinkage, HelloInit,
      ".plain.hello");
  Hello->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  Hello->setAlignment(Align(1));

  Function *Main = Function::Create(
      FunctionType::get(Type::getInt32Ty(C), false),
      GlobalValue::ExternalLinkage, "main", M);
  IRBuilder<> B(BasicBlock::Create(C, "entry", Main));
  Value *FirstPtr = B.CreateInBoundsGEP(
      Hello->getValueType(), Hello, {B.getInt32(0), B.getInt32(0)});
  Value *LastPtr = B.CreateInBoundsGEP(
      Hello->getValueType(), Hello, {B.getInt32(0), B.getInt32(4)});
  Value *NullPtr = B.CreateInBoundsGEP(
      Hello->getValueType(), Hello, {B.getInt32(0), B.getInt32(5)});
  Value *First = B.CreateLoad(B.getInt8Ty(), FirstPtr);
  Value *Last = B.CreateLoad(B.getInt8Ty(), LastPtr);
  Value *Terminator = B.CreateLoad(B.getInt8Ty(), NullPtr);
  Value *OK = B.CreateAnd(
      B.CreateICmpEQ(First, B.getInt8('h')),
      B.CreateAnd(B.CreateICmpEQ(Last, B.getInt8('o')),
                  B.CreateICmpEQ(Terminator, B.getInt8(0))));
  B.CreateRet(B.CreateSelect(OK, B.getInt32(0), B.getInt32(1)));

  ObfuscationOptions Options;
  Options.cseOpt()->setEnable(true);
  if (!validateLicense("standalone-test"))
    return 3;

  std::unique_ptr<ModulePass> Pass(createStringEncryptionPass(&Options));
  if (Pass->runOnModule(M))
    return 4;
  if (!Pass->doFinalization(M))
    return 5;

  if (M.getNamedGlobal(".plain.hello") != nullptr)
    return 6;
  GlobalVariable *Table = M.getNamedGlobal("__allvm_authenticated_string_table");
  if (Table == nullptr || containsPlaintext(*Table, "hello"))
    return 7;
  if (M.getFunction("__allvm_open_authenticated_strings") == nullptr ||
      M.getFunction("__allvm_string_open_v1") == nullptr ||
      M.getNamedGlobal("llvm.global_ctors") == nullptr)
    return 8;
  if (verifyModule(M, &errs()))
    return 9;

  std::error_code EC;
  raw_fd_ostream OS(argv[1], EC, sys::fs::OF_None);
  if (EC)
    return 10;
  WriteBitcodeToFile(M, OS);
  OS.flush();
  return 0;
}
