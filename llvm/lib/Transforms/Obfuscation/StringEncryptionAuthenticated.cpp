//===- StringEncryptionAuthenticated.cpp - authenticated string records --===//

#include "llvm/Transforms/Obfuscation/AuthenticatedStringCrypto.h"
#include "llvm/Transforms/Obfuscation/AuthenticatedStringIR.h"
#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/Transforms/Obfuscation/SecureRandom.h"
#include "llvm/Transforms/Obfuscation/StringEncryption.h"
#include "llvm/Transforms/Obfuscation/Utils.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/ValueMapper.h"

#include "llvm/CryptoUtils.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <set>
#include <string>
#include <vector>

#define DEBUG_TYPE "string-encryption"

using namespace llvm;

namespace {

static cl::opt<uint64_t> CSEMaxRecordBytes(
    "irobf-cse-max-record-bytes", cl::init(1024ULL * 1024ULL),
    cl::desc("Maximum authenticated plaintext bytes per string; 0 disables the limit"));
static cl::opt<uint64_t> CSEMaxTableBytes(
    "irobf-cse-max-table-bytes", cl::init(64ULL * 1024ULL * 1024ULL),
    cl::desc("Maximum authenticated encrypted string table bytes; 0 disables the limit"));
static cl::opt<uint64_t> CSESpinLimit(
    "irobf-cse-spin-limit", cl::init(10000000ULL),
    cl::desc("Maximum atomic-once wait iterations per string; 0 disables the limit"));
static cl::opt<bool> CSEStrict(
    "irobf-cse-strict", cl::init(false),
    cl::desc("Fail compilation instead of skipping unsupported string users"));
static cl::opt<bool> CSEWipeAtExit(
    "irobf-cse-wipe-at-exit", cl::init(true),
    cl::desc("Volatile-clear decrypted string buffers when the module unloads"));
static cl::opt<bool> CSEVerifyModule(
    "irobf-cse-verify", cl::init(true),
    cl::desc("Run the LLVM verifier after authenticated string rewriting"));

struct StringEntry {
  unsigned ID = 0;
  uint32_t Offset = 0;
  uint32_t PlainSize = 0;
  uint32_t Flags = 0;
  MaybeAlign Alignment;
  GlobalVariable *Original = nullptr;
  GlobalVariable *PlainGV = nullptr;
  GlobalVariable *StatusGV = nullptr;
  GlobalVariable *KeyShareA = nullptr;
  GlobalVariable *KeyShareB = nullptr;
  Function *DecryptFunction = nullptr;
  SmallPtrSet<Function *, 16> FunctionUsers;
  std::vector<uint8_t> Plaintext;
  std::array<uint8_t, 64> ShareA{};
  std::array<uint8_t, 64> ShareB{};
};

class StringEncryption : public ModulePass {
public:
  static char ID;

  explicit StringEncryption(ObfuscationOptions *Options)
      : ModulePass(ID), ArgsOptions(Options) {
    initializeStringEncryptionPass(*PassRegistry::getPassRegistry());
  }

  bool runOnModule(Module &M) override;
  StringRef getPassName() const override { return "StringEncryption"; }

private:
  ObfuscationOptions *ArgsOptions;
  CryptoUtils LayoutRandom;
  std::vector<std::unique_ptr<StringEntry>> Entries;
  GlobalVariable *EncryptedTable = nullptr;

  bool reject(const Twine &Reason) const;
  bool extractPlaintext(GlobalVariable &GV, std::vector<uint8_t> &Out,
                        uint32_t &Flags) const;
  bool collectFunctionUsers(GlobalVariable &GV,
                            SmallPtrSetImpl<Function *> &Functions) const;
  void fillRandom(CryptoUtils &Engine, MutableArrayRef<uint8_t> Bytes) const;
  void appendRandomJunk(std::vector<uint8_t> &Table, uint32_t Min,
                        uint32_t Max);
  bool buildEncryptedTable(Module &M);
  void createEntryGlobals(Module &M, StringEntry &Entry, Function *Runtime);
  Function *buildDecryptFunction(Module &M, StringEntry &Entry,
                                 Function *Runtime);
  void insertDecryptCalls();
  void remapUses(Module &M);
  void eraseOriginalStrings();
  void buildWipeDestructor(Module &M);
  void clearCompilerSecrets();
};

} // namespace

char StringEncryption::ID = 0;

bool StringEncryption::reject(const Twine &Reason) const {
  if (CSEStrict)
    report_fatal_error(Reason);
  if (isIRObfuscationDebugEnabled())
    errs() << "[CSE] skip: " << Reason << "\n";
  return false;
}

bool StringEncryption::extractPlaintext(GlobalVariable &GV,
                                        std::vector<uint8_t> &Out,
                                        uint32_t &Flags) const {
  if (!GV.isConstant() || !GV.hasInitializer() || !GV.hasLocalLinkage() ||
      GV.isThreadLocal() || GV.getAddressSpace() != 0 || GV.hasComdat() ||
      GV.isExternallyInitialized() || GV.hasSection() ||
      GV.hasDLLExportStorageClass() || GV.isDLLImportDependent() ||
      GV.getName().starts_with("llvm.") ||
      GV.getName().starts_with("__allvm_"))
    return false;

  auto *CDS = dyn_cast<ConstantDataSequential>(GV.getInitializer());
  if (CDS == nullptr || !isa<ArrayType>(GV.getValueType()))
    return false;

  Out.clear();
  Flags = 0;
  if (CDS->isString()) {
    StringRef Bytes = CDS->getRawDataValues();
    Out.assign(Bytes.bytes_begin(), Bytes.bytes_end());
  } else if (CDS->getElementType()->isIntegerTy(16)) {
    Flags = ALLVM_STR_FLAG_UTF16;
    const unsigned Count = CDS->getNumElements();
    Out.reserve(static_cast<size_t>(Count) * 2U);
    for (unsigned I = 0; I < Count; ++I) {
      const uint16_t Word = static_cast<uint16_t>(CDS->getElementAsInteger(I));
      Out.push_back(static_cast<uint8_t>(Word & 0xffU));
      Out.push_back(static_cast<uint8_t>((Word >> 8) & 0xffU));
    }
  } else {
    return false;
  }

  if (Out.empty() || Out.size() > std::numeric_limits<uint32_t>::max())
    return false;
  if (CSEMaxRecordBytes != 0 && Out.size() > CSEMaxRecordBytes)
    return reject(Twine("string '") + GV.getName() + "' has " +
                  Twine(Out.size()) + " bytes, exceeding " +
                  Twine(CSEMaxRecordBytes));
  return true;
}

bool StringEncryption::collectFunctionUsers(
    GlobalVariable &GV, SmallPtrSetImpl<Function *> &Functions) const {
  SmallVector<Value *, 32> Worklist;
  SmallPtrSet<Value *, 64> Visited;
  Worklist.push_back(&GV);

  while (!Worklist.empty()) {
    Value *Current = Worklist.pop_back_val();
    if (!Visited.insert(Current).second)
      continue;

    for (User *U : Current->users()) {
      if (auto *I = dyn_cast<Instruction>(U)) {
        Function *F = I->getFunction();
        if (F == nullptr || F->isDeclaration())
          return reject(Twine("string '") + GV.getName() +
                        "' has an instruction user without a function body");
        const auto Opt = ArgsOptions->toObfuscate(ArgsOptions->cseOpt(), F);
        if (!Opt.isEnabled())
          return reject(Twine("string '") + GV.getName() +
                        "' reaches CSE-disabled function '" + F->getName() +
                        "'");
        Functions.insert(F);
        continue;
      }

      if (auto *Container = dyn_cast<GlobalVariable>(U)) {
        if (Container != &GV && !Container->hasLocalLinkage())
          return reject(Twine("string '") + GV.getName() +
                        "' reaches externally visible global '" +
                        Container->getName() + "'");
        Worklist.push_back(Container);
        continue;
      }

      if (isa<GlobalValue>(U))
        return reject(Twine("string '") + GV.getName() +
                      "' reaches an unsupported global alias or value");

      if (isa<Constant>(U)) {
        Worklist.push_back(U);
        continue;
      }

      return reject(Twine("string '") + GV.getName() +
                    "' has unsupported user kind");
    }
  }
  return !Functions.empty();
}

void StringEncryption::fillRandom(CryptoUtils &Engine,
                                  MutableArrayRef<uint8_t> Bytes) const {
  size_t Offset = 0;
  while (Offset < Bytes.size()) {
    const size_t Remaining = Bytes.size() - Offset;
    const int Chunk = static_cast<int>(std::min<size_t>(
        Remaining, static_cast<size_t>(std::numeric_limits<int>::max())));
    Engine.get_bytes(reinterpret_cast<char *>(Bytes.data() + Offset), Chunk);
    Offset += static_cast<size_t>(Chunk);
  }
}

void StringEncryption::appendRandomJunk(std::vector<uint8_t> &Table,
                                        uint32_t Min, uint32_t Max) {
  assert(Max >= Min);
  uint32_t Count = Min;
  if (Max != Min)
    Count += LayoutRandom.get_range(Max - Min + 1U);
  const size_t OldSize = Table.size();
  Table.resize(OldSize + Count);
  fillRandom(LayoutRandom,
             MutableArrayRef<uint8_t>(Table.data() + OldSize, Count));
}

bool StringEncryption::buildEncryptedTable(Module &M) {
  std::vector<uint8_t> Table;
  Table.reserve(Entries.size() * 96U);

  for (std::unique_ptr<StringEntry> &Owned : Entries) {
    StringEntry &Entry = *Owned;
    appendRandomJunk(Table, 8U, 32U);
    while ((Table.size() & 7U) != 0U)
      appendRandomJunk(Table, 1U, 1U);

    if (Table.size() > std::numeric_limits<uint32_t>::max())
      return reject("authenticated string table offset exceeds 32 bits");
    Entry.Offset = static_cast<uint32_t>(Table.size());
    Entry.PlainSize = static_cast<uint32_t>(Entry.Plaintext.size());

    std::array<uint8_t, 64> Key{};
    std::array<uint8_t, 12> Nonce{};
    CryptoUtils KeyEngine;
    CryptoUtils MaskEngine;
    std::string Suffix = M.getModuleIdentifier();
    Suffix += '|';
    Suffix += std::to_string(Entry.ID);
    std::string KeyDomain = "string-record-key|" + Suffix;
    std::string MaskDomain = "string-record-mask|" + Suffix;
    allvm::seedCryptoUtils(KeyEngine, KeyDomain.c_str());
    allvm::seedCryptoUtils(MaskEngine, MaskDomain.c_str());
    fillRandom(KeyEngine, MutableArrayRef<uint8_t>(Key));
    fillRandom(KeyEngine, MutableArrayRef<uint8_t>(Nonce));
    fillRandom(MaskEngine, MutableArrayRef<uint8_t>(Entry.ShareA));
    for (size_t I = 0; I < Key.size(); ++I)
      Entry.ShareB[I] = static_cast<uint8_t>(Key[I] ^ Entry.ShareA[I]);

    const uint64_t RecordSize =
        static_cast<uint64_t>(ALLVM_STR_HEADER_SIZE) + Entry.PlainSize;
    if (RecordSize > std::numeric_limits<size_t>::max() ||
        RecordSize > std::numeric_limits<size_t>::max() - Table.size() ||
        (CSEMaxTableBytes != 0 &&
         static_cast<uint64_t>(Table.size()) + RecordSize > CSEMaxTableBytes)) {
      allvm::secureClear(Key.data(), Key.size());
      allvm::secureClear(Nonce.data(), Nonce.size());
      return reject(Twine("authenticated string table would exceed ") +
                    Twine(CSEMaxTableBytes) + " bytes");
    }

    const size_t RecordOffset = Table.size();
    Table.resize(RecordOffset + static_cast<size_t>(RecordSize));
    if (!allvm_str_seal_record(
            Table.data() + RecordOffset, RecordSize, Entry.Plaintext.data(),
            Entry.PlainSize, Key.data(), Nonce.data(), Entry.ID, Entry.Offset,
            Entry.Flags)) {
      allvm::secureClear(Key.data(), Key.size());
      allvm::secureClear(Nonce.data(), Nonce.size());
      return reject(Twine("failed to seal authenticated string record ") +
                    Twine(Entry.ID));
    }

    allvm::secureClear(Key.data(), Key.size());
    allvm::secureClear(Nonce.data(), Nonce.size());
    allvm::secureClear(Entry.Plaintext.data(), Entry.Plaintext.size());
    Entry.Plaintext.clear();
    Entry.Plaintext.shrink_to_fit();
  }

  Constant *Init = ConstantDataArray::get(M.getContext(), Table);
  EncryptedTable = new GlobalVariable(
      M, Init->getType(), true, GlobalValue::PrivateLinkage, Init,
      "__allvm_authenticated_string_table");
  EncryptedTable->setDSOLocal(true);
  EncryptedTable->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  EncryptedTable->setAlignment(Align(16));
  EncryptedTable->setMetadata("noobf", MDNode::get(M.getContext(), {}));
  allvm::secureClear(Table.data(), Table.size());
  return true;
}

void StringEncryption::createEntryGlobals(Module &M, StringEntry &Entry,
                                          Function *Runtime) {
  LLVMContext &C = M.getContext();
  const std::string HexID = Twine::utohexstr(Entry.ID);
  Constant *ZeroPlain = Constant::getNullValue(Entry.Original->getValueType());
  Entry.PlainGV = new GlobalVariable(
      M, Entry.Original->getValueType(), false, GlobalValue::PrivateLinkage,
      ZeroPlain, "__allvm_sbuf_" + HexID);
  Entry.PlainGV->setDSOLocal(true);
  if (Entry.Alignment)
    Entry.PlainGV->setAlignment(*Entry.Alignment);
  Entry.PlainGV->setMetadata("noobf", MDNode::get(C, {}));

  Entry.StatusGV = new GlobalVariable(
      M, Type::getInt32Ty(C), false, GlobalValue::PrivateLinkage,
      ConstantInt::get(Type::getInt32Ty(C), 0), "__allvm_sstate_" + HexID);
  Entry.StatusGV->setDSOLocal(true);
  Entry.StatusGV->setAlignment(Align(4));
  Entry.StatusGV->setMetadata("noobf", MDNode::get(C, {}));

  Constant *ShareAInit =
      ConstantDataArray::get(C, ArrayRef<uint8_t>(Entry.ShareA));
  Constant *ShareBInit =
      ConstantDataArray::get(C, ArrayRef<uint8_t>(Entry.ShareB));
  Entry.KeyShareA = new GlobalVariable(
      M, ShareAInit->getType(), true, GlobalValue::PrivateLinkage, ShareAInit,
      "__allvm_ska_" + HexID);
  Entry.KeyShareB = new GlobalVariable(
      M, ShareBInit->getType(), true, GlobalValue::PrivateLinkage, ShareBInit,
      "__allvm_skb_" + HexID);
  for (GlobalVariable *Share : {Entry.KeyShareA, Entry.KeyShareB}) {
    Share->setDSOLocal(true);
    Share->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Share->setAlignment(Align(16));
    Share->setMetadata("noobf", MDNode::get(C, {}));
  }

  Entry.DecryptFunction = buildDecryptFunction(M, Entry, Runtime);
}

Function *StringEncryption::buildDecryptFunction(Module &M, StringEntry &Entry,
                                                  Function *Runtime) {
  LLVMContext &C = M.getContext();
  Function *F = Function::Create(
      FunctionType::get(Type::getVoidTy(C), false),
      GlobalValue::PrivateLinkage,
      "__allvm_string_once_" + Twine::utohexstr(Entry.ID), M);
  F->setDSOLocal(true);
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::OptimizeNone);
  F->addFnAttr(Attribute::NoUnwind);
  F->setMetadata("noobf", MDNode::get(C, {}));

  BasicBlock *EntryBB = BasicBlock::Create(C, "entry", F);
  BasicBlock *TryClaim = BasicBlock::Create(C, "try", F);
  BasicBlock *Owner = BasicBlock::Create(C, "owner", F);
  BasicBlock *Publish = BasicBlock::Create(C, "publish", F);
  BasicBlock *PublishFailure = BasicBlock::Create(C, "publish.failure", F);
  BasicBlock *Wait = BasicBlock::Create(C, "wait", F);
  BasicBlock *WaitClassify = BasicBlock::Create(C, "wait.classify", F);
  BasicBlock *Ready = BasicBlock::Create(C, "ready", F);
  BasicBlock *Failure = BasicBlock::Create(C, "failure", F);

  IRBuilder<> B(EntryBB);
  AllocaInst *Spin = B.CreateAlloca(B.getInt64Ty(), nullptr, "spin");
  Spin->setAlignment(Align(8));
  B.CreateStore(B.getInt64(0), Spin);
  LoadInst *InitialStatus = B.CreateLoad(B.getInt32Ty(), Entry.StatusGV);
  InitialStatus->setAtomic(AtomicOrdering::Acquire);
  InitialStatus->setAlignment(Align(4));
  SwitchInst *InitialSwitch = B.CreateSwitch(InitialStatus, TryClaim, 2);
  InitialSwitch->addCase(B.getInt32(2), Ready);
  InitialSwitch->addCase(B.getInt32(3), Failure);

  B.SetInsertPoint(TryClaim);
  AtomicCmpXchgInst *Claim = B.CreateAtomicCmpXchg(
      Entry.StatusGV, B.getInt32(0), B.getInt32(1), Align(4),
      AtomicOrdering::AcquireRelease, AtomicOrdering::Acquire);
  Claim->setWeak(false);
  Value *Won = B.CreateExtractValue(Claim, 1);
  B.CreateCondBr(Won, Owner, Wait);

  B.SetInsertPoint(Owner);
  Value *Record = B.CreateInBoundsGEP(
      EncryptedTable->getValueType(), EncryptedTable,
      {B.getInt32(0), B.getInt32(Entry.Offset)});
  Value *KeyA = B.CreateInBoundsGEP(
      Entry.KeyShareA->getValueType(), Entry.KeyShareA,
      {B.getInt32(0), B.getInt32(0)});
  Value *KeyB = B.CreateInBoundsGEP(
      Entry.KeyShareB->getValueType(), Entry.KeyShareB,
      {B.getInt32(0), B.getInt32(0)});
  const uint64_t RecordSize =
      static_cast<uint64_t>(ALLVM_STR_HEADER_SIZE) + Entry.PlainSize;
  CallInst *Open = B.CreateCall(
      Runtime,
      {Entry.PlainGV, Record, B.getInt64(RecordSize), KeyA, KeyB,
       B.getInt32(Entry.ID), B.getInt32(Entry.Offset),
       B.getInt32(Entry.Flags), B.getInt32(Entry.PlainSize)});
  Open->setDoesNotThrow();
  B.CreateCondBr(B.CreateICmpNE(Open, B.getInt32(0)), Publish,
                 PublishFailure);

  B.SetInsertPoint(Publish);
  StoreInst *PublishStore = B.CreateStore(B.getInt32(2), Entry.StatusGV);
  PublishStore->setAtomic(AtomicOrdering::Release);
  PublishStore->setAlignment(Align(4));
  B.CreateBr(Ready);

  B.SetInsertPoint(PublishFailure);
  StoreInst *FailureStore = B.CreateStore(B.getInt32(3), Entry.StatusGV);
  FailureStore->setAtomic(AtomicOrdering::Release);
  FailureStore->setAlignment(Align(4));
  B.CreateBr(Failure);

  B.SetInsertPoint(Wait);
  Value *OldSpin = B.CreateLoad(B.getInt64Ty(), Spin);
  Value *NewSpin = B.CreateAdd(OldSpin, B.getInt64(1));
  B.CreateStore(NewSpin, Spin);
  if (CSESpinLimit != 0) {
    B.CreateCondBr(
        B.CreateICmpUGT(NewSpin,
                        B.getInt64(static_cast<uint64_t>(CSESpinLimit))),
        Failure, WaitClassify);
  } else {
    B.CreateBr(WaitClassify);
  }

  B.SetInsertPoint(WaitClassify);
  LoadInst *WaitStatus = B.CreateLoad(B.getInt32Ty(), Entry.StatusGV);
  WaitStatus->setAtomic(AtomicOrdering::Acquire);
  WaitStatus->setAlignment(Align(4));
  SwitchInst *WaitSwitch = B.CreateSwitch(WaitStatus, Failure, 3);
  WaitSwitch->addCase(B.getInt32(0), TryClaim);
  WaitSwitch->addCase(B.getInt32(1), Wait);
  WaitSwitch->addCase(B.getInt32(2), Ready);

  B.SetInsertPoint(Ready);
  B.CreateRetVoid();

  B.SetInsertPoint(Failure);
  Function *Trap = Intrinsic::getDeclaration(&M, Intrinsic::trap);
  B.CreateCall(Trap);
  B.CreateUnreachable();
  return F;
}

void StringEncryption::insertDecryptCalls() {
  std::set<std::pair<Function *, unsigned>> Inserted;
  for (const std::unique_ptr<StringEntry> &Owned : Entries) {
    StringEntry &Entry = *Owned;
    for (Function *F : Entry.FunctionUsers) {
      if (!Inserted.emplace(F, Entry.ID).second)
        continue;
      IRBuilder<> B(F->getContext());
      B.SetInsertPointPastAllocas(F);
      CallInst *Call = B.CreateCall(Entry.DecryptFunction);
      Call->setDoesNotThrow();
      Call->setMetadata("noobf", MDNode::get(F->getContext(), {}));
    }
  }
}

void StringEncryption::remapUses(Module &M) {
  ValueToValueMapTy VMap;
  for (const std::unique_ptr<StringEntry> &Owned : Entries)
    VMap[Owned->Original] = Owned->PlainGV;

  for (GlobalVariable &GV : M.globals()) {
    if (!GV.hasInitializer() || VMap.count(&GV) != 0)
      continue;
    Constant *Old = GV.getInitializer();
    Constant *Mapped = MapValue(Old, VMap, RF_IgnoreMissingLocals);
    if (Mapped != Old)
      GV.setInitializer(Mapped);
  }

  for (Function &F : M) {
    for (Instruction &I : instructions(F))
      RemapInstruction(&I, VMap,
                       RF_IgnoreMissingLocals | RF_DoNotRemapAtoms);
  }
}

void StringEncryption::eraseOriginalStrings() {
  for (const std::unique_ptr<StringEntry> &Owned : Entries) {
    GlobalVariable *GV = Owned->Original;
    GV->removeDeadConstantUsers();
    if (!GV->use_empty())
      report_fatal_error(Twine("authenticated string rewrite left uses of '") +
                         GV->getName() + "'");
    GV->eraseFromParent();
  }
}

void StringEncryption::buildWipeDestructor(Module &M) {
  if (!CSEWipeAtExit || Entries.empty())
    return;
  LLVMContext &C = M.getContext();
  Function *Dtor = Function::Create(
      FunctionType::get(Type::getVoidTy(C), false),
      GlobalValue::PrivateLinkage, "__allvm_wipe_decrypted_strings", M);
  Dtor->setDSOLocal(true);
  Dtor->addFnAttr(Attribute::NoInline);
  Dtor->addFnAttr(Attribute::OptimizeNone);
  Dtor->addFnAttr(Attribute::NoUnwind);
  Dtor->setMetadata("noobf", MDNode::get(C, {}));
  IRBuilder<> B(BasicBlock::Create(C, "entry", Dtor));
  for (const std::unique_ptr<StringEntry> &Owned : Entries) {
    StringEntry &Entry = *Owned;
    B.CreateMemSet(Entry.PlainGV, B.getInt8(0), Entry.PlainSize,
                   Entry.Alignment ? Entry.Alignment : MaybeAlign(1), true);
    StoreInst *Reset = B.CreateStore(B.getInt32(0), Entry.StatusGV, true);
    Reset->setAtomic(AtomicOrdering::Release);
    Reset->setAlignment(Align(4));
  }
  B.CreateRetVoid();
  appendToGlobalDtors(M, Dtor, 65535);
}

void StringEncryption::clearCompilerSecrets() {
  for (std::unique_ptr<StringEntry> &Owned : Entries) {
    allvm::secureClear(Owned->Plaintext.data(), Owned->Plaintext.size());
    allvm::secureClear(Owned->ShareA.data(), Owned->ShareA.size());
    allvm::secureClear(Owned->ShareB.data(), Owned->ShareB.size());
  }
}

bool StringEncryption::runOnModule(Module &M) {
  if (!isLicenseValidated())
    return false;
  if (!M.getDataLayout().isLittleEndian())
    return reject(
        "authenticated string records currently require a little-endian target");

  Entries.clear();
  EncryptedTable = nullptr;
  std::string LayoutDomain = "string-record-layout|";
  LayoutDomain += M.getModuleIdentifier();
  allvm::seedCryptoUtils(LayoutRandom, LayoutDomain.c_str());

  SmallVector<GlobalVariable *, 32> Candidates;
  for (GlobalVariable &GV : M.globals())
    Candidates.push_back(&GV);

  for (GlobalVariable *GV : Candidates) {
    auto Entry = std::make_unique<StringEntry>();
    Entry->Original = GV;
    Entry->Alignment = MaybeAlign(GV->getAlignment());
    if (!extractPlaintext(*GV, Entry->Plaintext, Entry->Flags))
      continue;
    if (!collectFunctionUsers(*GV, Entry->FunctionUsers)) {
      allvm::secureClear(Entry->Plaintext.data(), Entry->Plaintext.size());
      continue;
    }
    Entry->ID = static_cast<unsigned>(Entries.size());
    Entries.push_back(std::move(Entry));
  }

  if (Entries.empty())
    return false;
  if (!buildEncryptedTable(M)) {
    clearCompilerSecrets();
    return false;
  }

  Function *Runtime = allvm::getOrCreateAuthenticatedStringOpen(M);
  for (std::unique_ptr<StringEntry> &Owned : Entries)
    createEntryGlobals(M, *Owned, Runtime);

  insertDecryptCalls();
  remapUses(M);
  eraseOriginalStrings();
  buildWipeDestructor(M);
  clearCompilerSecrets();

  if (CSEVerifyModule && verifyModule(M, &errs()))
    report_fatal_error(
        "authenticated string encryption produced invalid LLVM IR");

  if (isIRObfuscationDebugEnabled())
    errs() << "[CSE] authenticated " << Entries.size()
           << " string records\n";
  return true;
}

ModulePass *llvm::createStringEncryptionPass(ObfuscationOptions *Options) {
  return new StringEncryption(Options);
}

INITIALIZE_PASS(StringEncryption, "string-encryption",
                "Enable authenticated IR string encryption", false, false)
