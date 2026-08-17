//===- StringEncryption.cpp - authenticated string records ---------------===//

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
#include "llvm/ADT/StringExtras.h"
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
static cl::opt<bool> CSEStrict(
    "irobf-cse-strict", cl::init(false),
    cl::desc("Fail compilation instead of skipping unsupported string users"));
static cl::opt<bool> CSEWipeAtExit(
    "irobf-cse-wipe-at-exit", cl::init(true),
    cl::desc("Volatile-clear decrypted string buffers after ordinary destructors"));
static cl::opt<bool> CSEVerifyModule(
    "irobf-cse-verify", cl::init(true),
    cl::desc("Run the LLVM verifier after authenticated string rewriting"));

struct StringRecord {
  unsigned ID = 0;
  uint32_t Offset = 0;
  uint32_t PlainSize = 0;
  uint32_t Flags = 0;
  MaybeAlign Alignment;
  GlobalVariable *Original = nullptr;
  GlobalVariable *PlainGV = nullptr;
  GlobalVariable *KeyShareA = nullptr;
  GlobalVariable *KeyShareB = nullptr;
  SmallPtrSet<Function *, 16> FunctionUsers;
  std::vector<uint8_t> Plaintext;
  std::array<uint8_t, 64> ShareA{};
  std::array<uint8_t, 64> ShareB{};
};

class AuthenticatedStringEncryption final : public ModulePass {
public:
  static char ID;

  explicit AuthenticatedStringEncryption(ObfuscationOptions *Options)
      : ModulePass(ID), ArgsOptions(Options) {
    initializeStringEncryptionPass(*PassRegistry::getPassRegistry());
  }

  // The custom pass manager executes module passes before function passes.
  // Delay string rewriting until finalization so the cryptographic runtime is
  // never flattened, indirected, virtualized, or constant-rewritten.
  bool runOnModule(Module &) override { return false; }
  bool doFinalization(Module &M) override { return runAuthenticated(M); }
  StringRef getPassName() const override {
    return "AuthenticatedStringEncryption";
  }

private:
  ObfuscationOptions *ArgsOptions;
  CryptoUtils LayoutRandom;
  std::vector<std::unique_ptr<StringRecord>> Records;
  GlobalVariable *EncryptedTable = nullptr;

  bool reject(const Twine &Reason) const;
  bool extractPlaintext(GlobalVariable &GV, std::vector<uint8_t> &Out,
                        uint32_t &Flags) const;
  bool collectFunctionUsers(GlobalVariable &GV,
                            SmallPtrSetImpl<Function *> &Functions) const;
  void fillRandom(CryptoUtils &Engine, MutableArrayRef<uint8_t> Bytes) const;
  void appendRandomJunk(std::vector<uint8_t> &Table, uint32_t Min,
                        uint32_t Max);
  std::string recordFingerprint(ArrayRef<uint8_t> Plaintext) const;
  bool buildEncryptedTable(Module &M);
  void createRecordGlobals(Module &M, StringRecord &Record);
  void buildDecryptConstructor(Module &M, Function *Runtime);
  void remapUses(Module &M);
  void eraseOriginalStrings();
  void buildWipeDestructor(Module &M);
  void clearCompilerSecrets();
  bool runAuthenticated(Module &M);
};

} // namespace

char AuthenticatedStringEncryption::ID = 0;

bool AuthenticatedStringEncryption::reject(const Twine &Reason) const {
  if (CSEStrict)
    report_fatal_error(Reason);
  if (isIRObfuscationDebugEnabled())
    errs() << "[CSE] skip: " << Reason << "\n";
  return false;
}

bool AuthenticatedStringEncryption::extractPlaintext(
    GlobalVariable &GV, std::vector<uint8_t> &Out, uint32_t &Flags) const {
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
    Out.assign(Bytes.begin(), Bytes.end());
  } else if (CDS->getElementType()->isIntegerTy(16)) {
    Flags = ALLVM_STR_FLAG_UTF16;
    const unsigned Count = CDS->getNumElements();
    if (Count > std::numeric_limits<uint32_t>::max() / 2U)
      return reject(Twine("UTF-16 string '") + GV.getName() +
                    "' exceeds the 32-bit record format");
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

bool AuthenticatedStringEncryption::collectFunctionUsers(
    GlobalVariable &GV, SmallPtrSetImpl<Function *> &Functions) const {
  SmallVector<Value *, 32> Worklist;
  SmallPtrSet<Value *, 32> Visited;
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
                      "' reaches an unsupported alias or global value");
      if (isa<Constant>(U)) {
        Worklist.push_back(U);
        continue;
      }
      return reject(Twine("string '") + GV.getName() +
                    "' has an unsupported user kind");
    }
  }
  return !Functions.empty();
}

void AuthenticatedStringEncryption::fillRandom(
    CryptoUtils &Engine, MutableArrayRef<uint8_t> Bytes) const {
  size_t Offset = 0;
  while (Offset < Bytes.size()) {
    const size_t Remaining = Bytes.size() - Offset;
    const int Chunk = static_cast<int>(std::min<size_t>(
        Remaining, static_cast<size_t>(std::numeric_limits<int>::max())));
    Engine.get_bytes(reinterpret_cast<char *>(Bytes.data() + Offset), Chunk);
    Offset += static_cast<size_t>(Chunk);
  }
}

void AuthenticatedStringEncryption::appendRandomJunk(
    std::vector<uint8_t> &Table, uint32_t Min, uint32_t Max) {
  uint32_t Count = Min;
  if (Max != Min)
    Count += LayoutRandom.get_range(Max - Min + 1U);
  const size_t OldSize = Table.size();
  Table.resize(OldSize + Count);
  fillRandom(LayoutRandom,
             MutableArrayRef<uint8_t>(Table.data() + OldSize, Count));
}

std::string AuthenticatedStringEncryption::recordFingerprint(
    ArrayRef<uint8_t> Plaintext) const {
  allvm_str_sip_state First;
  allvm_str_sip_state Second;
  allvm_str_sip_init(&First, 0x243f6a8885a308d3ULL,
                     0x13198a2e03707344ULL);
  allvm_str_sip_init(&Second, 0xa4093822299f31d0ULL,
                     0x082efa98ec4e6c89ULL);
  allvm_str_sip_update(&First, Plaintext.data(), Plaintext.size());
  allvm_str_sip_update(&Second, Plaintext.data(), Plaintext.size());
  return utohexstr(allvm_str_sip_final(&First)) +
         utohexstr(allvm_str_sip_final(&Second));
}

bool AuthenticatedStringEncryption::buildEncryptedTable(Module &M) {
  std::vector<uint8_t> Table;
  Table.reserve(Records.size() * 96U);

  for (std::unique_ptr<StringRecord> &Owned : Records) {
    StringRecord &Record = *Owned;
    appendRandomJunk(Table, 8U, 32U);
    while ((Table.size() & 7U) != 0U)
      appendRandomJunk(Table, 1U, 1U);

    if (Table.size() > std::numeric_limits<uint32_t>::max())
      return reject("authenticated string table offset exceeds 32 bits");
    Record.Offset = static_cast<uint32_t>(Table.size());
    Record.PlainSize = static_cast<uint32_t>(Record.Plaintext.size());

    const std::string Fingerprint = recordFingerprint(Record.Plaintext);
    std::string Suffix = M.getModuleIdentifier();
    Suffix += '|';
    Suffix += Record.Original->getName().str();
    Suffix += '|';
    Suffix += std::to_string(Record.ID);
    Suffix += '|';
    Suffix += std::to_string(Record.Flags);
    Suffix += '|';
    Suffix += Fingerprint;

    std::array<uint8_t, 64> Key{};
    std::array<uint8_t, 12> Nonce{};
    CryptoUtils KeyEngine;
    CryptoUtils MaskEngine;
    std::string KeyDomain = "string-record-key|" + Suffix;
    std::string MaskDomain = "string-record-mask|" + Suffix;
    allvm::seedCryptoUtils(KeyEngine, KeyDomain.c_str());
    allvm::seedCryptoUtils(MaskEngine, MaskDomain.c_str());
    fillRandom(KeyEngine, MutableArrayRef<uint8_t>(Key));
    fillRandom(KeyEngine, MutableArrayRef<uint8_t>(Nonce));
    fillRandom(MaskEngine, MutableArrayRef<uint8_t>(Record.ShareA));
    for (size_t I = 0; I < Key.size(); ++I)
      Record.ShareB[I] = static_cast<uint8_t>(Key[I] ^ Record.ShareA[I]);

    const uint64_t RecordSize =
        static_cast<uint64_t>(ALLVM_STR_HEADER_SIZE) + Record.PlainSize;
    const bool SizeOverflow =
        RecordSize > std::numeric_limits<size_t>::max() ||
        RecordSize > std::numeric_limits<size_t>::max() - Table.size();
    const bool LimitExceeded =
        CSEMaxTableBytes != 0 &&
        static_cast<uint64_t>(Table.size()) + RecordSize > CSEMaxTableBytes;
    if (SizeOverflow || LimitExceeded) {
      allvm::secureClear(Key.data(), Key.size());
      allvm::secureClear(Nonce.data(), Nonce.size());
      return reject(
          "authenticated string table exceeds its configured or addressable size");
    }

    const size_t RecordOffset = Table.size();
    Table.resize(RecordOffset + static_cast<size_t>(RecordSize));
    if (!allvm_str_seal_record(
            Table.data() + RecordOffset, RecordSize, Record.Plaintext.data(),
            Record.PlainSize, Key.data(), Nonce.data(), Record.ID,
            Record.Offset, Record.Flags)) {
      allvm::secureClear(Key.data(), Key.size());
      allvm::secureClear(Nonce.data(), Nonce.size());
      return reject(Twine("failed to seal authenticated string record ") +
                    Twine(Record.ID));
    }

    allvm::secureClear(Key.data(), Key.size());
    allvm::secureClear(Nonce.data(), Nonce.size());
    allvm::secureClear(Record.Plaintext.data(), Record.Plaintext.size());
    Record.Plaintext.clear();
    Record.Plaintext.shrink_to_fit();
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

void AuthenticatedStringEncryption::createRecordGlobals(
    Module &M, StringRecord &Record) {
  LLVMContext &C = M.getContext();
  const std::string HexID = utohexstr(Record.ID);
  Constant *ZeroPlain = Constant::getNullValue(Record.Original->getValueType());
  Record.PlainGV = new GlobalVariable(
      M, Record.Original->getValueType(), false, GlobalValue::PrivateLinkage,
      ZeroPlain, "__allvm_sbuf_" + HexID);
  Record.PlainGV->setDSOLocal(true);
  if (Record.Alignment)
    Record.PlainGV->setAlignment(*Record.Alignment);
  Record.PlainGV->setMetadata("noobf", MDNode::get(C, {}));

  Constant *ShareAInit = ConstantDataArray::get(
      C, ArrayRef<uint8_t>(Record.ShareA.data(), Record.ShareA.size()));
  Constant *ShareBInit = ConstantDataArray::get(
      C, ArrayRef<uint8_t>(Record.ShareB.data(), Record.ShareB.size()));
  Record.KeyShareA = new GlobalVariable(
      M, ShareAInit->getType(), true, GlobalValue::PrivateLinkage, ShareAInit,
      "__allvm_ska_" + HexID);
  Record.KeyShareB = new GlobalVariable(
      M, ShareBInit->getType(), true, GlobalValue::PrivateLinkage, ShareBInit,
      "__allvm_skb_" + HexID);
  for (GlobalVariable *Share : {Record.KeyShareA, Record.KeyShareB}) {
    Share->setDSOLocal(true);
    Share->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Share->setAlignment(Align(16));
    Share->setMetadata("noobf", MDNode::get(C, {}));
  }
}

void AuthenticatedStringEncryption::buildDecryptConstructor(
    Module &M, Function *Runtime) {
  LLVMContext &C = M.getContext();
  Function *Ctor = Function::Create(
      FunctionType::get(Type::getVoidTy(C), false),
      GlobalValue::PrivateLinkage, "__allvm_open_authenticated_strings", M);
  Ctor->setDSOLocal(true);
  Ctor->addFnAttr(Attribute::NoInline);
  Ctor->addFnAttr(Attribute::OptimizeNone);
  Ctor->addFnAttr(Attribute::NoUnwind);
  Ctor->setMetadata("noobf", MDNode::get(C, {}));

  BasicBlock *Current = BasicBlock::Create(C, "entry", Ctor);
  BasicBlock *Failure = BasicBlock::Create(C, "failure", Ctor);
  IRBuilder<> B(Current);

  for (const std::unique_ptr<StringRecord> &Owned : Records) {
    StringRecord &RecordInfo = *Owned;
    Value *RecordPtr = B.CreateInBoundsGEP(
        EncryptedTable->getValueType(), EncryptedTable,
        {B.getInt32(0), B.getInt32(RecordInfo.Offset)});
    Value *KeyA = B.CreateInBoundsGEP(
        RecordInfo.KeyShareA->getValueType(), RecordInfo.KeyShareA,
        {B.getInt32(0), B.getInt32(0)});
    Value *KeyB = B.CreateInBoundsGEP(
        RecordInfo.KeyShareB->getValueType(), RecordInfo.KeyShareB,
        {B.getInt32(0), B.getInt32(0)});
    const uint64_t RecordSize =
        static_cast<uint64_t>(ALLVM_STR_HEADER_SIZE) + RecordInfo.PlainSize;
    CallInst *Open = B.CreateCall(
        Runtime,
        {RecordInfo.PlainGV, RecordPtr, B.getInt64(RecordSize), KeyA, KeyB,
         B.getInt32(RecordInfo.ID), B.getInt32(RecordInfo.Offset),
         B.getInt32(RecordInfo.Flags), B.getInt32(RecordInfo.PlainSize)});
    Open->setDoesNotThrow();
    BasicBlock *Next = BasicBlock::Create(
        C, "record." + Twine(RecordInfo.ID), Ctor, Failure);
    B.CreateCondBr(B.CreateICmpNE(Open, B.getInt32(0)), Next, Failure);
    B.SetInsertPoint(Next);
  }
  B.CreateRetVoid();

  B.SetInsertPoint(Failure);
  B.CreateCall(Intrinsic::getDeclaration(&M, Intrinsic::trap));
  B.CreateUnreachable();

  // Lower priority values execute before ordinary C++ global constructors.
  appendToGlobalCtors(M, Ctor, 0);
}

void AuthenticatedStringEncryption::remapUses(Module &M) {
  ValueToValueMapTy VMap;
  for (const std::unique_ptr<StringRecord> &Owned : Records)
    VMap[Owned->Original] = Owned->PlainGV;

  for (GlobalVariable &GV : M.globals()) {
    if (!GV.hasInitializer() || VMap.count(&GV) != 0)
      continue;
    Constant *Old = GV.getInitializer();
    Constant *Mapped = MapValue(Old, VMap, RF_IgnoreMissingLocals);
    if (Mapped != Old)
      GV.setInitializer(Mapped);
  }

  for (Function &F : M)
    for (Instruction &I : instructions(F))
      RemapInstruction(&I, VMap, RF_IgnoreMissingLocals);
}

void AuthenticatedStringEncryption::eraseOriginalStrings() {
  for (const std::unique_ptr<StringRecord> &Owned : Records) {
    GlobalVariable *GV = Owned->Original;
    GV->removeDeadConstantUsers();
    if (!GV->use_empty())
      report_fatal_error(Twine("authenticated string rewrite left uses of '") +
                         GV->getName() + "'");
    GV->eraseFromParent();
  }
}

void AuthenticatedStringEncryption::buildWipeDestructor(Module &M) {
  if (!CSEWipeAtExit || Records.empty())
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
  for (const std::unique_ptr<StringRecord> &Owned : Records) {
    const StringRecord &Record = *Owned;
    B.CreateMemSet(Record.PlainGV, B.getInt8(0), Record.PlainSize,
                   Record.Alignment ? Record.Alignment : MaybeAlign(1), true);
  }
  B.CreateRetVoid();
  // Destructors run in reverse priority order; zero runs after ordinary 65535.
  appendToGlobalDtors(M, Dtor, 0);
}

void AuthenticatedStringEncryption::clearCompilerSecrets() {
  for (std::unique_ptr<StringRecord> &Owned : Records) {
    allvm::secureClear(Owned->Plaintext.data(), Owned->Plaintext.size());
    allvm::secureClear(Owned->ShareA.data(), Owned->ShareA.size());
    allvm::secureClear(Owned->ShareB.data(), Owned->ShareB.size());
  }
}

bool AuthenticatedStringEncryption::runAuthenticated(Module &M) {
  if (!isLicenseValidated())
    return false;
  if (!M.getDataLayout().isLittleEndian())
    return reject(
        "authenticated string records currently require a little-endian target");

  Records.clear();
  EncryptedTable = nullptr;
  std::string LayoutDomain = "string-record-layout|";
  LayoutDomain += M.getModuleIdentifier();
  allvm::seedCryptoUtils(LayoutRandom, LayoutDomain.c_str());

  SmallVector<GlobalVariable *, 32> Candidates;
  for (GlobalVariable &GV : M.globals())
    Candidates.push_back(&GV);

  for (GlobalVariable *GV : Candidates) {
    auto Record = std::make_unique<StringRecord>();
    Record->Original = GV;
    Record->Alignment = GV->getAlign();
    if (!extractPlaintext(*GV, Record->Plaintext, Record->Flags))
      continue;
    if (!collectFunctionUsers(*GV, Record->FunctionUsers)) {
      allvm::secureClear(Record->Plaintext.data(), Record->Plaintext.size());
      continue;
    }
    Record->ID = static_cast<unsigned>(Records.size());
    Records.push_back(std::move(Record));
  }

  if (Records.empty())
    return false;
  if (!buildEncryptedTable(M)) {
    clearCompilerSecrets();
    return false;
  }

  for (std::unique_ptr<StringRecord> &Owned : Records)
    createRecordGlobals(M, *Owned);
  Function *Runtime = allvm::getOrCreateAuthenticatedStringOpen(M);
  buildDecryptConstructor(M, Runtime);
  remapUses(M);
  eraseOriginalStrings();
  buildWipeDestructor(M);
  clearCompilerSecrets();

  if (CSEVerifyModule && verifyModule(M, &errs()))
    report_fatal_error(
        "authenticated string encryption produced invalid LLVM IR");
  if (isIRObfuscationDebugEnabled())
    errs() << "[CSE] authenticated " << Records.size()
           << " string records\n";
  return true;
}

ModulePass *llvm::createStringEncryptionPass(ObfuscationOptions *Options) {
  return new AuthenticatedStringEncryption(Options);
}

INITIALIZE_PASS(AuthenticatedStringEncryption, "string-encryption",
                "Enable authenticated IR string encryption", false, false)
