//===- aVMP.cpp - 虚拟机保护混淆Pass ---------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/InlineCost.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/ValueHandle.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Obfuscation/ObfuscationPassManager.h"
#include "llvm/Transforms/Obfuscation/SecureRandom.h"
#include "llvm/Transforms/Obfuscation/VMPCompatibility.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ModuleUtils.h" 
#include "llvm/Transforms/Utils/ValueMapper.h"
#include "llvm/Transforms/Obfuscation/aVMP.h"
#include "llvm/Transforms/Obfuscation/vm.h"
#include "../../../../aVMPInterpreter/VMPIntegrity.h"
#include <assert.h>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#define ENABLE_VMP
#ifdef ENABLE_VMP

using namespace llvm;
using namespace std;

static cl::opt<uint64_t> VMPMaxBasicBlocks(
    "irobf-vmp-max-bbs", cl::init(4096),
    cl::desc("Maximum basic blocks accepted by legacy VMP; 0 disables the limit"));
static cl::opt<uint64_t> VMPMaxInstructions(
    "irobf-vmp-max-instructions", cl::init(50000),
    cl::desc("Maximum instructions accepted by legacy VMP; 0 disables the limit"));
static cl::opt<uint64_t> VMPMaxCodeBytes(
    "irobf-vmp-max-code-bytes", cl::init(16ULL * 1024ULL * 1024ULL),
    cl::desc("Maximum estimated legacy VMP bytecode size; 0 disables the limit"));
static cl::opt<uint64_t> VMPMaxDataBytes(
    "irobf-vmp-max-data-bytes", cl::init(16ULL * 1024ULL * 1024ULL),
    cl::desc("Maximum estimated legacy VMP data segment size; 0 disables the limit"));
static cl::opt<bool> VMPStrictCompatibility(
    "irobf-vmp-strict", cl::init(false),
    cl::desc("Fail compilation instead of skipping an incompatible VMP function"));
static cl::opt<uint64_t> VMPMaxRuntimeSteps(
    "irobf-vmp-max-runtime-steps", cl::init(10000000ULL),
    cl::desc("Maximum VM opcodes per invocation; 0 disables the limit"));
static cl::opt<uint64_t> VMPMaxRuntimeCalls(
    "irobf-vmp-max-runtime-calls", cl::init(65536ULL),
    cl::desc("Maximum VM call opcodes per invocation; 0 disables the limit"));
static cl::opt<uint64_t> VMPMaxCallDepth(
    "irobf-vmp-max-call-depth", cl::init(64ULL),
    cl::desc("Maximum nested VMP wrapper depth per thread; 0 disables the limit"));

static allvm::VMPResourceLimits currentVMPResourceLimits() {
    allvm::VMPResourceLimits Limits;
    Limits.MaxBasicBlocks = VMPMaxBasicBlocks;
    Limits.MaxInstructions = VMPMaxInstructions;
    Limits.MaxCodeBytes = VMPMaxCodeBytes;
    Limits.MaxDataBytes = VMPMaxDataBytes;
    return Limits;
}

static bool validateVMPFunction(Function &F) {
    const allvm::VMPCompatibilityResult Result =
        allvm::analyzeVMPFunction(F, currentVMPResourceLimits());
    if (Result.Supported) {
        if (isIRObfuscationDebugEnabled()) {
            errs() << "[VMP] Preflight accepted " << F.getName()
                   << ": bbs=" << Result.BasicBlockCount
                   << ", instructions=" << Result.InstructionCount
                   << ", estimated-code=" << Result.EstimatedCodeBytes
                   << ", estimated-data=" << Result.EstimatedDataBytes << "\n";
        }
        return true;
    }

    errs() << "[VMP] Skipping incompatible function '" << F.getName() << "':\n";
    for (const std::string &Reason : Result.Reasons)
        errs() << "  - " << Reason << "\n";

    if (VMPStrictCompatibility) {
        report_fatal_error(
            Twine("legacy VMP compatibility check failed for '") +
            F.getName() + "'");
    }
    return false;
}

static void prepareVMPFunction(Function &F) {
    F.removeFnAttr(Attribute::AlwaysInline);
    F.addFnAttr(Attribute::NoInline);
    F.addFnAttr(Attribute::OptimizeNone);
}

extern GlobalVariable *gv_code_seg;
extern GlobalVariable *gv_data_seg;
extern GlobalVariable *ip;
extern GlobalVariable *data_seg_addr;
extern GlobalVariable *code_seg_addr;
extern Function *govm_interpreter;

static void resetVMPGlobals() {
    govm_interpreter = nullptr;
    gv_code_seg = nullptr;
    gv_data_seg = nullptr;
    ip = nullptr;
    data_seg_addr = nullptr;
    code_seg_addr = nullptr;
}

// code and data segment
// extern GlobalVariable * gv_code_seg;
// extern GlobalVariable * gv_data_seg;
// extern GlobalVariable * ip;
// extern GlobalVariable * data_seg_addr;
GlobalVariable * gv_code_seg;
GlobalVariable * gv_data_seg;
GlobalVariable * ip;
GlobalVariable * data_seg_addr;
GlobalVariable * code_seg_addr;


// Interpreter
// extern Function * govm_interpreter;
Function * govm_interpreter;


// Opcode 
#define NOP_OP              0x00
#define ALLOCA_OP           0x01
#define LOAD_OP             0x02
#define STORE_OP            0x03
#define BinaryOperator_OP   0x04
#define GEP_OP              0x05
#define CMP_OP              0x06
#define CAST_OP             0x07
#define BR_OP               0x08
#define Call_OP             0x09
#define Ret_OP              0x0A
#define SWITCH_OP           0x0B
#define INSERTVALUE_OP      0x0C
#define EXTRACTVALUE_OP     0x0D

#define OP_TOTAL            0x0D





/* ********************************************************************
*   PROJECT_LOGUTILS_H
***********************************************************************
*/

class LogUtils {
    public:
        static std::string *log_title(const char *);
};

std::string *LogUtils::log_title(const char *title) {
    int width = 64-4;
    int title_len = strlen(title);
    int pos = width/2-title_len/2;
    if (title_len%2) {
        pos -= 1;
    }

    assert(strlen(title) <= 60);

    std::string *res = new std::string("");
    *res += "\n\n################################################################\n";
    *res += "##                                                            ##\n";
    *res += "##                                                            ##\n";
    *res += "##";
    for (int i = 0; i < pos; i++) {
        *res += " ";
    }
    *res += title;
    for (int i = 0; i < width-pos-title_len; i++) {
        *res += " ";
    }
    *res += "##\n";

    *res += "##                                                            ##\n";
    *res += "##                                                            ##\n";
    *res += "################################################################\n\n";

    return res;
}


/* ********************************************************************
*   GOVMTRANSLATOR_H
***********************************************************************
*/


#define GOVTRANSLATOR_DEBUG

/***
 * The main class that modify the callsite of vm-function.
 */
class GOVMTranslator {
    
    public:
        GOVMTranslator(Function * F,
                       const allvm::VMPResourceLimits &Limits) {
            this->Mod = F->getParent();
            this->F = F;
            this->modDataLayout = const_cast<DataLayout *>(&this->Mod->getDataLayout());
            this->pointer_size = modDataLayout->getPointerSize();  // 动态获取指针大小
            this->ResourceLimits = Limits;

            std::string DomainSuffix = this->Mod->getModuleIdentifier();
            DomainSuffix += '|';
            DomainSuffix += this->F->getName().str();

            std::string LayoutDomain = "legacy-vmp-layout|" + DomainSuffix;
            allvm::seedCryptoUtils(RandomEngine, LayoutDomain.c_str());

            std::string IntegrityDomain =
                "legacy-vmp-integrity|" + DomainSuffix;
            allvm::seedCryptoUtils(IntegrityEngine, IntegrityDomain.c_str());
            do {
                IntegrityKey0 = IntegrityEngine.get_uint64_t();
                IntegrityKey1 = IntegrityEngine.get_uint64_t();
            } while ((IntegrityKey0 | IntegrityKey1) == 0);

            // construct function and global variables
            init();
        }

        Module * Mod;
        Function * F;
        DataLayout * modDataLayout;
        unsigned pointer_size;  // 动态获取的指针大小,支持不同架构
        CryptoUtils RandomEngine;
        CryptoUtils IntegrityEngine;
        uint64_t IntegrityKey0 = 0;
        uint64_t IntegrityKey1 = 0;
        allvm::VMPResourceLimits ResourceLimits;
        bool TranslationFailed = false;
        std::string TranslationError;

        // construct callinst_handler to interprete callinst 
        Function * callinst_handler;
        BasicBlock * callinst_handler_conBBL;
        BasicBlock * callinst_handler_entryBB;  // 保存entryBB用于添加if-else
        Value * targetfunc_id;
        unsigned callinst_handler_curr_idx;
        std::map<Function *, unsigned> function_id_map;

        // hex code
        std::vector<uint8_t> vm_code;

        // map
        std::map<Value *, int> value_map;
        std::map<BasicBlock *, int> basicblock_map;
        std::vector<pair<int, BasicBlock *>> br_map;
        std::map<CallBase *, long long> callinst_map;
        
        // LLVM 21: SwitchInst支持
        std::vector<std::tuple<int, BasicBlock *, int>> switch_map;  // (code_pos, target_bb, case_value)

        // collect global variable
        std::map<GlobalVariable *, int> gv_value_map;

        // current offset in data_seg
        int curr_data_offset = 0;


        virtual bool run ();
        virtual void handle_inst(Instruction *);
        virtual void construct_gv();

        // create callinst_handler function, add instructions to callinst_handler and create ret basicblock to callinst_handler 
        virtual void setup_callinst_handler();
        virtual void handle_callinst(CallBase * inst, long long curr_func_id);
        virtual void finish_callinst_handler();

        // get a NULL value
        std::vector<uint8_t> get_null_value() {
            return std::vector<uint8_t>(2 + pointer_size);
        }

        // pack a value
        #define GET_PACK_VALUE(value) (packValue(value, &value_map))


        // construct function and global variables
        void init() {
            // construct_gv();
            setup_callinst_handler();  // 创建call_handler

            // encrypt opcode
            init_xorshift32();
        }

        Function *get_callinst_handler() {
            return this->callinst_handler;
        }

        // insert arg into res.end
        template <typename T, typename Arg>
        void vector_appender(T &res, Arg arg)
        {
            res.insert(res.end(), arg.begin(), arg.end());
        }

        // combine multiple vector, result in res
        template <typename T, typename... Args>
        void ins_to_hex(T &res, Args ... arg)
        {
            (void)std::initializer_list<int>{ (vector_appender(res, arg), 0)... };
        }

        std::map<GlobalVariable *, int> *get_gv_value_map() {
            return &gv_value_map;
        }

        std::map<Value *, int> *get_value_map() {
            return &value_map;
        }

        StringRef getTranslationError() const {
            return TranslationError;
        }

        uint64_t getCodeSegmentSize() const {
            return static_cast<uint64_t>(vm_code.size());
        }

        uint64_t getDataSegmentSize() const {
            return curr_data_offset < 0
                       ? 0
                       : static_cast<uint64_t>(curr_data_offset);
        }

        uint64_t getIntegrityKey0() const { return IntegrityKey0; }
        uint64_t getIntegrityKey1() const { return IntegrityKey1; }

        void failTranslation(const Twine &Reason) {
            if (!TranslationFailed)
                TranslationError = Reason.str();
            TranslationFailed = true;
        }

        bool checkActualResourceUsage() {
            if (ResourceLimits.MaxCodeBytes != 0 &&
                vm_code.size() > ResourceLimits.MaxCodeBytes) {
                failTranslation(Twine("actual VM bytecode size ") +
                                Twine(vm_code.size()) + " exceeds configured limit " +
                                Twine(ResourceLimits.MaxCodeBytes));
            }
            if (curr_data_offset < 0) {
                failTranslation("VM data offset became negative");
            } else if (ResourceLimits.MaxDataBytes != 0 &&
                       static_cast<uint64_t>(curr_data_offset) >
                           ResourceLimits.MaxDataBytes) {
                failTranslation(Twine("actual VM data size ") +
                                Twine(curr_data_offset) +
                                " exceeds configured limit " +
                                Twine(ResourceLimits.MaxDataBytes));
            }
            if (vm_code.size() > std::numeric_limits<uint32_t>::max())
                failTranslation("VM bytecode exceeds the 32-bit interpreter IP range");
            return !TranslationFailed;
        }


        // insert a value to value_map
        void insert_to_value_map(std::map<Value *, int> * value_map, Value * value, int offset){
            value_map->insert(pair<Value *, int>(value, offset));
        }


        void dump_vector(std::vector<uint8_t> v){
            if (isIRObfuscationDebugEnabled()) {
                for(auto i : v){
                    errs() << int(i) << " ";
                }
                errs() << "\n";
            }
        }


        // pack a int to vector<uint8_t>(4)
        std::vector<uint8_t> p32(int int32){
            std::vector<uint8_t> tmp;
            tmp.push_back(int32 & 0xFF);
            tmp.push_back((int32 >> 8) & 0xFF);
            tmp.push_back((int32 >> 16) & 0xFF);
            tmp.push_back((int32 >> 24) & 0xFF);
            return tmp;
        }

        // pack a int to vector<uint8_t>(1-8)
        std::vector<uint8_t> pack(long long int int_n, int size){

            if (size > 8){
                // long long is 64bit
                assert(0);
            }

            std::vector<uint8_t> tmp;
            while(size > 0){
                tmp.push_back((int_n) & 0xFF);
                size --;
                int_n = int_n >> 8;
            }
            return tmp;
        }

        // encrypt opcode, use xorshift
        uint32_t xorshift32_state = 0;
        uint32_t xorshift32_seed = 0;

        struct VMPBlockRecord {
            uint32_t HeaderOffset;
            uint32_t BodyBegin;
            uint32_t BodyEnd;
            uint32_t OpcodeSeed;
            uint32_t CodeSeed;
        };
        std::vector<VMPBlockRecord> vm_blocks;

        void init_xorshift32() {
            xorshift32_seed = gen_xorshift32_seed();
            xorshift32_state = xorshift32_seed;
        }

        uint32_t gen_xorshift32_seed() {
            uint32_t Seed = 0;
            do {
                Seed = RandomEngine.get_uint32_t();
            } while (Seed == 0);
            return Seed;
        }

        /* The state word must be initialized to non-zero */
        uint32_t xorshift32(uint32_t *state)
        {
            /* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
            uint32_t x = *state;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            return *state = x;
        }

        uint32_t vm_code_seed_setup() {
            uint32_t res = gen_xorshift32_seed();

            std::vector<uint8_t> hex_code;
            ins_to_hex(hex_code, pack(res, sizeof(uint32_t)));
            vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());

            return res;
        }

        uint32_t opcode_seed_setup() {
            xorshift32_seed = gen_xorshift32_seed();
            xorshift32_state = xorshift32_seed;

            std::vector<uint8_t> hex_code;
            ins_to_hex(hex_code, pack(xorshift32_seed, sizeof(uint32_t)));
            vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
            
            return xorshift32_seed;
        }

        void encrypt_vm_code() {
            for (const VMPBlockRecord &Block : vm_blocks) {
                uint32_t vm_code_seed = Block.CodeSeed;
                for (uint32_t addr = Block.BodyBegin;
                     addr < Block.BodyEnd; ++addr)
                    vm_code[addr] ^= (xorshift32(&vm_code_seed) & 0xFF);
            }
        }

        bool seal_vm_blocks() {
            for (const VMPBlockRecord &Block : vm_blocks) {
                if (Block.BodyEnd < Block.BodyBegin ||
                    static_cast<size_t>(Block.HeaderOffset) +
                            VMP_BLOCK_HEADER_SIZE >
                        vm_code.size() ||
                    Block.BodyEnd > vm_code.size()) {
                    failTranslation("VMP authenticated block range is invalid");
                    return false;
                }

                const uint64_t BodySize64 =
                    static_cast<uint64_t>(Block.BodyEnd - Block.BodyBegin);
                if (BodySize64 > std::numeric_limits<uint32_t>::max()) {
                    failTranslation("VMP authenticated block body exceeds 32-bit size");
                    return false;
                }

                uint8_t *Header = vm_code.data() + Block.HeaderOffset;
                vmp_integrity_store32_le(
                    Header + VMP_BLOCK_BODY_SIZE_OFFSET,
                    static_cast<vmp_u32>(BodySize64));
                vmp_integrity_store32_le(
                    Header + VMP_BLOCK_MAGIC_OFFSET, VMP_BLOCK_MAGIC);

                vmp_u64 Tag0 = 0;
                vmp_u64 Tag1 = 0;
                vmp_integrity_block_tags(
                    vm_code.data() + Block.BodyBegin,
                    static_cast<vmp_u32>(BodySize64),
                    IntegrityKey0, IntegrityKey1,
                    Block.HeaderOffset, Block.OpcodeSeed, Block.CodeSeed,
                    &Tag0, &Tag1);
                vmp_integrity_store64_le(
                    Header + VMP_BLOCK_TAG0_OFFSET, Tag0);
                vmp_integrity_store64_le(
                    Header + VMP_BLOCK_TAG1_OFFSET, Tag1);
            }
            return true;
        }

        // Encode one opcode as its ordinal in a collision-free xorshift byte sequence.
        // Byte zero is reserved for NOP and therefore does not advance the state.
        std::vector<uint8_t> pack_op(uint8_t op) {
            if (op == NOP_OP)
                return {0};
            if (op > OP_TOTAL) {
                failTranslation(Twine("opcode ") + Twine(op) +
                                " exceeds the legacy VMP opcode range");
                return {};
            }

            uint8_t seen[256] = {};
            uint8_t result = 0;
            unsigned unique_count = 0;
            unsigned attempts = 0;

            while (unique_count < op) {
                if (++attempts > 4096U) {
                    failTranslation("unable to construct a collision-free opcode sequence");
                    return {};
                }

                const uint8_t candidate =
                    static_cast<uint8_t>(xorshift32(&xorshift32_state) & 0xFFU);
                if (candidate == 0 || seen[candidate] != 0)
                    continue;

                seen[candidate] = 1;
                result = candidate;
                ++unique_count;
            }

            return {result};
        }


        // pack a Constant to a vector
        std::vector<uint8_t> pack_const_value(Value * const_value){
            std::vector<uint8_t> res;
            Type * type = const_value->getType();
            int type_size = modDataLayout->getTypeAllocSize(type);
            int64_t value = 0;
            bool handled = false;

            if (type->isIntegerTy()){
                if (ConstantInt* CI = dyn_cast<ConstantInt>(const_value)) {
                    if (CI->getBitWidth() <= 64) {
                        value = CI->getSExtValue();
                        handled = true;
                    }
                } else if (isa<UndefValue>(const_value) || isa<PoisonValue>(const_value)) {
                    value = 0;
                    handled = true;
                }
            }

            if (!handled) {
                if (ConstantFP *CFP = dyn_cast<ConstantFP>(const_value)) {
                    APInt api = CFP->getValueAPF().bitcastToAPInt();
                    value = api.getZExtValue();
                    handled = true;
                }
            }

            if (!handled && isa<ConstantPointerNull>(const_value)) {
                value = 0;
                handled = true;
            }

            if (!handled && (isa<UndefValue>(const_value) || isa<PoisonValue>(const_value))) {
                value = 0;
                handled = true;
            }

            if (!handled) {
                failTranslation(
                    Twine("unsupported constant value in function '") +
                    F->getName() + "'");
                value = 0;
            }

            res = pack(value, type_size);

            return res;
        }


        // pack type to a vector(2)
        // {size, TypeID}
        std::vector<uint8_t> type_to_hex(Type * type){
            std::vector<uint8_t> res;
            res.push_back(modDataLayout->getTypeAllocSize(type));
            res.push_back(type->getTypeID());
            return res;
        }


        // pack a value
        std::vector<uint8_t> packValue(Value * value, std::map<Value *, int> * value_map) {
            std::vector<uint8_t> res;
            std::vector<uint8_t> packed;
            std::vector<uint8_t> packType = type_to_hex(value->getType());
            if (isa<ConstantData>(value) ||
                isa<ConstantPointerNull>(value)) {
                packed = pack_const_value(value);
            }
            else{
                // if value not in map
                if (value_map->find(value) == value_map->end()) {
                    // check value is not a GlobalVariable
                    if (GlobalVariable *gv = dyn_cast<GlobalVariable>(value)) {
                        // is a GlobalVariable and not in value_map
                        // put it into value_map
                        insert_to_value_map(value_map, value, curr_data_offset);

                        // also put it into gv_value_map
                        gv_value_map.insert(pair<GlobalVariable *, int>(gv, curr_data_offset));

                        int res_size = modDataLayout->getTypeAllocSize(gv->getType());
                        curr_data_offset += res_size;
                    }
                    else {
                        failTranslation(
                            Twine("value is missing from VMP data map in function '") +
                            F->getName() + "'");
                        return {};
                    }
                }

                packed = pack((*value_map)[value], pointer_size);
                // variableï¼Œpacktype->TypeID=0
                packType[1] = 0;
            }

            res.insert(res.end(), packType.begin(), packType.end());
            res.insert(res.end(), packed.begin(), packed.end());

            return res;
        }

};




/* ********************************************************************
*   GOVMTRANSLATOR_CPP
***********************************************************************
*/

// GlobalVariable * gv_code_seg;
// GlobalVariable * gv_data_seg;
// GlobalVariable * ip;
// GlobalVariable * data_seg_addr;
// GlobalVariable * code_seg_addr;

void GOVMTranslator::construct_gv() {
    // construct code global array from vm_code
    
    // set Initializer for gv_code_seg
    ArrayRef<uint8_t> code_seg_arrayref(vm_code);
    Constant * code_seg_init = ConstantDataArray::get(Mod->getContext(), code_seg_arrayref);

    ArrayType * code_seg_type = ArrayType::get(IntegerType::get(Mod->getContext(), 8), vm_code.size());
    // ArrayType * code_seg_type = ArrayType::get(IntegerType::get(Mod->getContext(), 8), VM_CODE_SEG_SIZE);
    // global
    gv_code_seg = new GlobalVariable(
                                                    /*Module=*/*Mod,
                                                    /*Type=*/code_seg_type,
                                                    /*isConstant=*/true,
                                                    /*Linkage=*/GlobalValue::InternalLinkage,
                                                    /*Initializer=*/code_seg_init, // has initializer, specified
                                                                                    // below
                                                    /*Name=*/"gv_code_seg_"+F->getName());
    


    // construct data global array
    std::vector<uint8_t> data_seg_vector(curr_data_offset);
    // std::vector<uint8_t> data_seg_vector(VM_DATA_SEG_SIZE);
    ArrayRef<uint8_t> data_seg_arrayref(data_seg_vector);
    Constant * data_seg_init = ConstantDataArray::get(Mod->getContext(), data_seg_arrayref);
    ArrayType * data_seg_type = ArrayType::get(IntegerType::get(Mod->getContext(), 8), curr_data_offset);
    // ArrayType * data_seg_type = ArrayType::get(IntegerType::get(Mod->getContext(), 8), VM_DATA_SEG_SIZE);
    // global
    gv_data_seg = new GlobalVariable(
                                                    /*Module=*/*Mod,
                                                    /*Type=*/data_seg_type,
                                                    /*isConstant=*/false,
                                                    /*Linkage=*/GlobalValue::InternalLinkage,
                                                    /*Initializer=*/data_seg_init, // has initializer, specified
                                                                                    // below
                                                    /*Name=*/"gv_data_seg_"+F->getName());
    gv_data_seg->setThreadLocal(true);


    // ip
    Constant *ip_initGV = ConstantInt::get(Type::getInt32Ty(Mod->getContext()), 0);
    ip = new GlobalVariable(*Mod, Type::getInt32Ty(Mod->getContext()), 
                false,  GlobalValue::InternalLinkage, 
                ip_initGV, "ip_"+F->getName());
    ip->setThreadLocal(true);

    // data_seg_addr
    Constant *data_seg_addr_initGV = ConstantInt::get(Type::getInt64Ty(Mod->getContext()), 0);
    data_seg_addr = new GlobalVariable(*Mod, Type::getInt64Ty(Mod->getContext()), 
                false,  GlobalValue::InternalLinkage, 
                data_seg_addr_initGV, "data_seg_addr_"+F->getName());
    data_seg_addr->setThreadLocal(true);

    // code_seg_addr
    Constant *code_seg_addr_initGV = ConstantInt::get(Type::getInt64Ty(Mod->getContext()), 0);
    code_seg_addr = new GlobalVariable(*Mod, Type::getInt64Ty(Mod->getContext()), 
                false,  GlobalValue::InternalLinkage, 
                code_seg_addr_initGV, "code_seg_addr_"+F->getName());
    code_seg_addr->setThreadLocal(true);
}

void GOVMTranslator::setup_callinst_handler() {
    // collect dispatch function args type 
    std::vector<Type*> FuncTy_args;
    // param: targetfunc_id_value
    FuncTy_args.push_back(Type::getInt64Ty(Mod->getContext()));

    // get dispatch function type
    FunctionType* FuncTy = FunctionType::get(
        /*Result=*/Type::getVoidTy(this->Mod->getContext()),  // returning void
        /*Params=*/FuncTy_args,  
        /*isVarArg=*/false);
    // Constant *tmp = Mod->getOrInsertFunction("",FuncTy);
    Constant *tmp = Function::Create(FuncTy, llvm::GlobalValue::LinkageTypes::InternalLinkage, "vm_interpreter_callinst_dispatch_"+F->getName(), Mod);
    Function *func =  cast<Function>(tmp);
    // func->setLinkage(llvm::GlobalValue::LinkageTypes::InternalLinkage);

    // create entry BasicBlock
    BasicBlock *entryBB = BasicBlock::Create(func->getContext(), "entryBB", func);
    IRBuilder<> IRBentryBB(entryBB);

    // Store params
    Value *target_id_value;
    for (auto arg = func->arg_begin(); arg != func->arg_end(); arg++) {
        Value *tmparg = &*arg;
        if (arg == func->arg_begin()) {
            // targetfunc_id_value
            Value *paramPtr = IRBentryBB.CreateAlloca(Type::getInt64Ty(Mod->getContext()));
            IRBentryBB.CreateStore(tmparg, paramPtr);
            target_id_value = IRBentryBB.CreateLoad(Type::getInt64Ty(Mod->getContext()), paramPtr);
        } 
    }

    // 不在这里创建返回指令，会在handle_callinst中添加条件跳转
    // 最后一个基本块会在finish_callinst_handler中添加返回指令

    this->callinst_handler_curr_idx = 0;

    this->callinst_handler = func;
    this->callinst_handler_conBBL = entryBB;  // 使用entryBB作为conBBL

    this->targetfunc_id = target_id_value;
    
    this->callinst_handler_entryBB = entryBB;
}

void GOVMTranslator::finish_callinst_handler() {
    // 为最后一个基本块添加返回指令
    IRBuilder<> IRB(this->callinst_handler_conBBL);
    IRB.CreateRetVoid();
}

void GOVMTranslator::handle_callinst(CallBase *inst, long long curr_func_id) {

    // errs() << "[handle_callinst] Processing callinst #" << curr_func_id << "\n";
    
    if (!this->callinst_handler_conBBL) {
        // errs() << "[handle_callinst] ERROR: callinst_handler_conBBL is null!\n";
        return;
    }
    
    IRBuilder<> IRBcon(this->callinst_handler_conBBL);

    // firstly,  we need to unpack function args
    // errs() << "[handle_callinst] Unpacking args, arg_size=" << inst->arg_size() << "\n";
    std::vector<Value *> target_func_args;
    for (unsigned idx = 0; idx < inst->arg_size(); idx++){
        // errs() << "[handle_callinst] Processing arg " << idx << "\n";
        Value * currarg = inst->getArgOperand(idx);

        // if value is a constant, use it directly
        if(isa<Constant>(currarg)){
            // errs() << "[handle_callinst] Arg " << idx << " is constant\n";
            target_func_args.push_back(currarg);
            continue;
        }

        if (value_map.find(currarg) == value_map.end()) {
            // errs() << "[VMP] ERROR: arg not found in value_map for call: " << *inst << "\n";
            target_func_args.push_back(UndefValue::get(currarg->getType()));
            continue;
        }
        // errs() << "[handle_callinst] Arg " << idx << " found in value_map\n";
        unsigned curroffset = value_map[currarg];

        // construct load
        ConstantInt *Zero = ConstantInt::get(Type::getInt64Ty(Mod->getContext()), 0);
        Value * offset_value = ConstantInt::get(Type::getInt64Ty(Mod->getContext()), curroffset);
        Value * gepinst = IRBcon.CreateGEP(gv_data_seg->getValueType(), gv_data_seg, {Zero, offset_value}, "");

        // 对于指针类型，gepinst就是指向data_seg中存储指针值的位置
        // 需要加载这个指针值（实际地址）
        if (currarg->getType()->isPointerTy()) {
            // 从data_seg加载指针值（实际地址）
            Value * ptr_addr = IRBcon.CreatePointerCast(gepinst, PointerType::get(Mod->getContext(), 0));
            Value * actual_ptr = IRBcon.CreateLoad(PointerType::get(Mod->getContext(), 0), ptr_addr);
            target_func_args.push_back(actual_ptr);
        } else {
            // 非指针类型，从data_seg加载值
            Value * ptr = IRBcon.CreatePointerCast(gepinst, PointerType::get(Mod->getContext(), 0));
            Value * arg = IRBcon.CreateLoad(currarg->getType(), ptr);
            target_func_args.push_back(arg);
        }
    }


    // errs() << "[handle_callinst] Args done, creating callFunction BB\n";
    // secondly, we create a new basic block to construct callinst
    BasicBlock *callFunction = BasicBlock::Create(Mod->getContext(), "callFunction_" + to_string(this->callinst_handler_curr_idx), this->callinst_handler);
    IRBuilder<> IRBcallFunction(callFunction);

    // errs() << "[handle_callinst] Checking call type\n";
    Value *resultValue;

    // errs() << "[handle_callinst] isIndirectCall=" << inst->isIndirectCall() << "\n";
    
    bool treatAsIndirect = inst->isIndirectCall();
    Function *callee = nullptr;
    Value *calledValue = nullptr;
    
    if (!inst->isIndirectCall()) {
        // errs() << "[handle_callinst] Direct call\n";
        callee = inst->getCalledFunction();
        
        if (!callee) {
            // errs() << "[handle_callinst] WARNING: callee is null for direct call, treating as indirect: " << *inst << "\n";
            treatAsIndirect = true;
            calledValue = inst->getCalledOperand();
        } else {
            // errs() << "[handle_callinst] Callee: " << callee->getName() << "\n";
        }
    }

    if (!treatAsIndirect && callee) {
        // 检查是否是递归调用（调用自己）
        bool is_recursive_call = (callee == this->F);
        
        if (is_recursive_call) {
            
            // 将函数指针转换为整数
            Value *funcPtrInt = IRBcallFunction.CreatePtrToInt(
                callee, Type::getInt64Ty(Mod->getContext()));
            
            // 转换为函数指针类型
            Value *funcPtr = IRBcallFunction.CreateIntToPtr(
                funcPtrInt, PointerType::get(Mod->getContext(), 0));
            
            // 使用间接调用
            resultValue = IRBcallFunction.CreateCall(
                callee->getFunctionType(), funcPtr, ArrayRef<Value *>(target_func_args));
        } else {
            // 对于普通函数调用，需要判断是标准库函数还是用户函数
            // GOVMModifier会将原函数重命名为"原函数名_original"并创建wrapper
            
            // 检查是否是标准库函数
            bool is_stdlib = false;
            if (callee->hasName()) {
                std::string calleeName = callee->getName().str();
                
                // 跳过以__开头（编译器内部函数）
                if(calleeName.length() >= 2 && calleeName[0] == '_' && calleeName[1] == '_') {
                    is_stdlib = true;
                }
                // 跳过C标准库函数
                else if(calleeName.find("printf") != std::string::npos ||
                   calleeName.find("sprintf") != std::string::npos ||
                   calleeName.find("fprintf") != std::string::npos ||
                   calleeName.find("vsprintf") != std::string::npos ||
                   calleeName.find("vfprintf") != std::string::npos ||
                   calleeName.find("vsnprintf") != std::string::npos ||
                   calleeName.find("local_stdio") != std::string::npos ||
                   calleeName.find("frexp") != std::string::npos ||
                   calleeName.find("ldexp") != std::string::npos ||
                   calleeName.find("modf") != std::string::npos ||
                   calleeName.find("scalbn") != std::string::npos ||
                   calleeName.find("ilogb") != std::string::npos ||
                   calleeName.find("logb") != std::string::npos ||
                   calleeName.find("copysign") != std::string::npos ||
                   calleeName.find("nan") != std::string::npos ||
                   calleeName.find("nextafter") != std::string::npos ||
                   calleeName.find("fdim") != std::string::npos ||
                   calleeName.find("fmax") != std::string::npos ||
                   calleeName.find("fmin") != std::string::npos ||
                   calleeName.find("fma") != std::string::npos ||
                   calleeName.find("isnan") != std::string::npos ||
                   calleeName.find("isinf") != std::string::npos ||
                   calleeName.find("isfinite") != std::string::npos ||
                   calleeName.find("fabs") != std::string::npos ||
                   calleeName.find("ceil") != std::string::npos ||
                   calleeName.find("floor") != std::string::npos ||
                   calleeName.find("round") != std::string::npos ||
                   calleeName.find("trunc") != std::string::npos ||
                   calleeName.find("sqrt") != std::string::npos ||
                   calleeName.find("pow") != std::string::npos ||
                   calleeName.find("exp") != std::string::npos ||
                   calleeName.find("log") != std::string::npos ||
                   calleeName.find("sin") != std::string::npos ||
                   calleeName.find("cos") != std::string::npos ||
                   calleeName.find("tan") != std::string::npos ||
                   calleeName.find("asin") != std::string::npos ||
                   calleeName.find("acos") != std::string::npos ||
                   calleeName.find("atan") != std::string::npos ||
                   calleeName.find("atan2") != std::string::npos ||
                   calleeName.find("sinh") != std::string::npos ||
                   calleeName.find("cosh") != std::string::npos ||
                   calleeName.find("tanh") != std::string::npos ||
                   calleeName.find("malloc") != std::string::npos ||
                   calleeName.find("free") != std::string::npos ||
                   calleeName.find("calloc") != std::string::npos ||
                   calleeName.find("realloc") != std::string::npos ||
                   calleeName.find("memcpy") != std::string::npos ||
                   calleeName.find("memset") != std::string::npos ||
                   calleeName.find("memmove") != std::string::npos ||
                   calleeName.find("strcmp") != std::string::npos ||
                   calleeName.find("strlen") != std::string::npos ||
                   calleeName.find("strcpy") != std::string::npos) {
                    is_stdlib = true;
                }
                // 跳过C++标准库函数
                else if(calleeName.find("std::") != std::string::npos ||
                   calleeName.find("basic_ostream") != std::string::npos ||
                   calleeName.find("basic_ios") != std::string::npos ||
                   calleeName.find("basic_istream") != std::string::npos ||
                   calleeName.find("basic_string") != std::string::npos ||
                   calleeName.find("basic_iostream") != std::string::npos ||
                   calleeName.find("basic_fstream") != std::string::npos ||
                   calleeName.find("basic_ifstream") != std::string::npos ||
                   calleeName.find("basic_ofstream") != std::string::npos ||
                   calleeName.find("basic_stringbuf") != std::string::npos ||
                   calleeName.find("basic_istringstream") != std::string::npos ||
                   calleeName.find("basic_ostringstream") != std::string::npos ||
                   calleeName.find("basic_stringstream") != std::string::npos ||
                   calleeName.find("ctype") != std::string::npos ||
                   calleeName.find("locale") != std::string::npos ||
                   calleeName.find("char_traits") != std::string::npos ||
                   calleeName.find("numpunct") != std::string::npos ||
                   calleeName.find("num_put") != std::string::npos ||
                   calleeName.find("allocator") != std::string::npos ||
                   calleeName.find("ios_base") != std::string::npos ||
                   calleeName.find("ostreambuf") != std::string::npos ||
                   calleeName.find("istreambuf") != std::string::npos) {
                    is_stdlib = true;
                }
                // 检查是否是声明（外部函数）
                else if (callee->isDeclaration()) {
                    is_stdlib = true;
                }
            }
            
            if (is_stdlib) {
                // 标准库函数，直接调用
                resultValue = IRBcallFunction.CreateCall(callee->getFunctionType(), callee,
                            ArrayRef<Value *>(target_func_args));
            } else {
                // 用户函数，调用wrapper函数（原函数名）
                // wrapper函数会设置VM环境并调用vm_interpreter
                resultValue = IRBcallFunction.CreateCall(callee->getFunctionType(), callee,
                            ArrayRef<Value *>(target_func_args));
            }
        }
    }
    else {
        // indirect call (or direct call with null callee treated as indirect)
        if (!calledValue) {
            calledValue = inst->getCalledOperand();
        }
        if (value_map.find(calledValue) == value_map.end()) {
            // errs() << "[VMP] WARNING: called_value not found in value_map for indirect call: " << *inst << "\n";
            // fallback: use a direct call approach by calling the function directly
            FunctionType *funcType = inst->getFunctionType();
            Value *funcPtr = IRBcallFunction.CreatePointerCast(calledValue, PointerType::get(Mod->getContext(), 0));
            resultValue = IRBcallFunction.CreateCall(funcType, funcPtr, ArrayRef<Value *>(target_func_args));
        } else {
            unsigned called_value_offset = value_map[calledValue];

            // load value from gv_data_seg
            ConstantInt *Zero = ConstantInt::get(Type::getInt64Ty(Mod->getContext()), 0);
            Value * offset_value = ConstantInt::get(Type::getInt64Ty(Mod->getContext()), called_value_offset);
            Value * gepinst = IRBcallFunction.CreateGEP(gv_data_seg->getValueType(), gv_data_seg, {Zero, offset_value}, "");

            // convert gep from i8* to value->getType() *
            Value * ptr = IRBcallFunction.CreatePointerCast(gepinst, PointerType::get(Mod->getContext(), 0));
            
            // load from gv_data_seg
            Value * value = IRBcallFunction.CreateLoad(calledValue->getType(), ptr);


            // indirect call - need to cast the function pointer
            FunctionType *funcType = inst->getFunctionType();
            Value *funcPtr = IRBcallFunction.CreatePointerCast(value, PointerType::get(Mod->getContext(), 0));
            resultValue = IRBcallFunction.CreateCall(funcType, funcPtr, ArrayRef<Value *>(target_func_args));
        }
    }

    // if return not void, store it to gv_data_seg
    if (inst->getType() != Type::getVoidTy(this->Mod->getContext())) {
        if (value_map.find(inst) == value_map.end()) {
            // errs() << "[VMP] ERROR: call result not found in value_map: " << *inst << "\n";
        } else {
            unsigned result_value_offset = value_map[inst];

            // load value from gv_data_seg
            ConstantInt *Zero = ConstantInt::get(Type::getInt64Ty(Mod->getContext()), 0);
            Value * offset_value = ConstantInt::get(Type::getInt64Ty(Mod->getContext()), result_value_offset);
            Value * gepinst = IRBcallFunction.CreateGEP(gv_data_seg->getValueType(), gv_data_seg, {Zero, offset_value}, "");

            // convert gep from i8* to value->getType() *
            Value * ptr = IRBcallFunction.CreatePointerCast(gepinst, PointerType::get(Mod->getContext(), 0));

            // store
            IRBcallFunction.CreateStore(resultValue, ptr);
        }
    }

    
    // Create Return
    IRBcallFunction.CreateRetVoid();
    

    // compare and jmp
    BasicBlock *falseconBBL = BasicBlock::Create(Mod->getContext(), "falseconBBL", this->callinst_handler);

    Value *currfunc_id = ConstantInt::get(Type::getInt64Ty(Mod->getContext()), curr_func_id);
    Value *condition = IRBcon.CreateICmpEQ(this->targetfunc_id, currfunc_id);
    IRBcon.CreateCondBr(condition, callFunction, falseconBBL);
    this->callinst_handler_conBBL = falseconBBL;

}


void GOVMTranslator::handle_inst(Instruction *ins) {
    if (!ins) {
        failTranslation("null LLVM instruction");
        return;
    }
    if (isa<DbgInfoIntrinsic>(ins) || isa<LifetimeIntrinsic>(ins))
        return;

    // switch inst type
    if(AllocaInst * inst = dyn_cast<AllocaInst>(ins)){
        // alloca memory for AllocaInst_Res and AllocaInst_alloca_area

        // AllocaInst_Res
        insert_to_value_map(&value_map, inst, curr_data_offset);
        int res_size = modDataLayout->getTypeAllocSize(inst->getType());
        curr_data_offset += res_size;

        std::vector<uint8_t> packed_res = GET_PACK_VALUE(inst);

        // AllocaInst_alloca_area
        int area_offset = curr_data_offset;
        int alloca_size = modDataLayout->getTypeAllocSize(inst->getAllocatedType());
        curr_data_offset += alloca_size;
        
        // align to pointer_size for next allocation
        if (curr_data_offset % pointer_size != 0) {
            curr_data_offset += pointer_size - (curr_data_offset % pointer_size);
        }

        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(ALLOCA_OP), packed_res, pack(area_offset, pointer_size));
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());

        #ifdef GOVTRANSLATOR_DEBUG
        // errs() << "[*] AllocaInst: " << *inst << "\n";
        // errs() << "\t area_offset: " << area_offset << "\tarea_size: " << alloca_size << "\n";
        // errs() << "\t current code_pos: " << vm_code.size() - hex_code.size() << "\n";
        // errs() << "\t Hex Code: "; dump_vector(hex_code); errs() << "\n";
        #endif
    }

    else if(LoadInst * inst = dyn_cast<LoadInst>(ins)){
        
        // return
        insert_to_value_map(&value_map, inst, curr_data_offset);
        int res_size = modDataLayout->getTypeAllocSize(inst->getType());
        curr_data_offset += res_size;

        std::vector<uint8_t> packed_res = GET_PACK_VALUE(inst);

        // PointerOperand
        std::vector<uint8_t> packed_pointer_operand = GET_PACK_VALUE(inst->getPointerOperand());


        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(LOAD_OP), packed_res, packed_pointer_operand);
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
    }

    else if(StoreInst * inst = dyn_cast<StoreInst>(ins)){
        
        // ValueOperand
        std::vector<uint8_t> packed_value_operand = GET_PACK_VALUE(inst->getValueOperand());

        // PointerOperand
        std::vector<uint8_t> packed_pointer_operand = GET_PACK_VALUE(inst->getPointerOperand());

        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(STORE_OP), packed_value_operand, packed_pointer_operand);
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
        
        #ifdef GOVTRANSLATOR_DEBUG
        // errs() << "[*] StoreInst: " << *inst << "\n";
        // errs() << "\t current code_pos: " << vm_code.size() - hex_code.size() << "\n";
        // errs() << "\t Hex Code: "; dump_vector(hex_code); errs() << "\n";
        #endif
    }

    else if(ins->isBinaryOp()){
        BinaryOperator * inst = dyn_cast<BinaryOperator>(ins);

        insert_to_value_map(&value_map, inst, curr_data_offset);
        int res_size = modDataLayout->getTypeAllocSize(inst->getType());
        curr_data_offset += res_size;
        
        std::vector<uint8_t> packed_res = GET_PACK_VALUE(inst);

        std::vector<uint8_t> packed_binaryOpcode = {static_cast<uint8_t>(inst->getOpcode())};

        std::vector<uint8_t> packed_op0 = GET_PACK_VALUE(inst->getOperand(0));
        std::vector<uint8_t> packed_op1 = GET_PACK_VALUE(inst->getOperand(1));


        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(BinaryOperator_OP), packed_binaryOpcode, packed_res, packed_op0, packed_op1);
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
    }

    else if(CmpInst * inst = dyn_cast<CmpInst>(ins)){

        insert_to_value_map(&value_map, inst, curr_data_offset);
        int res_size = modDataLayout->getTypeAllocSize(inst->getType());
        curr_data_offset += res_size;

        std::vector<uint8_t> packed_res = GET_PACK_VALUE(inst);

        std::vector<uint8_t> packed_op0 = GET_PACK_VALUE(inst->getOperand(0));
        std::vector<uint8_t> packed_op1 = GET_PACK_VALUE(inst->getOperand(1));

        std::vector<uint8_t> packed_predicate = {static_cast<uint8_t>(inst->getPredicate())};

        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(CMP_OP), packed_predicate, packed_res, packed_op0, packed_op1);
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());

        #ifdef GOVTRANSLATOR_DEBUG
        // errs() << "[*] CmpInst: " << *inst << "\n";
        // errs() << "\t Predicate: " << inst->getPredicate() << "\n";
        // errs() << "\t res_size: " << res_size << "\n";
        // errs() << "\t Op 0 Type: " << *inst->getOperand(0)->getType() << "\t Op 0 Size: " << modDataLayout->getTypeAllocSize(inst->getOperand(0)->getType()) << "\n";
        // errs() << "\t Op 1 Type: " << *inst->getOperand(1)->getType() << "\t Op 1 Size: " << modDataLayout->getTypeAllocSize(inst->getOperand(1)->getType()) << "\n";
        // errs() << "\t current code_pos: " << vm_code.size() - hex_code.size() << "\n";
        // errs() << "\n";
        #endif
    }

    else if(GetElementPtrInst * inst = dyn_cast<GetElementPtrInst>(ins)){
        insert_to_value_map(&value_map, inst, curr_data_offset);
        int res_size = modDataLayout->getTypeAllocSize(inst->getType());
        curr_data_offset += res_size;

        std::vector<uint8_t> packed_res = GET_PACK_VALUE(inst);

        std::vector<uint8_t> packed_ptr = GET_PACK_VALUE(inst->getPointerOperand());

        // get indices
        // but only consider last indice
        std::vector<Value *> indices;
        for (auto curr_idx=inst->idx_begin(); curr_idx != inst->idx_end(); curr_idx++){
            indices.push_back(*curr_idx);
        }

        // GEP type
        // {0, 0}: structure value is offset
        // {x, x}: array, value is offset
        Type * srcType = inst->getSourceElementType();
        std::vector<uint8_t> gep_type;
        std::vector<uint8_t> packed_value;
        if (dyn_cast<StructType>(srcType)) {
            // is struct type
            StructType * st = dyn_cast<StructType>(srcType);
            gep_type = {0, 0};
            if (indices.empty()) {
                // zero-index GEP on struct: result is same as base pointer
                packed_value = {0, 0};
            } else {
                Value* last_idx = indices.back();
                if (ConstantInt* CI = dyn_cast<ConstantInt>(last_idx)) {
                    int element_idx = CI->getSExtValue();
                    const StructLayout *Layout =
                        modDataLayout->getStructLayout(st);
                    const uint64_t curr_element_offset =
                        Layout->getElementOffset(element_idx);
                    packed_value = pack(curr_element_offset, pointer_size);
                    packed_value.insert(packed_value.begin(), 1);
                    packed_value.insert(packed_value.begin(), pointer_size);
                } else {
                    // last index is not a constant, use it as a variable
                    packed_value = GET_PACK_VALUE(last_idx);
                }
            }
        } else {
            // is array type
            gep_type = type_to_hex(inst->getResultElementType());
            if (indices.empty()) {
                packed_value = {0, 0};
            } else {
                packed_value = GET_PACK_VALUE(indices.back());
            }
        }

        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(GEP_OP), gep_type, packed_res, packed_ptr, packed_value);
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());


        #ifdef GOVTRANSLATOR_DEBUG
        // errs() << "[*] GetElementPtrInst: " << *inst << "\n";
        // errs() << "\t res_size: " << res_size << "\n";
        // errs() << "\t is struct gep: " << (dyn_cast<StructType>(srcType) != 0) << "\n";
        // errs() << "\t current code_pos: " << vm_code.size() - hex_code.size() << "\n";
        // errs() << "\n";
        #endif
    }

    else if(CastInst * inst = dyn_cast<CastInst>(ins)){
        insert_to_value_map(&value_map, inst, curr_data_offset);
        int res_size = modDataLayout->getTypeAllocSize(inst->getType());
        curr_data_offset += res_size;

        std::vector<uint8_t> packed_res = GET_PACK_VALUE(inst);
        std::vector<uint8_t> packed_value = GET_PACK_VALUE(inst->getOperand(0));

        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(CAST_OP), packed_res, packed_value);
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());

        #ifdef GOVTRANSLATOR_DEBUG
        // errs() << "[*] CastInst: " << *inst << "\n";
        // errs() << "\t res_size: " << res_size << "\n";
        // errs() << "\t Op 0 Type: " << *inst->getOperand(0)->getType() << "\t Op 0 Size: " << modDataLayout->getTypeAllocSize(inst->getOperand(0)->getType()) << "\n";
        // errs() << "\t current code_pos: " << vm_code.size() - hex_code.size() << "\n";
        // errs() << "\n";
        #endif
    }

    else if(BranchInst * inst = dyn_cast<BranchInst>(ins)){
        // Construct code_hex in here manually
        std::vector<uint8_t> hex_code;
        hex_code = pack_op(BR_OP);
        std::vector<uint8_t> padding = pack(0, pointer_size);

        if (inst->isUnconditional()) {
            hex_code.push_back(0);
            // errs() << vm_code.size()+2 << "\n";
            br_map.push_back(pair<int, BasicBlock *>(vm_code.size()+hex_code.size(), inst->getSuccessor(0)));          // fill after traverse whole function
            hex_code.insert(hex_code.end(), padding.begin(), padding.end());
        } else {
            hex_code.push_back(1);
            // condition
            std::vector<uint8_t> pack_condition = packValue(inst->getCondition(), &value_map);
            hex_code.insert(hex_code.end(), pack_condition.begin(), pack_condition.end());

            // errs() << vm_code.size()+2 << "\n";
            br_map.push_back(pair<int, BasicBlock *>(vm_code.size()+hex_code.size(), inst->getSuccessor(0)));
            hex_code.insert(hex_code.end(), padding.begin(), padding.end());
            // errs() << vm_code.size()+2+pointer_size << "\n";
            br_map.push_back(pair<int, BasicBlock *>(vm_code.size()+hex_code.size(), inst->getSuccessor(1)));
            hex_code.insert(hex_code.end(), padding.begin(), padding.end());
        }
        

        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());

        // errs() << "[*] BranchInst: " << *inst << "\n";
        // if (inst->isConditional())
        //     errs() << "\t Condition: " << *inst->getCondition() << "\n";
        // for (unsigned i=0; i<inst->getNumSuccessors(); i++) {
        //     errs() << "\t Successors: " << inst->getSuccessor(i)->getName().str() << "\n";
        // }
        // errs() << "\t current code_pos: " << vm_code.size() - hex_code.size() << "\n";
        // errs() << "\n";
    }
    
    else if(ReturnInst * inst = dyn_cast<ReturnInst>(ins)) {
        std::vector<uint8_t> value;

        if (inst->getNumOperands() == 0){           // return void
            value = get_null_value();
        }
        else{                                       // return something
            value = GET_PACK_VALUE(inst->getReturnValue());
        }

        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(Ret_OP), value);
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
    }

    else if(CallBase * inst = dyn_cast<CallBase>(ins)) {
        
        // current function id
        long long curr_func_id = this->callinst_handler_curr_idx ++;
        
        std::vector<uint8_t> packed_funcid = pack(curr_func_id, pointer_size);
        
        // check if this callsite return a void
        std::vector<uint8_t> packed_res;
        if (inst->getType() != Type::getVoidTy(this->Mod->getContext())) {
            // return a value
            insert_to_value_map(&value_map, inst, curr_data_offset);
            int res_size = modDataLayout->getTypeAllocSize(inst->getType());
            curr_data_offset += res_size;

            packed_res = GET_PACK_VALUE(inst);
        }

        // construct hex code
        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(Call_OP), packed_funcid);

        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());

        callinst_map.insert(std::pair<CallBase *, long long>(cast<CallBase>(ins), curr_func_id));
    }

    // LLVM 21: SwitchInst支持
    else if(SwitchInst * inst = dyn_cast<SwitchInst>(ins)) {
        std::vector<uint8_t> hex_code;
        hex_code = pack_op(SWITCH_OP);
        
        // pack condition value
        std::vector<uint8_t> packed_condition = GET_PACK_VALUE(inst->getCondition());
        hex_code.insert(hex_code.end(), packed_condition.begin(), packed_condition.end());
        
        // number of cases (excluding default)
        uint32_t num_cases = inst->getNumCases();
        std::vector<uint8_t> packed_num_cases = pack(num_cases, 4);
        hex_code.insert(hex_code.end(), packed_num_cases.begin(), packed_num_cases.end());
        
        // case value size (needed by interpreter to parse each case)
        int case_val_size = modDataLayout->getTypeAllocSize(inst->getCondition()->getType());
        std::vector<uint8_t> packed_case_size = pack(case_val_size, 4);
        hex_code.insert(hex_code.end(), packed_case_size.begin(), packed_case_size.end());
        
        // default case target (will be filled later)
        std::vector<uint8_t> padding = pack(0, pointer_size);
        int default_code_pos = vm_code.size() + hex_code.size();
        switch_map.push_back(std::make_tuple(default_code_pos, inst->getDefaultDest(), -1));
        hex_code.insert(hex_code.end(), padding.begin(), padding.end());
        
        // pack each case
        for (auto it = inst->case_begin(); it != inst->case_end(); ++it) {
            ConstantInt *case_value = it->getCaseValue();
            BasicBlock *case_bb = it->getCaseSuccessor();
            
            // pack case value
            int64_t case_val = case_value->getSExtValue();
            std::vector<uint8_t> packed_case_val = pack(case_val, case_val_size);
            hex_code.insert(hex_code.end(), packed_case_val.begin(), packed_case_val.end());
            
            // case target (will be filled later)
            int case_code_pos = vm_code.size() + hex_code.size();
            switch_map.push_back(std::make_tuple(case_code_pos, case_bb, (int)case_val));
            hex_code.insert(hex_code.end(), padding.begin(), padding.end());
        }
        
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
    }

    // ExtractValueInst支持 - 从结构体/数组中提取值
    else if(ExtractValueInst * inst = dyn_cast<ExtractValueInst>(ins)) {
        Value *aggregate = inst->getAggregateOperand();
        Type *aggType = aggregate->getType();
        
        // 计算偏移量
        unsigned offset = 0;
        Type *currentType = aggType;
        for (unsigned idx : inst->indices()) {
            if (StructType *ST = dyn_cast<StructType>(currentType)) {
                for (unsigned i = 0; i < idx; i++) {
                    offset += modDataLayout->getTypeAllocSize(ST->getElementType(i));
                }
                currentType = ST->getElementType(idx);
            } else if (ArrayType *AT = dyn_cast<ArrayType>(currentType)) {
                offset += idx * modDataLayout->getTypeAllocSize(AT->getElementType());
                currentType = AT->getElementType();
            }
        }
        
        // 结果值
        std::vector<uint8_t> packed_res = GET_PACK_VALUE(inst);
        
        // 聚合操作数
        std::vector<uint8_t> packed_agg = GET_PACK_VALUE(aggregate);
        
        // 偏移量作为常量
        std::vector<uint8_t> packed_offset = pack(offset, pointer_size);
        packed_offset.insert(packed_offset.begin(), 1);  // type = 1 (常量)
        packed_offset.insert(packed_offset.begin(), pointer_size);  // size
        
        // 结果类型大小
        int res_size = modDataLayout->getTypeAllocSize(inst->getType());
        std::vector<uint8_t> packed_size = pack(res_size, 4);
        
        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(EXTRACTVALUE_OP), packed_res, packed_agg, packed_offset, packed_size);
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
    }

    // UnreachableInst支持 - 生成无条件跳转到错误处理
    else if(isa<UnreachableInst>(ins)) {
        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(BR_OP));
        // 目标地址填0（表示退出VM）
        std::vector<uint8_t> packed_target = pack(0, pointer_size);
        hex_code.insert(hex_code.end(), packed_target.begin(), packed_target.end());
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
    }

    // C++ 异常处理指令 - 生成 NOP 或跳过
    // landingpad: 异常处理入口，返回异常对象和类型
    else if(isa<LandingPadInst>(ins)) {
        insert_to_value_map(&value_map, ins, curr_data_offset);
        int res_size = modDataLayout->getTypeAllocSize(ins->getType());
        curr_data_offset += res_size;
        // 生成 NOP - 异常处理在 VM 中不执行
        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(NOP_OP));
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
    }

    // resume: 恢复异常传播，生成 BR 到 0（退出）
    else if(isa<ResumeInst>(ins)) {
        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(BR_OP));
        std::vector<uint8_t> packed_target = pack(0, pointer_size);
        hex_code.insert(hex_code.end(), packed_target.begin(), packed_target.end());
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
    }

    // insertvalue: 插入值到聚合类型，简化为直接存储
    else if(InsertValueInst *inst = dyn_cast<InsertValueInst>(ins)) {
        insert_to_value_map(&value_map, inst, curr_data_offset);
        int res_size = modDataLayout->getTypeAllocSize(inst->getType());
        curr_data_offset += res_size;
        
        std::vector<uint8_t> packed_res = GET_PACK_VALUE(inst);
        std::vector<uint8_t> packed_agg = GET_PACK_VALUE(inst->getAggregateOperand());
        std::vector<uint8_t> packed_val = GET_PACK_VALUE(inst->getInsertedValueOperand());
        
        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(INSERTVALUE_OP), packed_res, packed_agg, packed_val);
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
    }

    // extractvalue: 从聚合类型提取值
    else if(ExtractValueInst *inst = dyn_cast<ExtractValueInst>(ins)) {
        insert_to_value_map(&value_map, inst, curr_data_offset);
        int res_size = modDataLayout->getTypeAllocSize(inst->getType());
        curr_data_offset += res_size;
        
        std::vector<uint8_t> packed_res = GET_PACK_VALUE(inst);
        std::vector<uint8_t> packed_agg = GET_PACK_VALUE(inst->getAggregateOperand());
        
        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(EXTRACTVALUE_OP), packed_res, packed_agg);
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
    }

    // CatchSwitchInst: 异常处理分发，生成 NOP
    else if(isa<CatchSwitchInst>(ins)) {
        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(NOP_OP));
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
    }

    // CatchReturnInst: 异常处理返回，生成 NOP
    else if(isa<CatchReturnInst>(ins)) {
        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(NOP_OP));
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
    }

    // CleanupReturnInst: 清理返回，生成 NOP
    else if(isa<CleanupReturnInst>(ins)) {
        std::vector<uint8_t> hex_code;
        ins_to_hex(hex_code, pack_op(NOP_OP));
        vm_code.insert(vm_code.end(), hex_code.begin(), hex_code.end());
    }

    else {
        failTranslation(Twine("unsupported instruction reached translator: ") +
                        ins->getOpcodeName());
    }
}


// Translator
bool GOVMTranslator::run(){
    curr_data_offset = 0;

    if (!F->getReturnType()->isVoidTy())
        curr_data_offset += modDataLayout->getTypeAllocSize(F->getReturnType());

    for (auto arg = F->arg_begin(); arg != F->arg_end(); ++arg) {
        Value *tmparg = &*arg;
        insert_to_value_map(&value_map, tmparg, curr_data_offset);
        curr_data_offset += modDataLayout->getTypeAllocSize(tmparg->getType());
    }

    if (curr_data_offset < 16)
        curr_data_offset = 16;
    if (curr_data_offset % pointer_size != 0)
        curr_data_offset += pointer_size - (curr_data_offset % pointer_size);
    if (!checkActualResourceUsage())
        return false;

    for (auto bbl = F->begin(); bbl != F->end(); ++bbl) {
        BasicBlock *bb = &*bbl;
        if (vm_code.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
            failTranslation("basic block offset exceeds signed-int range");
            return false;
        }
        const uint32_t block_header =
            static_cast<uint32_t>(vm_code.size());
        basicblock_map.emplace(bb, static_cast<int>(block_header));

        const uint32_t opcode_seed = opcode_seed_setup();
        const uint32_t vm_code_seed = vm_code_seed_setup();
        vm_code.resize(
            vm_code.size() + VMP_BLOCK_HEADER_SIZE - 8U, 0);
        const uint32_t currbb_begin =
            static_cast<uint32_t>(vm_code.size());

        std::vector<Instruction *> instructions_to_process;
        for (auto ins = bbl->begin(); ins != bbl->end(); ++ins)
            instructions_to_process.push_back(&*ins);

        for (Instruction *inst : instructions_to_process) {
            if (!inst || inst->getParent() != bb)
                continue;

            std::vector<std::pair<unsigned, ConstantExpr *>> const_exprs;
            for (unsigned idx = 0; idx < inst->getNumOperands(); ++idx) {
                if (ConstantExpr *Op = dyn_cast<ConstantExpr>(inst->getOperand(idx)))
                    const_exprs.emplace_back(idx, Op);
            }

            for (const auto &Item : const_exprs) {
                const unsigned idx = Item.first;
                ConstantExpr *Op = Item.second;
                Instruction *const_inst = Op->getAsInstruction();
                const_inst->insertBefore(inst->getIterator());
                inst->setOperand(idx, const_inst);
                handle_inst(const_inst);
                if (TranslationFailed)
                    return false;
            }

            handle_inst(inst);
            if (TranslationFailed || !checkActualResourceUsage())
                return false;
        }

        const uint32_t currbb_end = static_cast<uint32_t>(vm_code.size());
        vm_blocks.push_back({block_header, currbb_begin, currbb_end,
                             opcode_seed, vm_code_seed});
        if (!checkActualResourceUsage())
            return false;
    }

    for (auto it = br_map.rbegin(); it != br_map.rend(); ++it) {
        const int code_pos = it->first;
        auto bb_it = basicblock_map.find(it->second);
        if (bb_it == basicblock_map.end()) {
            failTranslation("branch target was not translated");
            return false;
        }
        const uint32_t target_offset = static_cast<uint32_t>(bb_it->second);
        const std::vector<uint8_t> bb_addr = pack(target_offset, pointer_size);
        if (code_pos < 0 ||
            static_cast<size_t>(code_pos) + pointer_size > vm_code.size()) {
            failTranslation("branch patch position is outside VM bytecode");
            return false;
        }
        std::copy(bb_addr.begin(), bb_addr.end(), vm_code.begin() + code_pos);
    }

    for (auto it = switch_map.rbegin(); it != switch_map.rend(); ++it) {
        const int code_pos = std::get<0>(*it);
        auto bb_it = basicblock_map.find(std::get<1>(*it));
        if (bb_it == basicblock_map.end()) {
            failTranslation("switch target was not translated");
            return false;
        }
        const uint32_t target_offset = static_cast<uint32_t>(bb_it->second);
        const std::vector<uint8_t> bb_addr = pack(target_offset, pointer_size);
        if (code_pos < 0 ||
            static_cast<size_t>(code_pos) + pointer_size > vm_code.size()) {
            failTranslation("switch patch position is outside VM bytecode");
            return false;
        }
        std::copy(bb_addr.begin(), bb_addr.end(), vm_code.begin() + code_pos);
    }

    if (!checkActualResourceUsage())
        return false;

    encrypt_vm_code();
    if (!seal_vm_blocks())
        return false;
    construct_gv();
    for (const auto &Item : callinst_map)
        handle_callinst(Item.first, Item.second);
    finish_callinst_handler();
    return !TranslationFailed;
}



/* ********************************************************************
*   GOVMMODIFIER_H
***********************************************************************
*/

#define GOVMMODIFIER_DEBUG

/***
 * The main class that modify the callsite of vm-function.
 */
class GOVMModifier {
    
    public:
        GOVMModifier(Function * F, std::map<GlobalVariable *, int> *gv_value_map, std::map<Value *, int> *value_map) {
            this->Mod = F->getParent();
            this->F = F;
            this->modDataLayout = const_cast<DataLayout *>(&this->Mod->getDataLayout());
            this->gv_value_map = gv_value_map;
            this->value_map = value_map;
        }

        Module * Mod;
        Function * F;
        DataLayout * modDataLayout;

        std::map<GlobalVariable *, int> *gv_value_map;
        std::map<Value *, int> *value_map;


        virtual void run ();


};



/* ********************************************************************
*   GOVMMODIFIER_CPP
***********************************************************************
*/

void GOVMModifier::run() {

    std::string orig_name = F->getName().str();
    
    F->deleteBody();
    
    BasicBlock* body_bbl = BasicBlock::Create(this->Mod->getContext(), "entry", F);
    IRBuilder<> irbuilder(body_bbl);

    assert(!F->isVarArg());

    std::vector<pair<Value*, int>> args_map;
    int arg_offset = 0;
    if (!F->getReturnType()->isVoidTy()) {
        arg_offset += modDataLayout->getTypeAllocSize(F->getReturnType());
    }

    for (auto arg = F->arg_begin(); arg != F->arg_end(); arg++) {
        Value *tmparg = &*arg;
        
        Value *paramPtr = irbuilder.CreateAlloca(tmparg->getType());
        irbuilder.CreateStore(tmparg, paramPtr);
        Value *currvalue = irbuilder.CreateLoad(tmparg->getType(), paramPtr);

        args_map.push_back(pair<Value *, int>(currvalue, arg_offset));
        arg_offset += modDataLayout->getTypeAllocSize(tmparg->getType());
    }

    for (auto p: *gv_value_map) {
        GlobalVariable *gv = p.first;
        int offset = p.second;

        Value * gv_addr_int = irbuilder.CreatePtrToInt(gv,Type::getInt64Ty(Mod->getContext()));

        ConstantInt *Zero = ConstantInt::get(Type::getInt64Ty(Mod->getContext()), 0);
        Value * offset_value = ConstantInt::get(Type::getInt64Ty(Mod->getContext()), offset);
        Value * gepinst = irbuilder.CreateGEP(gv_data_seg->getValueType(), gv_data_seg, {Zero, offset_value}, "");

        Value * ptr = irbuilder.CreatePointerCast(gepinst, PointerType::get(Mod->getContext(), 0));

        irbuilder.CreateStore(gv_addr_int, ptr);
    }

    std::map<int, std::pair<Value*, int>> wrapper_arg_to_orig;
    int wrapper_arg_idx = 0;
    for (auto arg = F->arg_begin(); arg != F->arg_end(); arg++, wrapper_arg_idx++) {
        auto orig_arg = F->arg_begin();
        std::advance(orig_arg, wrapper_arg_idx);
        
        if (value_map->find(&*orig_arg) != value_map->end()) {
            int orig_offset = (*value_map)[&*orig_arg];
            wrapper_arg_to_orig[wrapper_arg_idx] = std::make_pair(&*arg, orig_offset);
        }
    }
    
    int temp_arg_idx = 0;
    for (auto arg = F->arg_begin(); arg != F->arg_end(); arg++, temp_arg_idx++) {
        Value *tmparg = &*arg;
        
        Value *paramPtr = irbuilder.CreateAlloca(tmparg->getType());
        irbuilder.CreateStore(tmparg, paramPtr);
        Value *currvalue = irbuilder.CreateLoad(tmparg->getType(), paramPtr);
        
        int offset = wrapper_arg_to_orig[temp_arg_idx].second;
        
        ConstantInt *Zero = ConstantInt::get(Type::getInt64Ty(F->getContext()), 0);
        Value * const_curr_value_offset = ConstantInt::get(Type::getInt64Ty(F->getContext()), offset);
        Value * gepinst = irbuilder.CreateGEP(gv_data_seg->getValueType(), gv_data_seg, {Zero, const_curr_value_offset}, "");

        Value * ptr = irbuilder.CreatePointerCast(gepinst, PointerType::get(F->getContext(), 0));
        
        irbuilder.CreateStore(currvalue, ptr);
    }

    Value * data_seg_ptr2int = irbuilder.CreatePtrToInt(gv_data_seg, Type::getInt64Ty(Mod->getContext()));
    irbuilder.CreateStore(data_seg_ptr2int, data_seg_addr);
    Value * code_seg_ptr2int = irbuilder.CreatePtrToInt(gv_code_seg, Type::getInt64Ty(Mod->getContext()));
    irbuilder.CreateStore(code_seg_ptr2int, code_seg_addr);

    irbuilder.CreateCall(govm_interpreter);

    if (!F->getReturnType()->isVoidTy()) {
        ConstantInt *Zero = ConstantInt::get(Type::getInt64Ty(F->getContext()), 0);
        Value * gepinst = irbuilder.CreateGEP(gv_data_seg->getValueType(), gv_data_seg, {Zero, Zero}, "");
        Value * ptr = irbuilder.CreatePointerCast(gepinst, PointerType::get(F->getContext(), 0));
        Value * retval = irbuilder.CreateLoad(F->getReturnType(), ptr);
        irbuilder.CreateRet(retval);
    }
    else {
        irbuilder.CreateRetVoid();
    }
}



/* ********************************************************************
*   GOVMINTERPRETER_H
***********************************************************************
*/

#define GOVMINTERPRETER_DEBUG


/***
 * The main class that construct the interpreter of vm-function.
 */
class GOVMInterpreter {
    
    public:
        GOVMInterpreter(Function *F, Function *callinst_handler,
                        uint64_t CodeSegmentSize,
                        uint64_t DataSegmentSize,
                        uint64_t IntegrityKey0,
                        uint64_t IntegrityKey1,
                        uint64_t RuntimeStepLimit,
                        uint64_t RuntimeCallLimit,
                        uint64_t RuntimeCallDepthLimit) {
            this->Mod = F->getParent();
            this->F = F;
            this->modDataLayout =
                const_cast<DataLayout *>(&this->Mod->getDataLayout());
            this->callinst_handler = callinst_handler;
            this->CodeSegmentSize = CodeSegmentSize;
            this->DataSegmentSize = DataSegmentSize;
            this->IntegrityKey0 = IntegrityKey0;
            this->IntegrityKey1 = IntegrityKey1;
            this->RuntimeStepLimit = RuntimeStepLimit;
            this->RuntimeCallLimit = RuntimeCallLimit;
            this->RuntimeCallDepthLimit = RuntimeCallDepthLimit;

            construct_gv();
        }


        Module * Mod;
        Function * F;
        DataLayout * modDataLayout;

        Function *callinst_handler;
        uint64_t CodeSegmentSize = 0;
        uint64_t DataSegmentSize = 0;
        uint64_t IntegrityKey0 = 0;
        uint64_t IntegrityKey1 = 0;
        uint64_t RuntimeStepLimit = 0;
        uint64_t RuntimeCallLimit = 0;
        uint64_t RuntimeCallDepthLimit = 0;

        GlobalVariable *pointer_size_gv;
        GlobalVariable *opcode_xorshift32_state;
        GlobalVariable *vm_code_state;
        GlobalVariable *code_seg_size_gv;
        GlobalVariable *data_seg_size_gv;
        GlobalVariable *vm_fault_gv;
        GlobalVariable *integrity_key0_gv;
        GlobalVariable *integrity_key1_gv;
        GlobalVariable *block_end_gv;
        GlobalVariable *step_limit_gv;
        GlobalVariable *call_limit_gv;
        GlobalVariable *call_depth_limit_gv;
        GlobalVariable *steps_remaining_gv;
        GlobalVariable *calls_remaining_gv;
        GlobalVariable *call_depth_gv;
        GlobalVariable *frame_active_gv;

        virtual bool run ();
        virtual void construct_gv ();


        Module *llvm_parse_bitcode_from_string()
        {
            // Use the new binary_ir_data array
            std::vector<char> binary_ir = get_binary_ir();
            
            StringRef str_ref(binary_ir.data(), binary_ir.size());
            MemoryBufferRef buf_ref = MemoryBufferRef(str_ref, "aVMPInterpreter.bc");
            
            // Try parseBitcodeFile first (more reliable for embedded bitcode)
            Expected<std::unique_ptr<Module>> ModuleOrErr = parseBitcodeFile(buf_ref, Mod->getContext());
            if (!ModuleOrErr) {
                return nullptr;
            }
            
            return ModuleOrErr.get().release();
        }

        Module *llvm_parse_bitcode()
        {
            SMDiagnostic Err;
            // LLVMContext *LLVMCtx = new LLVMContext();
            LLVMContext *LLVMCtx = &Mod->getContext();          // match Mod context
            unique_ptr<Module> M = parseIRFile("../c-implement/govm.bc", Err, *LLVMCtx);
            return M.release();
        }

};


#define IS_INLINE_FUNC

// memcpy functions: for points to and taint propagation.
const std::set<std::string> interpreter_function_names{
#ifndef IS_INLINE_FUNC
                                                        "xorshift32",
                                                        "get_byte_code",
                                                        "get_xorshift_seed",
                                                        "unpack_code",
                                                        "unpack_data",
                                                        "unpack_addr",
                                                        "pack_store_addr", 
                                                        "get_value_with_size", 
                                                        "get_value",
                                                        "alloca_handler",
                                                        "load_handler",
                                                        "store_handler",
                                                        "binaryOperator_handler",
                                                        "gep_handler",
                                                        "cmp_handler",
                                                        "cast_handler",
                                                        "br_handler",
                                                        "return_handler",
                                                        "get_opcode",
#endif
                                                        "vm_interpreter",
                                                        "vm_interpreter_callinst_dispatch"      // only for check annotation

                                                        };



// check targetfunction is c-implement functions
        bool is_interpreter_function(Function *targetFunction) {
            if(!targetFunction->isDeclaration() && targetFunction->hasName()) {
                std::string func_name = targetFunction->getName().str();
                // errs() << "is_interpreter_function: " << func_name << "\n";
                for (const std::string &curr_func: interpreter_function_names) {
                    if (func_name.find(curr_func.c_str()) != std::string::npos) {
                    // if (targetFunction->getName().str() == curr_func.c_str()) {
                        return true;
                    }
                }
            }
            return false;
        }
        std::string get_vm_function_name(Function *targetFunction) {
            if(!targetFunction->isDeclaration() && targetFunction->hasName()) {
                std::string func_name = targetFunction->getName().str();
                // errs() << "is_interpreter_function: " << func_name << "\n";
                for (const std::string &curr_func: interpreter_function_names) {
                    size_t pos = func_name.find(curr_func.c_str());
                    if (pos != std::string::npos) {
                        if (func_name.length() <= pos+curr_func.length()) {
                            // just vm function self
                            return func_name;
                        } else {
                            return func_name.substr(pos+curr_func.length()+1);
                        }
                    }
                }
            }
            return "";
        }


/* ********************************************************************
*   GOVMINTERPRETER_CPP
***********************************************************************
*/

void GOVMInterpreter::construct_gv() {
    // pointer_size - 根据目标架构动态设置（必须是可修改的，因为解释器会设置它）
    unsigned ptr_size = modDataLayout->getPointerSize();
    Constant *pointer_size_initGV = ConstantInt::get(Type::getInt32Ty(Mod->getContext()), ptr_size);
    pointer_size_gv = new GlobalVariable(*Mod, Type::getInt32Ty(Mod->getContext()), 
                false,  GlobalValue::InternalLinkage, 
                pointer_size_initGV, "pointer_size_"+F->getName());
    pointer_size_gv->setThreadLocal(true);

    // opcode_xorshift32_state      32bit
    Constant *opcode_xorshift32_state_initGV = ConstantInt::get(Type::getInt32Ty(Mod->getContext()), 0);
    opcode_xorshift32_state = new GlobalVariable(*Mod, Type::getInt32Ty(Mod->getContext()), 
                false,  GlobalValue::InternalLinkage, 
                opcode_xorshift32_state_initGV, "opcode_xorshift32_state_"+F->getName());
    opcode_xorshift32_state->setThreadLocal(true);

    // vm_code_state                32bit
    Constant *vm_code_state_initGV = ConstantInt::get(Type::getInt32Ty(Mod->getContext()), 0);
    vm_code_state = new GlobalVariable(*Mod, Type::getInt32Ty(Mod->getContext()), 
                false,  GlobalValue::InternalLinkage, 
                vm_code_state_initGV, "vm_code_state_"+F->getName());
    vm_code_state->setThreadLocal(true);

    Constant *code_size_init = ConstantInt::get(
        Type::getInt64Ty(Mod->getContext()), CodeSegmentSize);
    code_seg_size_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), true,
        GlobalValue::InternalLinkage, code_size_init,
        "code_seg_size_" + F->getName());

    Constant *data_size_init = ConstantInt::get(
        Type::getInt64Ty(Mod->getContext()), DataSegmentSize);
    data_seg_size_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), true,
        GlobalValue::InternalLinkage, data_size_init,
        "data_seg_size_" + F->getName());

    Constant *fault_init = ConstantInt::get(
        Type::getInt32Ty(Mod->getContext()), 0);
    vm_fault_gv = new GlobalVariable(
        *Mod, Type::getInt32Ty(Mod->getContext()), false,
        GlobalValue::InternalLinkage, fault_init,
        "vm_fault_" + F->getName());
    vm_fault_gv->setThreadLocal(true);


    Constant *key0_init = ConstantInt::get(
        Type::getInt64Ty(Mod->getContext()), IntegrityKey0);
    integrity_key0_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), true,
        GlobalValue::InternalLinkage, key0_init,
        "vm_integrity_key0_" + F->getName());

    Constant *key1_init = ConstantInt::get(
        Type::getInt64Ty(Mod->getContext()), IntegrityKey1);
    integrity_key1_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), true,
        GlobalValue::InternalLinkage, key1_init,
        "vm_integrity_key1_" + F->getName());

    Constant *zero64 = ConstantInt::get(
        Type::getInt64Ty(Mod->getContext()), 0);
    block_end_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), false,
        GlobalValue::InternalLinkage, zero64,
        "vm_block_end_" + F->getName());
    block_end_gv->setThreadLocal(true);

    step_limit_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), true,
        GlobalValue::InternalLinkage,
        ConstantInt::get(Type::getInt64Ty(Mod->getContext()), RuntimeStepLimit),
        "vm_step_limit_" + F->getName());
    call_limit_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), true,
        GlobalValue::InternalLinkage,
        ConstantInt::get(Type::getInt64Ty(Mod->getContext()), RuntimeCallLimit),
        "vm_call_limit_" + F->getName());
    call_depth_limit_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), true,
        GlobalValue::InternalLinkage,
        ConstantInt::get(Type::getInt64Ty(Mod->getContext()),
                         RuntimeCallDepthLimit),
        "vm_call_depth_limit_" + F->getName());

    steps_remaining_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), false,
        GlobalValue::InternalLinkage, zero64,
        "vm_steps_remaining_" + F->getName());
    steps_remaining_gv->setThreadLocal(true);
    calls_remaining_gv = new GlobalVariable(
        *Mod, Type::getInt64Ty(Mod->getContext()), false,
        GlobalValue::InternalLinkage, zero64,
        "vm_calls_remaining_" + F->getName());
    calls_remaining_gv->setThreadLocal(true);

    call_depth_gv =
        Mod->getGlobalVariable("__allvm_vmp_call_depth", true);
    if (call_depth_gv == nullptr) {
        call_depth_gv = new GlobalVariable(
            *Mod, Type::getInt64Ty(Mod->getContext()), false,
            GlobalValue::InternalLinkage, zero64,
            "__allvm_vmp_call_depth");
        call_depth_gv->setThreadLocal(true);
    } else if (call_depth_gv->getValueType() !=
               Type::getInt64Ty(Mod->getContext())) {
        report_fatal_error("ALLVM VMP call-depth TLS has an invalid type");
    }

    frame_active_gv = new GlobalVariable(
        *Mod, Type::getInt32Ty(Mod->getContext()), false,
        GlobalValue::InternalLinkage, fault_init,
        "vm_frame_active_" + F->getName());
    frame_active_gv->setThreadLocal(true);
}

// Function *govm_interpreter;

bool GOVMInterpreter::run() {

    Module *interpreter_module = llvm_parse_bitcode_from_string();
    if (!interpreter_module) {
        return false;
    }

    // replace GlobalVariable 
    std::vector<std::string> gv_list = {
        "ip", "data_seg_addr", "code_seg_addr", "pointer_size",
        "opcode_xorshift32_state", "vm_code_state",
        "code_seg_size", "data_seg_size", "vm_fault",
        "vm_integrity_key0", "vm_integrity_key1", "vm_block_end",
        "vm_step_limit", "vm_call_limit", "vm_call_depth_limit",
        "vm_steps_remaining", "vm_calls_remaining", "vm_call_depth",
        "vm_frame_active"};
    std::vector<GlobalVariable *> new_gv_list = {
        ip, data_seg_addr, code_seg_addr, pointer_size_gv,
        opcode_xorshift32_state, vm_code_state, code_seg_size_gv,
        data_seg_size_gv, vm_fault_gv, integrity_key0_gv,
        integrity_key1_gv, block_end_gv, step_limit_gv, call_limit_gv,
        call_depth_limit_gv, steps_remaining_gv, calls_remaining_gv,
        call_depth_gv, frame_active_gv};
    for (unsigned i = 0; i < gv_list.size(); i++) {
        GlobalVariable *old_gv = interpreter_module->getGlobalVariable(gv_list[i]);
        if (!old_gv) {
            continue;
        }
        GlobalVariable *new_gv = new_gv_list[i];
        if (!new_gv) {
            continue;
        }
        
        old_gv->replaceAllUsesWith(new_gv);
    }

    // replace call_handler
    Function *old_func = interpreter_module->getFunction("call_handler");
    if (old_func && callinst_handler) {
        old_func->replaceAllUsesWith(callinst_handler);
    }

    // clone functions
    // First, collect all function declarations from interpreter module
    // and add them to target module (including intrinsics)
    for(auto Func = interpreter_module->begin(); Func != interpreter_module->end(); ++Func) {
        Function *fun = &*Func;
        if(fun->isDeclaration()) {
            // Check if function already exists in target module
            if(!Mod->getFunction(fun->getName())) {
                FunctionCallee FC = Mod->getOrInsertFunction(fun->getName().str(), fun->getFunctionType());
                Function *NewF = cast<Function>(FC.getCallee());
                NewF->setLinkage(fun->getLinkage());
            }
        }
    }
    
    for(auto Func = interpreter_module->begin();Func!=interpreter_module->end();++Func)
        {
            
            Function *fun = &*Func;

            if(is_interpreter_function(fun)) {
                FunctionCallee FC = Mod->getOrInsertFunction(fun->getName().str(), fun->getFunctionType());
                Function *NewF = cast<Function>(FC.getCallee());
                NewF->setLinkage(llvm::GlobalValue::LinkageTypes::InternalLinkage);


                ValueToValueMapTy VMap;
                SmallVector<ReturnInst*, 8> returns;

                for (Instruction &I : instructions(fun)) {
                    if (CallBase *CB = dyn_cast<CallBase>(&I)) {
                        Function *Callee = CB->getCalledFunction();
                        if (Callee && Callee != fun) {
                            Function *TargetCallee = Mod->getFunction(Callee->getName());
                            if (!TargetCallee && Callee->isDeclaration()) {
                                FunctionCallee FC2 = Mod->getOrInsertFunction(Callee->getName().str(), Callee->getFunctionType());
                                TargetCallee = cast<Function>(FC2.getCallee());
                                TargetCallee->setLinkage(Callee->getLinkage());
                            }
                            if (TargetCallee) {
                                VMap[Callee] = TargetCallee;
                            }
                        }
                    }
                }

                Function::arg_iterator DestI = NewF->arg_begin();

                for (const Argument & I : fun->args())
                    if (VMap.count(&I) == 0) {
                        DestI->setName(I.getName());
                        VMap[&I] = &*DestI++;
                    }

                CloneFunctionInto(NewF, fun, VMap, CloneFunctionChangeType::DifferentModule, returns);

                NewF->setName(fun->getName()+"_"+F->getName());

                std::vector<CallInst *> F_users;
                for (User *U : fun->users()) {
                    if (CallInst *CI = dyn_cast<CallInst>(U)) {
                        F_users.push_back(CI);
                    }
                }

                // replace references
                for (CallInst *CI: F_users) {
                    // errs() << "[*] Replacing references: " << *CI << "\n";
                    CI->setCalledFunction(NewF);
                }
                
            }

            
        }
    
    
    // remove all function of interpreter_module
    while(true) {
        bool flag = true;
        for(auto Func = interpreter_module->begin(), Funcend = interpreter_module->end();Func!=Funcend;++Func) {

            Function *fun = dyn_cast<Function>(&*Func);
            
            if(fun->use_empty()) {
                // errs() << "[*] Removing function: " << fun->getName().str() << "\n";
                flag = false;
                fun->eraseFromParent();
                break;
            }
        }
        if (flag)
            break;
    }

    
    govm_interpreter = Mod->getFunction("vm_interpreter_"+F->getName().str());
    return govm_interpreter != nullptr;
}
namespace {


    std::string readAnnotate(Function *f) {
        std::string annotation = "";

        // Get annotation variable
        GlobalVariable *glob =
            f->getParent()->getGlobalVariable("llvm.global.annotations");

        if (glob != NULL && glob->hasInitializer()) {
            Constant *init = glob->getInitializer();
            if (!init) return annotation;
            
            // Get the array
            if (ConstantArray *ca = dyn_cast<ConstantArray>(init)) {
            for (unsigned i = 0; i < ca->getNumOperands(); ++i) {
                // Get the struct
                if (ConstantStruct *structAn =
                        dyn_cast<ConstantStruct>(ca->getOperand(i))) {
                    
                // Get the annotated function
                // Can be a ConstantExpr (BitCast) or a direct Function pointer
                Function *annotatedFunc = nullptr;
                Value *op0 = structAn->getOperand(0);
                
                if (ConstantExpr *expr = dyn_cast<ConstantExpr>(op0)) {
                    // It's a ConstantExpr (e.g., BitCast)
                    if (expr->getOpcode() == Instruction::BitCast) {
                        annotatedFunc = dyn_cast<Function>(expr->getOperand(0));
                    }
                } else if (Function *directFunc = dyn_cast<Function>(op0)) {
                    // It's a direct Function pointer
                    annotatedFunc = directFunc;
                }
                
                if (annotatedFunc == f) {
                    // Found annotation for this function
                    // Get the annotation string
                    // Can be a ConstantExpr (GetElementPtr) or a direct GlobalVariable
                    Value *op1 = structAn->getOperand(1);
                    GlobalVariable *annoteStr = nullptr;
                    
                    if (ConstantExpr *note = dyn_cast<ConstantExpr>(op1)) {
                        // It's a ConstantExpr (e.g., GetElementPtr)
                        if (note->getOpcode() == Instruction::GetElementPtr) {
                            annoteStr = dyn_cast<GlobalVariable>(note->getOperand(0));
                        }
                    } else if (GlobalVariable *directGV = dyn_cast<GlobalVariable>(op1)) {
                        // It's a direct GlobalVariable pointer
                        annoteStr = directGV;
                    }
                    
                    if (annoteStr) {
                        if (ConstantDataSequential *data =
                                dyn_cast<ConstantDataSequential>(annoteStr->getInitializer())) {
                            if (data->isString()) {
                                annotation += data->getAsString().lower() + " ";
                            }
                        }
                    }
                }
                }
            }
            }
        }
        return annotation;
        }
    bool toObfuscateModule(bool global_flag,Module* M,std::string attribute)
        {
        std::string attr = "cpp_" + attribute;
        std::string noattr = "cpp_no" + attribute;
        for(auto Func = M->begin();Func!=M->end();++Func)
        {
            if(Function * f = dyn_cast<Function>(Func))
            {
            if (readAnnotate(f).find(attr) != std::string::npos)
            {
                return true;
            }
            if (readAnnotate(f).find(noattr) != std::string::npos)
            {
                return false;
            }
            }
        }
        return global_flag;
            
        }

    std::set<string> used_passes;
    bool toObfuscateFunction(bool global_flag, Function *f, std::string attribute) {
        std::string attr = attribute;
        std::string attrNo = "no" + attr;
        
        // 读取注解
        std::string annotation = readAnnotate(f);
        
        // 检查是否有novmp注解
        if (annotation.find(attrNo) != std::string::npos) {
            return false;
        }

        // 检查是否有vmp注解
        if (annotation.find(attr) != std::string::npos) {
            used_passes.insert(attribute);
            return true;
        }
        
        // VMP只处理有明确vmp注解的函数，不处理没有注解的函数
        // 这与FLA等其他混淆不同，因为VMP会显著改变函数结构
        return false;
    }

static void eraseUnusedGlobal(GlobalValue *Value) {
    if (Value != nullptr && Value->use_empty())
        Value->eraseFromParent();
}

static void cleanupFailedVMP(GOVMTranslator &Translator,
                             GOVMInterpreter *Interpreter = nullptr) {
    eraseUnusedGlobal(Translator.get_callinst_handler());
    if (Interpreter != nullptr) {
        eraseUnusedGlobal(Interpreter->pointer_size_gv);
        eraseUnusedGlobal(Interpreter->opcode_xorshift32_state);
        eraseUnusedGlobal(Interpreter->vm_code_state);
        eraseUnusedGlobal(Interpreter->code_seg_size_gv);
        eraseUnusedGlobal(Interpreter->data_seg_size_gv);
        eraseUnusedGlobal(Interpreter->vm_fault_gv);
        eraseUnusedGlobal(Interpreter->integrity_key0_gv);
        eraseUnusedGlobal(Interpreter->integrity_key1_gv);
        eraseUnusedGlobal(Interpreter->block_end_gv);
        eraseUnusedGlobal(Interpreter->step_limit_gv);
        eraseUnusedGlobal(Interpreter->call_limit_gv);
        eraseUnusedGlobal(Interpreter->call_depth_limit_gv);
        eraseUnusedGlobal(Interpreter->steps_remaining_gv);
        eraseUnusedGlobal(Interpreter->calls_remaining_gv);
        eraseUnusedGlobal(Interpreter->call_depth_gv);
        eraseUnusedGlobal(Interpreter->frame_active_gv);
    }
    eraseUnusedGlobal(gv_code_seg);
    eraseUnusedGlobal(gv_data_seg);
    eraseUnusedGlobal(ip);
    eraseUnusedGlobal(data_seg_addr);
    eraseUnusedGlobal(code_seg_addr);
    resetVMPGlobals();
}

static bool runVMPOnFunction(Function &F) {
    resetVMPGlobals();
    const allvm::VMPResourceLimits Limits = currentVMPResourceLimits();
    GOVMTranslator Translator(&F, Limits);
    if (!Translator.run()) {
        errs() << "[VMP] Translation failed for '" << F.getName()
               << "': " << Translator.getTranslationError() << "\n";
        cleanupFailedVMP(Translator);
        return false;
    }

    GOVMInterpreter Interpreter(
        &F, Translator.get_callinst_handler(),
        Translator.getCodeSegmentSize(), Translator.getDataSegmentSize(),
        Translator.getIntegrityKey0(), Translator.getIntegrityKey1(),
        static_cast<uint64_t>(VMPMaxRuntimeSteps),
        static_cast<uint64_t>(VMPMaxRuntimeCalls),
        static_cast<uint64_t>(VMPMaxCallDepth));
    if (!Interpreter.run()) {
        errs() << "[VMP] Embedded interpreter setup failed for '"
               << F.getName() << "'\n";
        cleanupFailedVMP(Translator, &Interpreter);
        return false;
    }

    prepareVMPFunction(F);
    GOVMModifier Modifier(&F, Translator.get_gv_value_map(),
                          Translator.get_value_map());
    Modifier.run();
    if (verifyFunction(F, &errs()))
        report_fatal_error(
            Twine("legacy VMP produced invalid IR for '") +
            F.getName() + "'");
    return true;
}

struct VMProtect : public ModulePass {
  static char ID;
  bool flag;

  VMProtect() : ModulePass(ID), flag(false) {}
  explicit VMProtect(bool flag) : ModulePass(ID), flag(flag) {}

  bool runOnModule(Module &M) override {
    if (!isLicenseValidated())
      return false;

    std::vector<Function *> FunctionsToProcess;
    for (Function &F : M) {
      if (!toObfuscateFunction(flag, &F, "vmp"))
        continue;
      if (!validateVMPFunction(F))
        continue;
      FunctionsToProcess.push_back(&F);
    }

    bool Changed = false;
    for (Function *F : FunctionsToProcess) {
      errs() << "[VMP] Processing function: " << F->getName() << "\n";
      if (runVMPOnFunction(*F)) {
        Changed = true;
        if (isIRObfuscationDebugEnabled())
          errs() << "[VMP] Function done: " << F->getName() << "\n";
      }
    }
    return Changed;
  }
};
} // end of anonymous namespace

char VMProtect::ID = 0;
static RegisterPass<VMProtect> X("aVMP", "aVMP", false, true);
Pass *llvm::createVMProtectPass(bool flag) {
  return new VMProtect(flag);
}

PreservedAnalyses llvm::VMProtectPass::run(Module &M,
                                           ModuleAnalysisManager &AM) {
  (void)AM;
  std::vector<Function *> FunctionsToProcess;
  for (Function &F : M) {
    if (!toObfuscateFunction(flag, &F, "vmp"))
      continue;
    if (!validateVMPFunction(F))
      continue;
    FunctionsToProcess.push_back(&F);
  }

  bool Changed = false;
  for (Function *F : FunctionsToProcess)
    Changed |= runVMPOnFunction(*F);

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
#endif

