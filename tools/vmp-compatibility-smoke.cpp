//===- vmp-compatibility-smoke.cpp - VMP preflight smoke test -----------===//
//
// Parses a compact LLVM IR module and verifies that the conservative VMP
// preflight accepts the supported scalar subset while rejecting constructs
// that the current uint64-based interpreter cannot preserve.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscation/VMPCompatibility.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <memory>
#include <string>

using namespace llvm;

namespace {

bool hasReason(const allvm::VMPCompatibilityResult &Result,
               StringRef Needle) {
  for (const std::string &Reason : Result.Reasons)
    if (StringRef(Reason).contains(Needle))
      return true;
  return false;
}

void printResult(StringRef Name,
                 const allvm::VMPCompatibilityResult &Result) {
  errs() << "VMP preflight result for '" << Name << "': "
         << (Result.Supported ? "supported" : "rejected") << "\n";
  errs() << "  basic blocks: " << Result.BasicBlockCount << "\n";
  errs() << "  instructions: " << Result.InstructionCount << "\n";
  errs() << "  estimated code bytes: " << Result.EstimatedCodeBytes << "\n";
  errs() << "  estimated data bytes: " << Result.EstimatedDataBytes << "\n";
  for (const std::string &Reason : Result.Reasons)
    errs() << "  - " << Reason << "\n";
}

bool expect(Function *F, bool Supported, StringRef Reason = {},
            const allvm::VMPResourceLimits &Limits = {}) {
  if (F == nullptr) {
    errs() << "missing test function\n";
    return false;
  }

  const allvm::VMPCompatibilityResult Result =
      allvm::analyzeVMPFunction(*F, Limits);
  if (Result.Supported != Supported ||
      (!Reason.empty() && !hasReason(Result, Reason))) {
    printResult(F->getName(), Result);
    errs() << "expected supported=" << Supported;
    if (!Reason.empty())
      errs() << " and a reason containing '" << Reason << "'";
    errs() << "\n";
    return false;
  }
  return true;
}

} // namespace

int main() {
  static constexpr char IR[] = R"IR(
    target datalayout = "e-p:64:64"

    %Padded = type { i8, i32 }

    declare i32 @variadic(ptr, ...)

    define i32 @supported(i32 %a, i32 %b) {
    entry:
      %sum = add i32 %a, %b
      %small = icmp ult i32 %sum, 100
      br i1 %small, label %return_sum, label %return_difference

    return_sum:
      ret i32 %sum

    return_difference:
      %difference = sub i32 %a, %b
      ret i32 %difference
    }

    define ptr @null_pointer() {
    entry:
      ret ptr null
    }

    define ptr @padded_gep(ptr %base) {
    entry:
      %field = getelementptr %Padded, ptr %base, i64 0, i32 1
      ret ptr %field
    }

    define i32 @with_phi(i1 %condition, i32 %left_value, i32 %right_value) {
    entry:
      br i1 %condition, label %left, label %right

    left:
      br label %merge

    right:
      br label %merge

    merge:
      %value = phi i32 [ %left_value, %left ], [ %right_value, %right ]
      ret i32 %value
    }

    define i32 @atomic_load(ptr %address) {
    entry:
      %value = load atomic i32, ptr %address seq_cst, align 4
      ret i32 %value
    }

    define i32 @signed_compare(i32 %left, i32 %right) {
    entry:
      %less = icmp slt i32 %left, %right
      %result = zext i1 %less to i32
      ret i32 %result
    }

    define i1 @floating_compare(double %left, double %right) {
    entry:
      %less = fcmp olt double %left, %right
      ret i1 %less
    }

    define <2 x i32> @vector_value(<2 x i32> %value) {
    entry:
      ret <2 x i32> %value
    }

    define i32 @recursive(i32 %value) {
    entry:
      %next = call i32 @recursive(i32 %value)
      ret i32 %next
    }

    define i32 @variadic_call(ptr %format) {
    entry:
      %result = call i32 (ptr, ...) @variadic(ptr %format, i32 7)
      ret i32 %result
    }

    define i32 @undef_value() {
    entry:
      ret i32 undef
    }

    define ptr @dynamic_alloca(i64 %count) {
    entry:
      %buffer = alloca i8, i64 %count
      ret ptr %buffer
    }
  )IR";

  LLVMContext Context;
  SMDiagnostic Diagnostic;
  std::unique_ptr<Module> M = parseAssemblyString(IR, Diagnostic, Context);
  if (!M) {
    Diagnostic.print("vmp-compatibility-smoke", errs());
    return 1;
  }

  bool Ok = true;
  Ok &= expect(M->getFunction("supported"), true);
  Ok &= expect(M->getFunction("null_pointer"), true);
  Ok &= expect(M->getFunction("padded_gep"), true);
  Ok &= expect(M->getFunction("with_phi"), false, "PHI");
  Ok &= expect(M->getFunction("atomic_load"), false, "atomic");
  Ok &= expect(M->getFunction("signed_compare"), false, "有符号");
  Ok &= expect(M->getFunction("floating_compare"), false, "浮点比较");
  Ok &= expect(M->getFunction("vector_value"), false, "向量");
  Ok &= expect(M->getFunction("recursive"), false, "直接递归");
  Ok &= expect(M->getFunction("variadic_call"), false, "可变参数调用");
  Ok &= expect(M->getFunction("undef_value"), false, "undef/poison");
  Ok &= expect(M->getFunction("dynamic_alloca"), false, "动态或数组 alloca");

  allvm::VMPResourceLimits TightLimits;
  TightLimits.MaxInstructions = 1;
  Ok &= expect(M->getFunction("supported"), false, "超过限制", TightLimits);

  if (!Ok)
    return 2;

  outs() << "VMP compatibility smoke test passed\n";
  return 0;
}
