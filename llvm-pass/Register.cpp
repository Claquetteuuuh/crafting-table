#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "Passes.h"

using namespace llvm;

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "MyModernObfuscator", LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM, ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "replace-null-by-prime-formula") {
                        FPM.addPass(ReplaceNullByPrimeFormulaPass());
                        return true;
                    }
                    return false;
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "shuffle-strings") {
                        MPM.addPass(StringShufflePass());
                        return true;
                    }
                    return false;
                });
        }
    };
}