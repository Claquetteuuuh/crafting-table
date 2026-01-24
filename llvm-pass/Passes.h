#ifndef OBFU_PASSES_H
#define OBFU_PASSES_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"

namespace llvm {
    // Passe de Fonctions (Opaque Constants)
    class ReplaceNullByPrimeFormulaPass : public PassInfoMixin<ReplaceNullByPrimeFormulaPass> {
    public:
        PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM);
    };

    // Passe de Module (Strings)
    class StringShufflePass : public PassInfoMixin<StringShufflePass> {
    public:
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
    };
}

#endif