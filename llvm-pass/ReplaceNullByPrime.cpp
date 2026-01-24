#include "Passes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include <vector>
#include <random>

using namespace llvm;

namespace {
    using prime_type = uint32_t;
    static const prime_type Prime_array[] = {
         2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 
         73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 
         157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 
         239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 
         331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 
         421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 
         509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 
         613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 
         709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 
         821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 
         919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997
    };
}

PreservedAnalyses ReplaceNullByPrimeFormulaPass::run(Function &F, FunctionAnalysisManager &FAM) {
    bool modified = false;
    std::vector<Value *> IntegerVect;
    std::default_random_engine Generator(std::random_device{}());

    auto isValidInstruction = [](Instruction &I) {
        return !(isa<GetElementPtrInst>(I) || isa<SwitchInst>(I) || isa<PHINode>(I) || isa<CallBase>(I));
    };

    auto getPrime = [&](uint32_t DiffFrom = 0) {
        std::uniform_int_distribution<size_t> Dist(0, 167);
        uint32_t p;
        do { p = Prime_array[Dist(Generator)]; } while (p == DiffFrom);
        return p;
    };

    for (auto &BB : F) {
        IntegerVect.clear();
        for (Instruction &Inst : BB) {
            if (isValidInstruction(Inst)) {
                for (size_t i = 0; i < Inst.getNumOperands(); ++i) {
                    Value *Op = Inst.getOperand(i);
                    ConstantInt *CI = dyn_cast<ConstantInt>(Op);
                    if (CI && CI->isZero() && !IntegerVect.empty()) {
                        uint32_t p1 = getPrime(), p2 = getPrime(p1);
                        IRBuilder<> B(&Inst);
                        Type *ITy = B.getInt32Ty();
                        Value *V1 = IntegerVect[std::uniform_int_distribution<size_t>(0, IntegerVect.size()-1)(Generator)];
                        Value *V2 = IntegerVect[std::uniform_int_distribution<size_t>(0, IntegerVect.size()-1)(Generator)];
                        
                        auto buildEq = [&](Value *V, uint32_t p, uint32_t any) {
                            Value *Cast = B.CreateZExtOrTrunc(V, ITy);
                            Value *Base = B.CreateOr(B.CreateAnd(Cast, B.getInt32(7)), B.getInt32(any));
                            return B.CreateMul(B.CreateMul(Base, Base), B.getInt32(p));
                        };

                        Value *Eq1 = buildEq(V1, p1, 3);
                        Value *Eq2 = buildEq(V2, p2, 5);
                        Value *Comp = B.CreateZExt(B.CreateICmpEQ(Eq1, Eq2), Op->getType());
                        Inst.setOperand(i, Comp);
                        modified = true;
                    }
                }
            }
            if (Inst.getType()->isIntegerTy()) IntegerVect.push_back(&Inst);
        }
    }
    return modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
}