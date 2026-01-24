#include "Passes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <map>

using namespace llvm;

namespace {
    // Stocker les longueurs réelles des strings obfusquées
    std::map<GlobalVariable*, uint64_t> StringLengths;

    // Fonction pour vérifier si une chaîne est une URL
    bool isURL(const std::string &Data) {
        return Data.find("http://") != std::string::npos || 
               Data.find("https://") != std::string::npos ||
               Data.find("ftp://") != std::string::npos;
    }

    Constant* obfuscateRecursive(Constant *C, LLVMContext &Ctx, bool &changed, uint64_t &strLen) {
        if (!C) return nullptr;

        if (auto *CDA = dyn_cast<ConstantDataArray>(C)) {
            if (CDA->getElementType()->isIntegerTy(8)) {
                StringRef S = CDA->getRawDataValues();
                std::string Data = S.str();
                
                // Vérifier si c'est une URL avant d'obfusquer
                if (Data.length() > 8 && isURL(Data)) {
                    std::vector<uint8_t> Bytes(Data.begin(), Data.end());
                    size_t len = (Bytes.back() == 0) ? Bytes.size() - 1 : Bytes.size();
                    
                    // AFFICHER L'URL COMPLÈTE
                    errs() << "[+] OBFS URL (len=" << len << ") : '" << Data << "'\n";
                    
                    std::reverse(Bytes.begin(), Bytes.begin() + len);
                    
                    changed = true;
                    strLen = len; // Stocker la longueur réelle
                    return ConstantDataArray::get(Ctx, Bytes);
                } else if (Data.length() > 8) {
                    errs() << "[SKIP] Non-URL (len=" << Data.length() << "): '" 
                           << Data.substr(0, std::min(size_t(30), Data.length())) << "'\n";
                }
            }
        }

        // Cas 2 : C'est une structure (NimStringV2 de Nim par exemple)
        if (auto *CS = dyn_cast<ConstantStruct>(C)) {
            std::vector<Constant*> Elements;
            bool localChanged = false;
            for (unsigned i = 0; i < CS->getNumOperands(); ++i) {
                uint64_t opLen = 0;
                Constant* newOp = obfuscateRecursive(CS->getOperand(i), Ctx, localChanged, opLen);
                Elements.push_back(newOp);
                if (localChanged && opLen > 0) {
                    strLen = opLen; // Propager la longueur vers le haut
                }
            }
            if (localChanged) {
                changed = true;
                return ConstantStruct::get(CS->getType(), Elements);
            }
        }

        if (auto *CA = dyn_cast<ConstantArray>(C)) {
            std::vector<Constant*> Elements;
            bool localChanged = false;
            for (unsigned i = 0; i < CA->getNumOperands(); ++i) {
                uint64_t opLen = 0;
                Constant* newOp = obfuscateRecursive(CA->getOperand(i), Ctx, localChanged, opLen);
                Elements.push_back(newOp);
                if (localChanged && opLen > 0) {
                    strLen = opLen;
                }
            }
            if (localChanged) {
                changed = true;
                return ConstantArray::get(CA->getType(), Elements);
            }
        }

        return C;
    }
}

PreservedAnalyses StringShufflePass::run(Module &M, ModuleAnalysisManager &AM) {
    auto &Ctx = M.getContext();
    std::vector<GlobalVariable*> StringsToFix;
    StringLengths.clear();

    errs() << "--- [URL Shuffler] Scan des variables globales ---\n";

    for (GlobalVariable &G : M.globals()) {
        if (!G.hasInitializer()) continue;

        bool changed = false;
        uint64_t strLen = 0;
        Constant *NewInit = obfuscateRecursive(G.getInitializer(), Ctx, changed, strLen);

        if (changed) {
            G.setInitializer(NewInit);
            G.setConstant(false); 
            StringsToFix.push_back(&G);
            StringLengths[&G] = strLen; // Stocker la longueur
            errs() << "    |_ Variable '" << G.getName() << "' marquee pour remise en ordre (len=" << strLen << ").\n";
        }
    }

    if (StringsToFix.empty()) {
        errs() << "--- [URL Shuffler] Aucune URL trouvee ---\n";
        return PreservedAnalyses::all();
    }

    Function *FixFunc = Function::Create(
        FunctionType::get(Type::getVoidTy(Ctx), false),
        Function::ExternalLinkage, "fixStrings", &M);
    
    IRBuilder<> B(BasicBlock::Create(Ctx, "entry", FixFunc));

    for (GlobalVariable *G : StringsToFix) {
        // Trouver le pointeur vers les données de la string dans la structure
        // Pour NimStringV2, les données sont généralement dans le premier champ d'une sous-structure
        Value *Ptr = nullptr;
        
        // Essayer de naviguer dans la structure pour trouver le ConstantDataArray
        if (auto *CS = dyn_cast<ConstantStruct>(G->getInitializer())) {
            // Parcourir les opérandes pour trouver le tableau de bytes
            for (unsigned i = 0; i < CS->getNumOperands(); ++i) {
                if (auto *Op = dyn_cast<Constant>(CS->getOperand(i))) {
                    if (isa<ConstantDataArray>(Op) || 
                        (isa<ConstantStruct>(Op) && Op->getNumOperands() > 0 && isa<ConstantDataArray>(Op->getOperand(0)))) {
                        // Créer un GEP vers cet élément
                        std::vector<Value*> Indices;
                        Indices.push_back(B.getInt32(0)); // Déréférencer le global
                        Indices.push_back(B.getInt32(i)); // Index du champ
                        
                        // Si c'est encore une structure, aller plus profond
                        if (isa<ConstantStruct>(Op) && Op->getNumOperands() > 0) {
                            Indices.push_back(B.getInt32(0));
                        }
                        
                        Ptr = B.CreateInBoundsGEP(G->getValueType(), G, Indices);
                        Ptr = B.CreateBitCast(Ptr, B.getInt8PtrTy());
                        break;
                    }
                }
            }
        }
        
        // Fallback : utiliser directement le global
        if (!Ptr) {
            Ptr = B.CreateBitCast(G, B.getInt8PtrTy());
        }
        
        uint64_t Len = StringLengths[G];
        
        errs() << "    |_ Génération du code de restauration pour '" << G->getName() 
               << "' (len=" << Len << ")\n";

        for (uint64_t i = 0; i < Len / 2; ++i) {
            Value *P1 = B.CreateGEP(B.getInt8Ty(), Ptr, B.getInt64(i));
            Value *P2 = B.CreateGEP(B.getInt8Ty(), Ptr, B.getInt64(Len - i - 1));
            Value *V1 = B.CreateLoad(B.getInt8Ty(), P1);
            Value *V2 = B.CreateLoad(B.getInt8Ty(), P2);
            B.CreateStore(V2, P1);
            B.CreateStore(V1, P2);
        }
    }
    B.CreateRetVoid();
    appendToGlobalCtors(M, FixFunc, 0);

    errs() << "--- [URL Shuffler] Termine : " << StringsToFix.size() << " URL(s) obfusquee(s) ---\n";
    return PreservedAnalyses::none();
}