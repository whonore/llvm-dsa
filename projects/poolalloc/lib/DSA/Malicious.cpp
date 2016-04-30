//===- Malicious.cpp - Look for malicious writes to kernel data structures ===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source 
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This pass searches for instructions that can write to memory and that have
// a target that could be a kernel data structure.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "dsa-malicious"

#include "dsa/DataStructure.h"
#include "dsa/DSGraph.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"

using namespace llvm;

static RegisterPass<Malicious>
X("dsa-malicious", "Checks for malicious writes to kernel data structures");

char Malicious::ID;

bool Malicious::runOnModule(Module &M) {
  // Get the DSGraph from BUDataStructures.
  BUDataStructures &Graphs = getAnalysis<BUDataStructures>();

  Module::iterator FI = M.begin(), FE = M.end();
  for (; FI != FE; ++FI) {
    Function *F = &*FI;

    // Skip functions with no DSGraph.
    if (!Graphs.hasDSGraph(*F)) {
      DEBUG(errs() << "\nNone for " << F->getName() << "\n");
      continue;
    }

    DEBUG(errs() << "\n" << F->getName() << "\n");
    DSGraph *DSG = Graphs.getDSGraph(*F);

    // Check for instructions that write to memory and with a target that 
    // is marked by the system call table flag.
    Function::iterator BI = FI->begin(), BE = FI->end();
    for (; BI != BE; ++BI) {
      BasicBlock::iterator II = BI->begin(), IE = BI->end();
      for (; II != IE; ++II) {
        Instruction *I = &*II;

        if (I->mayWriteToMemory()) {
          DEBUG(errs() << *I << "\n");
          // TODO: consider other instructions as well
          if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
            Value *target = SI->getPointerOperand();
            DSNode *N = DSG->getNodeForValue(target).getNode();

            // Skip targets without nodes
            if (N == NULL) {
              DEBUG(errs() << "Can't find\n");
              continue;
            }

            if (N->isSyscallTableNode()) {
              errs() << "\t" 
                     << *I 
                     << " in " 
                     << F->getName() 
                     << " is potentially dangerous\n";
            }
          }
        }
      }
    }
  }

  return false;
}
