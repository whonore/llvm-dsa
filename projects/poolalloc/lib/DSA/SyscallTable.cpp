//===-- SyscallTable.cpp - Marks references to the system call table ------===//                  
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source 
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// A pass to mark references to the system call table with a flag.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "dsa-syscalltbl"

#include "llvm/ADT/Statistic.h"
#include "dsa/DataStructure.h"
#include "dsa/AllocatorIdentification.h"
#include "dsa/DSGraph.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/Timer.h"
#include <iostream>
#include "llvm/IR/Module.h"

using namespace llvm;

static RegisterPass<SyscallTablePass> 
X("dsa-syscalltbl", "System call table marker");

char SyscallTablePass::ID;

// Get the name of the syscall table variable
// TODO: this should be automated
static cl::opt<std::string> 
systbl_name("sct", cl::Required, cl::desc("System call table name"));

bool SyscallTablePass::runOnModule (Module &M) {
  // Get the DSGraph from LocalDataStructures.
  init(&getAnalysis<LocalDataStructures>(), true, true, false, false);
  Module::iterator FI = M.begin(), EI = M.end();
  for (; FI != EI; ++FI)
    if (!FI->isDeclaration())
      getOrCreateGraph(&*FI);

  // Search for a variable matching the given name. Mark the corresponding
  // DSNode with a flag.
  DSGraph::ScalarMapTy &SM = GlobalsGraph->getScalarMap();
  DSScalarMap::global_iterator I = SM.global_begin(), E = SM.global_end();
  for (; I != E; ++I) {
    if (const GlobalVariable *GV = dyn_cast<GlobalVariable>(*I)) {
      if (GV->getName() == systbl_name) {
        const GlobalValue *leader = SM.getLeaderForGlobal(GV);
        DSNode *node = GlobalsGraph->getNodeForValue(leader).getNode();
        DEBUG(errs() << "Found " << *GV << "\n");
        DEBUG(errs() << "Leader " << *leader << "\n");
        GlobalsGraph->markSyscallTableNodes(node);
      }
    }
  }

  return false;
}
