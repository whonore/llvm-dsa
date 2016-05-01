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

#include "dsa/DataStructure.h"
#include "dsa/DSGraph.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"

#include <set>
#include <vector>

using namespace llvm;

static RegisterPass<SyscallTablePass> 
X("dsa-syscalltbl", "System call table marker");

char SyscallTablePass::ID;

// A table of all the linux system call names
std::set<std::string> syscall_names = {
  "sys_exit",                   "sys_fork",                  "sys_read",                // 1-3
  "sys_write",                  "sys_open",                  "sys_close",               // 4-6
  "sys_waitpid",                "sys_creat",                 "sys_link",                // 7-9
  "sys_unlink",                 "sys_execve",                "sys_chdir",               // 8-12
  "sys_time",                   "sys_mknod",                 "sys_chmod",               // 13-15
  "sys_lchown",                                              "sys_stat",                // 16-18
  "sys_lseek",                  "sys_getpid",                "sys_mount",               // 19-21
  "sys_oldumount",              "sys_setuid",                "sys_getuid",              // 22-24
  "sys_stime",                  "sys_ptrace",                "sys_alarm",               // 25-27
  "sys_fstat",                  "sys_pause",                 "sys_utime",               // 28-30
  "sys_access",                                                                         // 29-33
  "sys_nice",                                                "sys_sync",                // 34-36
  "sys_kill",                   "sys_rename",                "sys_mkdir",               // 37-39
  "sys_rmdir",                  "sys_dup",                   "sys_pipe",                // 40-42
  "sys_times",                                               "sys_brk",                 // 43-45
  "sys_setgid",                 "sys_getgid",                "sys_signal",              // 46-48
  "sys_geteuid",                "sys_getegid",               "sys_acct",                // 49-51
  "sys_umount",                                              "sys_ioctl",               // 52-54
  "sys_fcntl",                                               "sys_setpgid",             // 55-57
                                "sys_olduname",              "sys_umask",               // 58-60
  "sys_chroot",                 "sys_ustat",                 "sys_dup2",                // 61-63
  "sys_getppid",                "sys_getpgrp",               "sys_setsid",              // 64-66
  "sys_sigaction",              "sys_sgetmask",              "sys_ssetmask",            // 67-69
  "sys_setreuid",               "sys_setregid",              "sys_sigsuspend",          // 70-72
  "sys_sigpending",             "sys_sethostname",           "sys_setrlimit",           // 73-75
  "sys_getrlimit",              "sys_getrusage",             "sys_gettimeofday",        // 76-78
  "sys_settimeofday",           "sys_getgroups",             "sys_setgroups",           // 79-81
  "old_select",                 "sys_symlink",               "sys_lstat",               // 82-84
  "sys_readlink",               "sys_uselib",                "sys_swapon",              // 85-87
  "sys_reboot",                 "old_readdir",               "old_mmap",                // 88-90
  "sys_munmap",                 "sys_truncate",              "sys_ftruncate",           // 91-93
  "sys_fchmod",                 "sys_fchown",                "sys_getpriority",         // 94-96
  "sys_setpriority",                                         "sys_statfs",              // 97-99
  "sys_fstatfs",                "sys_ioperm",                "sys_socketcall",          // 100-102
  "sys_syslog",                 "sys_setitimer",             "sys_getitimer",           // 103-105
  "sys_newstat",                "sys_newlstat",              "sys_newfstat",            // 106-108
  "sys_uname",                  "sys_iopl",                  "sys_vhangup",             // 109-111
  "sys_idle",                   "sysvm86old",                "sys_wait4",               // 112-114
  "sys_swapoff",                "sys_sysinfo",               "sys_ipc",                 // 115-117
  "sys_fsync",                  "sys_sigreturn",             "sys_clone",               // 118-120
  "sys_setdomainname",          "sys_newuname",              "sys_modify_ldt",          // 121-123
  "sys_adjtimex",               "sys_mprotect",              "sys_sigprocmask",         // 124-126
  "sys_create_module",          "sys_init_module",           "sys_delete_module",       // 127-129
  "sys_get_kernel_syms",        "sys_quotactl",              "sys_getpgid",             // 130-132
  "sys_fchdir",                 "sys_bdflush",               "sys_sysfs",               // 133-135
  "sys_personality",                                         "sys_setfsuid",            // 136-138
  "sys_setfsgid",               "sys_llseek",                "sys_getdents",            // 139-141
  "sys_select",                 "sys_flock",                 "sys_msync",               // 142-144
  "sys_readv",                  "sys_writev",                "sys_getsid",              // 145-147
  "sys_fdatasync",              "sys_sysctl",                "sys_mlock",               // 148-150
  "sys_munlock",                "sys_mlockall",              "sys_munlockall",          // 151-153
  "sys_sched_setparam",         "sys_sched_getparam",        "sys_sched_setscheduler",  // 154-156
  "sys_sched_getscheduler",     "sys_sched_yield",        "sys_sched_get_priority_max", // 157-159
  "sys_sched_get_priority_min", "sys_sched_rr_get_interval", "sys_nanosleep",           // 160-162
  "sys_mremap",                 "sys_setresuid",             "sys_getresuid",           // 163-165
  "sys_vm86",                   "sys_query_module",          "sys_poll",                // 164-168
  "sys_nfsservctl",             "sys_setresgid",             "sys_getresgid",           // 169-171
  "sys_prctl",                  "sys_rt_sigreturn",          "sys_rt_sigaction",        // 172-174
  "sys_rt_sigprocmask",         "sys_rt_sigpending",         "sys_rt_sigtimedwait",     // 175-177
  "sys_rt_sigqueueinfo",        "sys_rt_sigsuspend",         "sys_pread",               // 178-180
  "sys_pwrite",                 "sys_chown",                 "sys_getcwd",              // 181-183
  "sys_capget",                 "sys_capset",                "sys_sigaltstack",         // 184-186
  "sys_sendfile",                                                                       // 187-189
  "sys_vfork"                                                                           // 190-192
};

// Follow instructions back to the initial definition.
static void trace_back(Value *V, std::vector<Instruction *> &marked) {
  if (AllocaInst *A = dyn_cast<AllocaInst>(V)) {
    DEBUG(errs() << "trace_back alloc:\n\t" << *A << "\n");
    marked.push_back(A);
  }
  else if (LoadInst *L = dyn_cast<LoadInst>(V)) {
    DEBUG(errs() << "trace_back load:\n\t" << *L << "\n");
    trace_back(L->getPointerOperand(), marked);
  }
  else if (GetElementPtrInst *G = dyn_cast<GetElementPtrInst>(V)) {
    DEBUG(errs() << "trace_back gep:\n\t" << *G << "\n");
    trace_back(G->getPointerOperand(), marked);
  }
  else {
    DEBUG(errs() << "trace_back:\n\t" << *V << "\n");
  }
}

// Search for comparisons to system calls.
// TODO: comparison doesn't have to be to a constant. Maybe mark casts first
// then check for compare?
static void find_table(Module &M, std::vector<Instruction *> &marked) {
  Module::iterator FI = M.begin(), FE = M.end();
  for (; FI != FE; ++FI) {
    Function *F = &*FI;

    inst_iterator II = inst_begin(*F), IE = inst_end(*F);
    for (; II != IE; ++II) {
      // Is it a compare?
      if (CmpInst *I = dyn_cast<CmpInst>(&*II)) {
        for (unsigned int OI = 0; OI < I->getNumOperands() ; ++OI) {
          // Is this operand a system call?
          if (ConstantExpr *O = dyn_cast<ConstantExpr>(I->getOperand(OI))) {
            std::string name = O->stripPointerCasts()->getName();

            // Follow the other operand back and mark it.
            if (syscall_names.count(name) != 0) {
              DEBUG(errs() << "find_table:\n\t" << *I << "\n");
              Value *other = I->getOperand((OI + 1) % 2);
              trace_back(other, marked);
            }
          }
        }
      }
    } 
  }
}

// Mark corresponding DSNodes with the SyscallTable flag.
void SyscallTablePass::mark_syscalltbl(std::vector<Instruction *> &Is) {
  std::vector<Instruction *>::iterator II = Is.begin(), IE = Is.end();
  for (; II != IE; ++II) {
    Instruction *I = *II;
    DSGraph *G = getOrCreateGraph(I->getParent()->getParent());
    DSNode *N = G->getScalarMap()[I].getNode();

    DEBUG(errs() << "marking " << *I << "\n");
    G->markSyscallTableNodes(N);
  }
}

bool SyscallTablePass::runOnModule(Module &M) {
  // Get the DSGraph from LocalDataStructures.
  init(&getAnalysis<LocalDataStructures>(), true, true, false, false);
  Module::iterator FI = M.begin(), EI = M.end();
  for (; FI != EI; ++FI)
    if (!FI->isDeclaration())
      getOrCreateGraph(&*FI);

  // Find and mark references to the syscall table.
  std::vector<Instruction *> marked;
  find_table(M, marked);
  mark_syscalltbl(marked);

  return false;
}
