/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.
*/

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/raw_ostream.h"


using namespace llvm;

namespace {

    class AFLCoverage : public ModulePass {

    public:

        static char ID;

        AFLCoverage() : ModulePass(ID) {}

        bool runOnModule(Module &M) override;

        // StringRef getPassName() const override {
        //  return "American Fuzzy Lop Instrumentation";
        // }

    };

}


char AFLCoverage::ID = 0;


bool AFLCoverage::runOnModule(Module &M) {

    LLVMContext &C = M.getContext();

    IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);


    /* Show a banner */

    char be_quiet = 0;

    if (isatty(2) && !getenv("AFL_QUIET")) {

        SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");

    } else be_quiet = 1;


    /* Decide instrumentation ratio */

    char *inst_ratio_str = getenv("AFL_INST_RATIO");
    unsigned int inst_ratio = 100;

    if (inst_ratio_str) {

        if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
            inst_ratio > 100)
            FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

    }

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */

    GlobalVariable *AFLMapPtr =
            new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                               GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

    GlobalVariable *AFLPrevLoc = new GlobalVariable(
            M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
            0, GlobalVariable::GeneralDynamicTLSModel, 0, false);


    GlobalVariable *pathString =
            new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                               GlobalValue::ExternalLinkage, 0, "__path_string_ptr");

    GlobalVariable *pathStringLen = new GlobalVariable(
            M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__path_string_len",
            0, GlobalVariable::GeneralDynamicTLSModel, 0, false);



    FunctionType *mallocFuncType = FunctionType::get(
            Type::getInt8PtrTy(M.getContext()),   // Return type: i8* represents void* in C
            {IntegerType::get(M.getContext(), 32)}, // Parameter type: i32 represents size_t on a 32-bit platform
            false   // Not varargs
    );

    // Declare the malloc function in your module
    Function *mallocFunc = Function::Create(
            mallocFuncType,
            Function::ExternalLinkage,
            "malloc",
            &M  // Attach the function to your module
    );

    std::vector < llvm::Type * > argTypes = {
            Type::getInt8PtrTy(M.getContext()),  // char* buffer
            Type::getInt8PtrTy(M.getContext())   // const char* format, 这里只声明了两个参数，实际上 sprintf 可以有更多
    };

    FunctionType *sprintfType = FunctionType::get(
            Type::getInt64Ty(M.getContext()),  // 返回值类型，sprintf 返回写入的字符数
            argTypes,
            true   // 表示这是一个可变参数函数
    );

    Function *sprintfFunc = Function::Create(
            sprintfType,
            Function::InternalLinkage,
            "sprintf",
            &M   // 这是你的模块对象
    );

    // Declare the strlen function type: i32 (i8*)
    FunctionType *strlenFuncType = FunctionType::get(
            IntegerType::get(M.getContext(), 32),  // Return type
            {Type::getInt8PtrTy(M.getContext())},  // Parameter type
            false  // Not varargs
    );

    // Declare the strlen function in your module
    Function *strlenFunc = Function::Create(
            strlenFuncType,
            Function::InternalLinkage,
            "strlen",
            &M  // Attach the function to your module
    );

    FunctionType *freeFuncType = FunctionType::get(
            Type::getVoidTy(M.getContext()),   // Return type: void
            {Type::getInt8PtrTy(M.getContext())}, // Parameter type: i8* represents void* in C
            false   // Not varargs
    );
    Function *freeFunc = Function::Create(
            freeFuncType,
            Function::InternalLinkage,
            "free",
            &M  // Attach the function to your module
    );



    Type *retType = Type::getVoidTy(C);
    std::vector<Type*> paramTypes_5 = {Type::getInt64Ty(C), Type::getInt64Ty(C)};
    FunctionType *logFuncType_5 = FunctionType::get(retType, paramTypes_5, false);
    FunctionCallee log_br = (&M)->getOrInsertFunction("log_br", logFuncType_5);

//    Type *retType1 = Type::getInt64Ty(C);  // assuming 64-bit platform
//    Type *charPtrType = Type::getInt8PtrTy(C);
//    FunctionType *funcType = FunctionType::get(retType1, charPtrType, false);
//    FunctionCallee strlen_wrapper = (&M)->getOrInsertFunction("strlen_wrapper", funcType);

    /* Instrument all the things! */

    int inst_blocks = 0;

    for (auto &F: M) {

        for (auto &BB: F) {

            BasicBlock::iterator IP = BB.getFirstInsertionPt();
            IRBuilder<> IRB(&(*IP));

            if (AFL_R(100) >= inst_ratio) continue;

            /* Make up cur_loc */

            unsigned int cur_loc = AFL_R(MAP_SIZE);

            ConstantInt *CurLoc = ConstantInt::get(Int64Ty, cur_loc);

            /* Load prev_loc */

            LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
            PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

            /* Load SHM pointer */

            LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
            MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *MapPtrIdx =
                    IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

            /* Update bitmap */

            LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
            Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
            IRB.CreateStore(Incr, MapPtrIdx)
                    ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

            /* Set prev_loc to cur_loc >> 1 */

            StoreInst *Store =
                    IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
            Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

            inst_blocks++;

            /*Set Path*/
            // init curLoc curLen
            AllocaInst *curLocBuffer = IRB.CreateAlloca(IntegerType::get(M.getContext(), 8),
                                                        ConstantInt::get(Int64Ty, 10));
            IRB.CreateCall(sprintfFunc, {curLocBuffer, IRB.CreateGlobalStringPtr("-%d"), CurLoc});
            Value *src = IRB.CreateBitCast(curLocBuffer, Type::getInt8PtrTy(M.getContext()));
            Value *srcLen = IRB.CreateCall(strlenFunc, {src});

            // init Last pathLoc  pathLen
            LoadInst *pathStringPtr = IRB.CreateLoad(pathString);
            LoadInst *pathStringLenLoc = IRB.CreateLoad(pathStringLen);
            Value *len = IRB.CreateZExt(pathStringLenLoc, IRB.getInt32Ty());

           // get total len
            Value *newLen = IRB.CreateAdd(len, srcLen);

            // copy
            Value *newMem = IRB.CreateCall(mallocFunc, {newLen});
            IRB.CreateMemCpy(IRB.CreateBitCast(newMem, Type::getInt8PtrTy(M.getContext())), Align(1), pathStringPtr, Align(1),len);

            //concat
            IRB.CreateMemCpy(IRB.CreateGEP(IRB.CreateBitCast(newMem, Type::getInt8PtrTy(M.getContext())), len),
                             Align(1), src, Align(1), srcLen);

            // pathString update
            const DataLayout &DL = M.getDataLayout();
            unsigned align = DL.getPrefTypeAlignment(Type::getInt8Ty(M.getContext()));
            IRB.CreateMemCpy(pathStringPtr, llvm::MaybeAlign(align), newMem, llvm::MaybeAlign(align), newLen);


            // free before
            Value *isNull = IRB.CreateIsNull(newMem);
            if (!isNull) {
                IRB.CreateCall(freeFunc, {newMem});
            }
            // pathLen update
            IRB.CreateStore(newLen, pathStringLen);
            // test
            Value *MapPtrIdx1 =IRB.CreateGEP(MapPtr, ConstantInt::get(Int8Ty, 1));
            IRB.CreateStore(newLen, MapPtrIdx1);
//
//            LoadInst *pathStringPtr = IRB.CreateLoad(pathString);
//            Value *pathStringIdx1 =IRB.CreateGEP(pathStringPtr, ConstantInt::get(Int8Ty, 1));
//            Value * val2 = IRB.CreateAdd(ConstantInt::get(Int8Ty, 2), ConstantInt::get(Int8Ty, 1));
//            IRB.CreateStore(val2, pathStringIdx1);
//            //llvm::outs()<<"====pathStringPt==="<<pathString;
            Value * args[] = {newLen, CurLoc, srcLen, len};
            IRB.CreateCall(log_br, args);
        }
    }


    /* Say something nice. */

    if (!be_quiet) {


        if (!inst_blocks) WARNF("No instrumentation targets found.");
        else
            OKF("Instrumented %u locations (%s mode, ratio %u%%).",
                inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
                             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
                              "ASAN/MSAN" : "non-hardened"), inst_ratio);

    }
    return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

    PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
        PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
        PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);