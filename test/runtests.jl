using BPFnative
#using Test

# FIXME: Get `mod`
#param_types = LLVMTypeRef[LLVMInt32Type()]
#ret_type = LLVMFunctionType(LLVMInt32Type(), param_types, 1, 0)
#_myextfunc = LLVMAddFunction(mod, "myextfunc", ret_type)

function f(x)
    return myextfunc(x)
end

BPFnative.code_llvm(f, (Int32,))
BPFnative.code_native(f, (Int32,))
