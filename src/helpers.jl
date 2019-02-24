# Example external declaration borrowed from:
# https://github.com/JuliaGPU/CUDAnative.jl/blob/dc37a71024869034ecb58cfe65c0f9658ea60aa7/src/device/cuda_intrinsics/memory_dynamic.jl
@generated function myextfunc(x::Int32)
    T_i32 = convert(LLVMType, Int32)

    # create function
    llvm_f, _ = create_function(T_i32, [T_i32])
    mod = LLVM.parent(llvm_f)

    # get the intrinsic
    intr = LLVM.Function(mod, "myextfunc", LLVM.FunctionType(T_i32, [T_i32]))

    # generate IR
    Builder(JuliaContext()) do builder
        entry = BasicBlock(llvm_f, "entry", JuliaContext())
        position!(builder, entry)
        res = call!(builder, intr, [parameters(llvm_f)[1]])
        ret!(builder, res)
    end

    call_function(llvm_f, Int32, Tuple{Int32}, :((x,)))
end

const KERNEL_HELPERS = []
for helper in KERNEL_HELPERS
    # FIXME: Create our magical kernel helper functions
end
