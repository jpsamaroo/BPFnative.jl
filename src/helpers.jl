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

#=
@inline function bpf_map_lookup_elem(fd, key)
    ccall("bpf_map_lookup_elem", Int32, (Int64, Int32), fd, key)
end
=#
@generated function bpfcall(intr_name::Val{S}, ::Type{ret}, args...) where {S,ret}
    ret_type = convert(LLVMType, ret)
    arg_types = [convert(LLVMType, arg) for arg in args]

    # create function
    llvm_f, _ = create_function(ret_type, arg_types)
    mod = LLVM.parent(llvm_f)

    # get the intrinsic
    intr = LLVM.Function(mod, string(S), LLVM.FunctionType(ret_type, arg_types))

    # generate IR
    Builder(JuliaContext()) do builder
        entry = BasicBlock(llvm_f, "entry", JuliaContext())
        position!(builder, entry)
        res = call!(builder, intr, [parameters(llvm_f)...])
        ret!(builder, res)
    end

    arg_ex = Expr(:tuple)
    for idx in 1:length(args)
        push!(arg_ex.args, :(args[$idx]))
    end
    call_function(llvm_f, ret, Tuple{args...}, arg_ex)
end
