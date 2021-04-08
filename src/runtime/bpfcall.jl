export bpfcall

@generated function _bpfcall(::Val{cmd}, ::Type{rettype}, ::Type{argtypes}, args::Vararg{Any}) where {cmd,rettype,argtypes}
    JuliaContext() do ctx
        T_ret = convert(LLVMType, rettype, ctx)
        T_args = map(x->convert(LLVMType, x, ctx), argtypes.parameters)

        llvm_f, _ = create_function(T_ret, LLVMType[T_args...])
        mod = LLVM.parent(llvm_f)

        Builder(ctx) do builder
            entry = BasicBlock(llvm_f, "entry", ctx)
            position!(builder, entry)
            ft = LLVM.FunctionType(T_ret, LLVMType[T_args...])
            ftp = LLVM.PointerType(ft)
            f = inttoptr!(builder, ConstantInt(cmd, ctx), ftp)
            value = call!(builder, f, LLVM.Value[parameters(llvm_f)...])
            ret!(builder, value)
        end
        call_function(llvm_f, rettype, Base.to_tuple_type(args), :((args...,)))
    end
end
@inline bpfcall(cmd::API.BPFHelper, RT, AT, args...) =
    _bpfcall(Val(Int(cmd)), RT, AT, args...)
@inline bpfcall(cmd::API.BPFHelper, RT) = _bpfcall(Val(Int(cmd)), RT, Tuple{})
@inline bpfcall(cmd::API.BPFHelper) = _bpfcall(Val(Int(cmd)), Cvoid, Tuple{})
