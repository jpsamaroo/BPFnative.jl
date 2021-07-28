export bpfcall

@generated function _bpfcall(::Val{cmd}, ::Type{rettype}, ::Type{argtypes}, args::Vararg{Any}) where {cmd,rettype,argtypes}
    Context() do ctx
        T_ret = convert(LLVMType, rettype; ctx)
        T_jlptr = convert(LLVMType, Ptr{Cvoid}; ctx)
        T_ptr_i8 = LLVM.PointerType(LLVM.Int8Type(ctx))

        outer_args = filter(arg->!(arg <: RTMap), args)
        T_outer_args = LLVMType[convert(LLVMType, arg; ctx) for arg in outer_args]

        llvm_f, _ = create_function(T_ret, T_outer_args)
        mod = LLVM.parent(llvm_f)

        outer_args_ex = Expr[]
        Builder(ctx) do builder
            entry = BasicBlock(llvm_f, "entry"; ctx)
            position!(builder, entry)

            inner_args = LLVM.Value[]
            T_inner_args = LLVMType[]
            jlidx = 1
            pidx = 1
            for (idx, arg) in enumerate(argtypes.parameters)
                if arg <: RTMap
                    map_gv = _genmap!(mod, arg, ctx)
                    push!(inner_args, map_gv)
                    push!(T_inner_args, llvmtype(map_gv))
                else
                    llvm_arg = parameters(llvm_f)[pidx]
                    T_arg = T_outer_args[pidx]
                    if arg <: Ptr
                        llvm_arg = inttoptr!(builder, llvm_arg, T_ptr_i8)
                        T_arg = llvmtype(llvm_arg)
                    end
                    push!(inner_args, llvm_arg)
                    push!(T_inner_args, T_arg)
                    push!(outer_args_ex, Expr(:ref, :args, jlidx))
                    pidx += 1
                end
                jlidx += 1
            end

            ft = LLVM.FunctionType(T_ret, T_inner_args)
            ftp = LLVM.PointerType(ft)
            f = inttoptr!(builder, ConstantInt(cmd; ctx), ftp)
            value = call!(builder, f, inner_args)
            ret!(builder, value)
        end
        #outer_args_ex = Expr(:tuple, outer_args_ex...)
        call_function(llvm_f, rettype, Base.to_tuple_type(outer_args), outer_args_ex...)
    end
end
@inline bpfcall(cmd::API.BPFHelper, RT, AT, args...) =
    _bpfcall(Val(Int(cmd)), RT, AT, args...)
@inline bpfcall(cmd::API.BPFHelper, RT) = _bpfcall(Val(Int(cmd)), RT, Tuple{})
@inline bpfcall(cmd::API.BPFHelper) = _bpfcall(Val(Int(cmd)), Cvoid, Tuple{})
