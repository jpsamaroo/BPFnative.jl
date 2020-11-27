export bpf_get_current_pid_tgid

@generated function bpf_get_current_pid_tgid()
    JuliaContext() do ctx
        T_u64 = LLVM.Int64Type(ctx)
        llvm_f, _ = create_function(T_u64)
        Builder(ctx) do builder
            entry = BasicBlock(llvm_f, "entry", ctx)
            position!(builder, entry)
            ftp = LLVM.PointerType(LLVM.FunctionType(T_u64))
            f = inttoptr!(builder, ConstantInt(Int64(14), ctx), ftp)
            value = call!(builder, f)
            ret!(builder, value)
        end
        call_function(llvm_f, UInt64, Tuple{}, :(()))
    end
end
function split_u64_u32(x::UInt64)
    lower = Base.unsafe_trunc(UInt32, x)
    upper = Base.unsafe_trunc(UInt32, (x & (UInt64(typemax(UInt32)) << 32)) >> 32)
    return lower, upper
end
