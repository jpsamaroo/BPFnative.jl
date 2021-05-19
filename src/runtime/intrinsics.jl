for (name,T) in [("byte", UInt8),("half",UInt16),("word",UInt32)]
    @eval @inline $(Symbol("load_$name"))(ctx, off::Int64) =
        unsafe_trunc($T,
                     ccall($("llvm.bpf.load.$name"), llvmcall, UInt64,
                           (Core.LLVMPtr{$T, 0}, Int64),
                           reinterpret(Core.LLVMPtr{$T, 0}, ctx), off))
    @eval @inline $(Symbol("load_$name"))(ctx, off::Union{Int8,Int16,Int32}) =
        $(Symbol("load_$name"))(ctx, Core.sext_int(Int64, off))
    @eval @inline $(Symbol("load_$name"))(ctx, off::Union{UInt8,UInt16,UInt32}) =
        $(Symbol("load_$name"))(ctx, Core.zext_int(Int64, off))
    # TODO: We should early exit with typemax(UInt64) if off > typemax(Int64)
    @eval @inline $(Symbol("load_$name"))(ctx, off::UInt64) =
        $(Symbol("load_$name"))(ctx, reinterpret(Int64, off))
end
