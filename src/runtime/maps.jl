function map_lookup_elem(map::RTMap{Name,MT,K,V,ME,F}, key::K) where {Name,MT,K,V,ME,F}
    keyref = ZeroInitRef(K, key)
    GC.@preserve keyref begin
        keyref_ptr = Base.unsafe_convert(Ptr{K}, keyref)
        map_lookup_elem(map, keyref_ptr)
    end
end
@inline function map_update_elem(map::RTMap{Name,MT,K,V,ME,F}, key::K, value::V, flags::UInt64) where {Name,MT,K,V,ME,F}
    keyref = ZeroInitRef(K, key)
    valref = ZeroInitRef(V, value)
    GC.@preserve keyref valref begin
        keyref_ptr = Base.unsafe_convert(Ptr{K}, keyref)
        valref_ptr = Base.unsafe_convert(Ptr{V}, valref)
        map_update_elem(map, keyref_ptr, valref_ptr, flags)
    end
end
function map_delete_elem(map::RTMap{Name,MT,K,V,ME,F}, key::K) where {Name,MT,K,V,ME,F}
    keyref = ZeroInitRef(K, key)
    GC.@preserve keyref begin
        keyref_ptr = Base.unsafe_convert(Ptr{K}, keyref)
        map_delete_elem(map, Base.unsafe_convert(Ptr{K}, keyref))
    end
end

# TODO: Use bpfcall
@generated function map_lookup_elem(map::RTMap{Name,MT,K,V,ME,F}, key::Ptr{K}) where {Name,MT,K,V,ME,F}
    Context() do ctx
        T_keyp = LLVM.PointerType(convert(LLVMType, K; ctx))
        T_valp = LLVM.PointerType(convert(LLVMType, V; ctx))
        T_jlptr = convert(LLVMType, key; ctx)

        llvm_f, _ = create_function(T_jlptr, [T_jlptr])
        mod = LLVM.parent(llvm_f)

        map_gv = _genmap!(mod, map, ctx)
        T_map_gv = llvmtype(map_gv)

        Builder(ctx) do builder
            entry = BasicBlock(llvm_f, "entry"; ctx)
            position!(builder, entry)
            ft = LLVM.FunctionType(T_valp, [T_map_gv, T_keyp])
            ftp = LLVM.PointerType(ft)
            elem = inttoptr!(builder, parameters(llvm_f)[1], T_keyp)
            f = inttoptr!(builder, ConstantInt(Int64(1); ctx), ftp)
            value = call!(builder, f, [map_gv, elem])
            value = ptrtoint!(builder, value, T_jlptr)
            ret!(builder, value)
        end
        call_function(llvm_f, Ptr{V}, Tuple{Ptr{K}}, :key)
    end
end
@generated function map_update_elem(map::RTMap{Name,MT,K,V,ME,F}, key::Ptr{K}, val::Ptr{V}, flags::UInt64) where {Name,MT,K,V,ME,F}
    Context() do ctx
        T_cint = convert(LLVMType, Cint; ctx)
        T_keyp = LLVM.PointerType(convert(LLVMType, K; ctx))
        T_valp = LLVM.PointerType(convert(LLVMType, V; ctx))
        T_flags = convert(LLVMType, flags; ctx)
        T_jlptr = convert(LLVMType, key; ctx)

        llvm_f, _ = create_function(T_cint, [T_jlptr, T_jlptr, T_flags])
        mod = LLVM.parent(llvm_f)

        map_gv = _genmap!(mod, map, ctx)
        T_map_gv = llvmtype(map_gv)

        Builder(ctx) do builder
            entry = BasicBlock(llvm_f, "entry"; ctx)
            position!(builder, entry)
            ft = LLVM.FunctionType(T_cint, [T_map_gv, T_keyp, T_valp, T_flags])
            ftp = LLVM.PointerType(ft)
            key_elem = inttoptr!(builder, parameters(llvm_f)[1], T_keyp)
            val_elem = inttoptr!(builder, parameters(llvm_f)[2], T_valp)
            f = inttoptr!(builder, ConstantInt(Int64(2); ctx), ftp)
            value = call!(builder, f, [map_gv, key_elem, val_elem, parameters(llvm_f)[3]])
            ret!(builder, value)
        end
        call_function(llvm_f, Cint, Tuple{Ptr{K},Ptr{V},UInt64}, :key, :val, :flags)
    end
end
@generated function map_delete_elem(map::RTMap{Name,MT,K,V,ME,F}, key::Ptr{K}) where {Name,MT,K,V,ME,F}
    Context() do ctx
        T_cint = convert(LLVMType, Cint; ctx)
        T_keyp = LLVM.PointerType(convert(LLVMType, K; ctx))
        T_jlptr = convert(LLVMType, key; ctx)

        llvm_f, _ = create_function(T_cint, [T_jlptr])
        mod = LLVM.parent(llvm_f)

        map_gv = _genmap!(mod, map, ctx)
        T_map_gv = llvmtype(map_gv)

        Builder(ctx) do builder
            entry = BasicBlock(llvm_f, "entry"; ctx)
            position!(builder, entry)
            ft = LLVM.FunctionType(T_cint, [T_map_gv, T_keyp])
            ftp = LLVM.PointerType(ft)
            elem = inttoptr!(builder, parameters(llvm_f)[1], T_keyp)
            f = inttoptr!(builder, ConstantInt(Int64(3); ctx), ftp)
            value = call!(builder, f, [map_gv, elem])
            ret!(builder, value)
        end
        call_function(llvm_f, Cint, Tuple{Ptr{K}}, :key)
    end
end

# BPF-safe convert alternative
bpfconvert(T, ::Nothing) = nothing
bpfconvert(::Type{T}, v::T) where {T} = v
function bpfconvert(::Type{T}, v::V) where {T<:Unsigned,V<:Unsigned}
    if v > typemax(T)
        nothing
    elseif typemax(V) > typemax(T)
        unsafe_trunc(T, v)
    else
        convert(T, v)
    end::T
end
function bpfconvert(::Type{T}, v::V) where {T,V}
    if (v > typemax(T)) || (v < typemin(T))
        nothing
    elseif (typemax(V) > typemax(T)) || (typemin(V) < typemin(T))
        unsafe_trunc(T, v)
    else
        convert(T, v)
    end::Union{T,Nothing}
end

@inline Base.getindex(map::RTMap{Name,MT,K,V,ME,F}, idx) where {Name,MT,K,V,ME,F} =
    getindex(map, bpfconvert(K, idx))
@inline Base.getindex(map::RTMap{Name,MT,K,V,ME,F}, idx_ptr::Ptr{K}) where {Name,MT,K,V,ME,F} =
    map_lookup_elem(map, idx_ptr)
Base.getindex(map::RTMap, ::Nothing) = nothing
@inline function Base.getindex(map::AbstractHashMap{Name,MT,K,V,ME,F}, idx::K) where {Name,MT,K,V,ME,F}
    ptr = map_lookup_elem(map, idx)
    if reinterpret(UInt64, ptr) > 0
        return unsafe_load(ptr)
    else
        return nothing
    end
end
@inline function Base.getindex(map::AbstractArrayMap{Name,MT,K,V,ME,F}, idx::K) where {Name,MT,K,V,ME,F}
    if idx > 0
        ptr = map_lookup_elem(map, idx-K(1))
        if reinterpret(UInt64, ptr) > 0
            return unsafe_load(ptr)
        else
            return nothing
        end
    else
        return nothing
    end
end

@inline Base.setindex!(map::RTMap{Name,MT,K,V,ME,F}, value, idx) where {Name,MT,K,V,ME,F} =
    setindex!(map, bpfconvert(V, value), bpfconvert(K, idx))
@inline function Base.setindex!(map::RTMap{Name,MT,K,V,ME,F}, value, idx_ptr::Ptr{K}) where {Name,MT,K,V,ME,F}
    value_ref = ZeroInitRef(V, bpfconvert(V, value))
    GC.@preserve value_ref begin
        value_ptr = Base.unsafe_convert(Ptr{V}, value_ref)
        map_update_elem(map, idx_ptr, value_ptr, UInt64(0))
    end
end
@inline function Base.setindex!(map::RTMap{Name,MT,K,V,ME,F}, value_ptr::Ptr{V}, idx) where {Name,MT,K,V,ME,F}
    idx_ref = ZeroInitRef(K, bpfconvert(K, idx))
    GC.@preserve idx_ref begin
        idx_ptr = Base.unsafe_convert(Ptr{K}, idx_ref)
        map_update_elem(map, idx_ptr, value_ptr, UInt64(0))
    end
end
@inline Base.setindex!(map::RTMap{Name,MT,K,V,ME,F}, value_ptr::Ptr{V}, idx_ptr::Ptr{K}) where {Name,MT,K,V,ME,F} =
    map_update_elem(map, idx_ptr, value_ptr, UInt64(0))
@inline Base.setindex!(map::RTMap, ::Nothing, idx) = nothing
@inline Base.setindex!(map::RTMap, value, ::Nothing) = nothing
@inline Base.setindex!(map::RTMap, ::Nothing, ::Nothing) = nothing
@inline function Base.setindex!(map::AbstractHashMap{Name,MT,K,V,ME,F}, value::V, idx::K) where {Name,MT,K,V,ME,F}
    map_update_elem(map, idx, value, UInt64(0))
    value
end
@inline function Base.setindex!(map::AbstractArrayMap{Name,MT,K,V,ME,F}, value::V, idx::K) where {Name,MT,K,V,ME,F}
    if idx > 0
        map_update_elem(map, idx-K(1), value, UInt64(0))
    end
    value
end

@inline Base.delete!(map::RTMap{Name,MT,K,V,ME,F}, idx) where {Name,MT,K,V,ME,F} =
    delete!(map, bpfconvert(K, idx))
Base.delete!(map::RTMap, ::Nothing) = nothing
@inline function Base.delete!(map::AbstractHashMap{Name,MT,K,V,ME,F}, idx::K) where {Name,MT,K,V,ME,F}
    map_delete_elem(map, idx)
    map
end
@inline function Base.delete!(map::AbstractArrayMap{Name,MT,K,V,ME,F}, idx::K) where {Name,MT,K,V,ME,F}
    if idx > 0
        map_delete_elem(map, idx-K(1))
    end
    map
end

@inline Base.haskey(map::AbstractHashMap{Name,MT,K,V,ME,F}, idx) where {Name,MT,K,V,ME,F} =
    map[bpfconvert(K, idx)] !== nothing
@inline Base.haskey(map::RTMap, ::Nothing) = false
@inline function Base.haskey(map::AbstractArrayMap{Name,MT,K,V,ME,F}, idx) where {Name,MT,K,V,ME,F}
    if idx > 0
        map[bpfconvert(K, idx)-K(1)] !== nothing
    else
        false
    end
end

@inline function Base.get(map::RTMap{Name,MT,K,V,ME,F}, k::K, v::V) where {Name,MT,K,V,ME,F}
    map_v = map[k]
    if map_v !== nothing
        return map_v
    else
        return v
    end
end
@inline Base.get(map::RTMap{Name,MT,K,V,ME,F}, k, v) where {Name,MT,K,V,ME,F} =
    get(map, bpfconvert(K, k), bpfconvert(V, v))

## Perf

#= TODO
export perf_event_output

function perf_event_output(pt_ctx::Ptr{API.pt_regs}, map::RTMap, flags::Union{Int64,UInt64}, data::D, sz::Union{Int64,UInt64}) where D
    data_ref = Ref{D}(data)
    GC.@preserve data_ref begin
        data_ptr = Base.unsafe_convert(Ptr{D}, data_ref)
        _perf_event_output(pt_ctx, map, reinterpret(UInt64, flags), data_ptr, reinterpret(UInt64, sz))
    end
end
@generated function _perf_event_output(pt_ctx::Ptr{API.pt_regs}, map::RTMap{Name,MT,K,V,ME,F}, flags::UInt64, data::Ptr{D}, sz::UInt64) where {Name,MT,K,V,ME,F,D}
    Context() do ctx
        T_cint = convert(LLVMType, Cint, ctx)
        T_ptctx = convert(LLVMType, pt_ctx, ctx)
        T_datap = LLVM.PointerType(convert(LLVMType, data, ctx))
        T_u64 = LLVM.Int64Type(ctx)
        T_jlptr = convert(LLVMType, Ptr{Cvoid}, ctx)

        llvm_f, _ = create_function(T_cint, [T_ptctx, T_u64, T_jlptr, T_u64])
        mod = LLVM.parent(llvm_f)

        map_gv = _genmap!(mod, map, ctx)
        T_map_gv = llvmtype(map_gv)

        Builder(ctx) do builder
            entry = BasicBlock(llvm_f, "entry", ctx)
            position!(builder, entry)
            ft = LLVM.FunctionType(T_cint, [T_ptctx, T_map_gv, T_u64, T_datap, T_u64])
            ftp = LLVM.PointerType(ft)
            data_elem = inttoptr!(builder, parameters(llvm_f)[3], T_datap)
            f = inttoptr!(builder, ConstantInt(Int64(25), ctx), ftp)
            value = call!(builder, f, [parameters(llvm_f)[1], map_gv, parameters(llvm_f)[2], data_elem, parameters(llvm_f)[4]])
            ret!(builder, value)
        end
        call_function(llvm_f, Cint, Tuple{Ptr{API.pt_regs},UInt64,Ptr{D},UInt64}, :((pt_ctx,flags,data,sz)))
    end
end
=#
