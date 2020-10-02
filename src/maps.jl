export BPFMap, bpf_map_lookup_elem, bpf_map_update_elem, bpf_map_delete_elem

struct BPFMap{Name,MT,K,V,ME,F} end
BPFMap(name, maptype, keytype, valuetype, maxentries=1, flags=0) =
    BPFMap{Symbol(name), maptype, keytype, valuetype, maxentries, flags}()

function bpf_map_lookup_elem(map::BPFMap{Name,MT,K,V,ME,F}, key::K) where {Name,MT,K,V,ME,F}
    keyref = Ref{K}(key-1)
    GC.@preserve keyref begin
        _bpf_map_lookup_elem(map, Base.unsafe_convert(Ptr{K}, keyref))
    end
end
function bpf_map_update_elem(map::BPFMap{Name,MT,K,V,ME,F}, key::K, value::V, flags::UInt64) where {Name,MT,K,V,ME,F}
    keyref = Ref{K}(key-1)
    valref = Ref{V}(value)
    GC.@preserve keyref valref begin
        _bpf_map_update_elem(map,
                             Base.unsafe_convert(Ptr{K}, keyref),
                             Base.unsafe_convert(Ptr{V}, valref),
                             flags)
    end
end
function bpf_map_delete_elem(map::BPFMap{Name,MT,K,V,ME,F}, key::K) where {Name,MT,K,V,ME,F}
    keyref = Ref{K}(key-1)
    GC.@preserve keyref begin
        _bpf_map_delete_elem(map, Base.unsafe_convert(Ptr{K}, keyref))
    end
end
function _genmap!(mod::LLVM.Module, ::Type{BPFMap{Name,MT,K,V,ME,F}}, ctx) where {Name,MT,K,V,ME,F}
    T_i32 = LLVM.Int32Type(ctx)
    T_map = LLVM.StructType([T_i32, T_i32, T_i32, T_i32, T_i32])
    name = string(Name)
    return if haskey(LLVM.globals(mod), name)
        LLVM.globals(mod)[name]
    else
        gv = GlobalVariable(mod, T_map, name)
        section!(gv, "maps")
        alignment!(gv, 4)
        vec = Any[Int32(MT),Int32(sizeof(K)),Int32(sizeof(V)),Int32(ME),Int32(F)]
        A_vec = [ConstantInt(v, ctx) for v in vec]
        init = LLVM.API.LLVMConstStruct(A_vec, length(A_vec), 0)
        init = ConstantStruct(init)
        initializer!(gv, init)
        gv
    end
end
@generated function _bpf_map_lookup_elem(map::BPFMap{Name,MT,K,V,ME,F}, key::Ptr{K}) where {Name,MT,K,V,ME,F}
    JuliaContext() do ctx
        T_keyp = LLVM.PointerType(convert(LLVMType, K, ctx))
        T_valp = LLVM.PointerType(convert(LLVMType, V, ctx))
        T_jlptr = convert(LLVMType, key, ctx)

        llvm_f, _ = create_function(T_jlptr, [T_jlptr])
        mod = LLVM.parent(llvm_f)

        map_gv = _genmap!(mod, map, ctx)
        T_map_gv = llvmtype(map_gv)

        Builder(ctx) do builder
            entry = BasicBlock(llvm_f, "entry", ctx)
            position!(builder, entry)
            ft = LLVM.FunctionType(T_valp, [T_map_gv, T_keyp])
            ftp = LLVM.PointerType(ft)
            elem = inttoptr!(builder, parameters(llvm_f)[1], T_keyp)
            f = inttoptr!(builder, ConstantInt(Int64(1), ctx), ftp)
            value = call!(builder, f, [map_gv, elem])
            value = ptrtoint!(builder, value, T_jlptr)
            ret!(builder, value)
        end
        call_function(llvm_f, Ptr{V}, Tuple{Ptr{K}}, :((key,)))
    end
end
@generated function _bpf_map_update_elem(map::BPFMap{Name,MT,K,V,ME,F}, key::Ptr{K}, val::Ptr{V}, flags::UInt64) where {Name,MT,K,V,ME,F}
    JuliaContext() do ctx
        T_cint = convert(LLVMType, Cint, ctx)
        T_keyp = LLVM.PointerType(convert(LLVMType, K, ctx))
        T_valp = LLVM.PointerType(convert(LLVMType, V, ctx))
        T_flags = convert(LLVMType, flags, ctx)
        T_jlptr = convert(LLVMType, key, ctx)

        llvm_f, _ = create_function(T_cint, [T_jlptr, T_jlptr, T_flags])
        mod = LLVM.parent(llvm_f)

        map_gv = _genmap!(mod, map, ctx)
        T_map_gv = llvmtype(map_gv)

        Builder(ctx) do builder
            entry = BasicBlock(llvm_f, "entry", ctx)
            position!(builder, entry)
            ft = LLVM.FunctionType(T_cint, [T_map_gv, T_keyp, T_valp, T_flags])
            ftp = LLVM.PointerType(ft)
            key_elem = inttoptr!(builder, parameters(llvm_f)[1], T_keyp)
            val_elem = inttoptr!(builder, parameters(llvm_f)[2], T_valp)
            f = inttoptr!(builder, ConstantInt(Int64(2), ctx), ftp)
            value = call!(builder, f, [map_gv, key_elem, val_elem, parameters(llvm_f)[3]])
            ret!(builder, value)
        end
        call_function(llvm_f, Cint, Tuple{Ptr{K},Ptr{V},UInt64}, :((key,val,flags)))
    end
end
@generated function _bpf_map_delete_elem(map::BPFMap{Name,MT,K,V,ME,F}, key::Ptr{K}) where {Name,MT,K,V,ME,F}
    JuliaContext() do ctx
        T_cint = convert(LLVMType, Cint, ctx)
        T_keyp = LLVM.PointerType(convert(LLVMType, K, ctx))
        T_jlptr = convert(LLVMType, key, ctx)

        llvm_f, _ = create_function(T_cint, [T_jlptr])
        mod = LLVM.parent(llvm_f)

        map_gv = _genmap!(mod, map, ctx)
        T_map_gv = llvmtype(map_gv)

        Builder(ctx) do builder
            entry = BasicBlock(llvm_f, "entry", ctx)
            position!(builder, entry)
            ft = LLVM.FunctionType(T_cint, [T_map_gv, T_keyp])
            ftp = LLVM.PointerType(ft)
            elem = inttoptr!(builder, parameters(llvm_f)[1], T_keyp)
            f = inttoptr!(builder, ConstantInt(Int64(3), ctx), ftp)
            value = call!(builder, f, [map_gv, elem])
            ret!(builder, value)
        end
        call_function(llvm_f, Cint, Tuple{Ptr{K}}, :((key,)))
    end
end
