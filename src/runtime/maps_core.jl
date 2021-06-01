abstract type RTMap{Name,MT,K,V,ME,F} end
abstract type AbstractHashMap{Name,MT,K,V,ME,F} <: RTMap{Name,MT,K,V,ME,F} end
abstract type AbstractArrayMap{Name,MT,K,V,ME,F} <: RTMap{Name,MT,K,V,ME,F} end

struct HashMap{Name,MT,K,V,ME,F} <: AbstractHashMap{Name,MT,K,V,ME,F} end
maptype_to_jltype(::Val{API.BPF_MAP_TYPE_HASH}) = HashMap
maptype_to_jltype(::Val{API.BPF_MAP_TYPE_STACK_TRACE}) = HashMap
struct ArrayMap{Name,MT,K,V,ME,F} <: AbstractArrayMap{Name,MT,K,V,ME,F} end
maptype_to_jltype(::Val{API.BPF_MAP_TYPE_ARRAY}) = ArrayMap

function RTMap(; name, maptype, keytype, valuetype, maxentries=1, flags=0)
    jltype = maptype_to_jltype(Val(maptype))
    jltype{Symbol(name), maptype, keytype, valuetype, maxentries, flags}()
end

function _genmap!(mod::LLVM.Module, ::Type{<:RTMap{Name,MT,K,V,ME,F}}, ctx) where {Name,MT,K,V,ME,F}
    T_i32 = LLVM.Int32Type(ctx)
    T_map = LLVM.StructType([T_i32, T_i32, T_i32, T_i32, T_i32], ctx)
    name = string(Name)
    gv = GlobalVariable(mod, T_map, name)
    section!(gv, "maps")
    alignment!(gv, 4)
    vec = Any[Int32(MT),Int32(sizeof(K)),Int32(sizeof(V)),Int32(ME),Int32(F)]
    init = ConstantStruct([ConstantInt(v, ctx) for v in vec], ctx)
    initializer!(gv, init)
    linkage!(gv, LLVM.API.LLVMLinkOnceODRLinkage)
    return gv
end

