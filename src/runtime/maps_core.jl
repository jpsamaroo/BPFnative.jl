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
    T_map = LLVM.StructType([T_i32, T_i32, T_i32, T_i32, T_i32]; ctx)
    name = string(Name)
    gv = GlobalVariable(mod, T_map, name)
    section!(gv, "maps")
    alignment!(gv, 4)
    vec = Any[Int32(MT),Int32(sizeof(K)),Int32(sizeof(V)),Int32(ME),Int32(F)]
    init = ConstantStruct([ConstantInt(v; ctx) for v in vec]; ctx)
    initializer!(gv, init)
    linkage!(gv, LLVM.API.LLVMLinkOnceODRLinkage)
    return gv
end

# From AMDGPU.jl/src/device/gcn/memory_static.jl
@inline function _memset!(builder, ctx, mod, dest, value, len, volatile)
    T_nothing = LLVM.VoidType(ctx)
    T_dest = llvmtype(dest)
    T_int8 = convert(LLVMType, UInt8; ctx)
    T_int64 = convert(LLVMType, UInt64; ctx)
    T_int1 = LLVM.Int1Type(ctx)

    T_intr = LLVM.FunctionType(T_nothing, [T_dest, T_int8, T_int64, T_int1])
    intr = LLVM.Function(mod, "llvm.memset.p$(Int(addrspace(T_dest)))i8.i64", T_intr)
    call!(builder, intr, [dest, value, len, volatile])
end
@inline @generated function memset!(dest_ptr::LLVMPtr{UInt8,DestAS}, value::UInt8, len::LT) where {DestAS,LT<:Union{Int64,UInt64}}
    Context() do ctx
        T_nothing = LLVM.VoidType(ctx)
        T_pint8_dest = convert(LLVMType, dest_ptr; ctx)
        T_int8 = convert(LLVMType, UInt8; ctx)
        T_int64 = convert(LLVMType, UInt64; ctx)
        T_int1 = LLVM.Int1Type(ctx)

        llvm_f, _ = create_function(T_nothing, [T_pint8_dest, T_int8, T_int64])
        mod = LLVM.parent(llvm_f)
        Builder(ctx) do builder
            entry = BasicBlock(llvm_f, "entry"; ctx)
            position!(builder, entry)

            _memset!(builder, ctx, mod, parameters(llvm_f)[1], parameters(llvm_f)[2], parameters(llvm_f)[3], ConstantInt(T_int1, 0))
            ret!(builder)
        end
        call_function(llvm_f, Nothing, Tuple{LLVMPtr{UInt8,DestAS},UInt8,LT}, :dest_ptr, :value, :len)
    end
end
@inline memset!(dest_ptr::LLVMPtr{T,DestAS}, value::UInt8, len::Integer) where {T,DestAS} =
    memset!(reinterpret(LLVMPtr{UInt8,DestAS}, dest_ptr), value, UInt64(len))
@inline memset!(dest_ptr::Union{<:Ptr,<:LLVMPtr}, src_ptr::Union{<:Ptr,<:LLVMPtr}, len::Integer) =
    memset!(reinterpret(LLVMPtr{UInt8,0}, dest_ptr), reinterpret(LLVMPtr{UInt8,0}, src_ptr), UInt64(len))

@inline function _memcpy!(builder, ctx, mod, dest, src, len, volatile)
    T_nothing = LLVM.VoidType(ctx)
    T_dest = llvmtype(dest)
    T_src = llvmtype(src)
    T_int8 = convert(LLVMType, UInt8; ctx)
    T_int64 = convert(LLVMType, UInt64; ctx)
    T_int1 = LLVM.Int1Type(ctx)

    T_intr = LLVM.FunctionType(T_nothing, [T_dest, T_src, T_int64, T_int1])
    intr = LLVM.Function(mod, "llvm.memcpy.p$(Int(addrspace(T_dest)))p$(Int(addrspace(T_src))).i64", T_intr)
    call!(builder, intr, [dest, src, len, volatile])
end
@inline @generated function memcpy!(dest_ptr::LLVMPtr{UInt8,DestAS}, src_ptr::LLVMPtr{UInt8,SrcAS}, len::LT) where {DestAS,SrcAS,LT<:Union{Int64,UInt64}}
    Context() do ctx
        T_nothing = LLVM.VoidType(ctx)
        T_pint8_dest = convert(LLVMType, dest_ptr; ctx)
        T_pint8_src = convert(LLVMType, src_ptr; ctx)
        T_int8 = convert(LLVMType, UInt8; ctx)
        T_int64 = convert(LLVMType, UInt64; ctx)
        T_int1 = LLVM.Int1Type(ctx)

        llvm_f, _ = create_function(T_nothing, [T_pint8_dest, T_pint8_src, T_int64])
        mod = LLVM.parent(llvm_f)
        Builder(ctx) do builder
            entry = BasicBlock(llvm_f, "entry"; ctx)
            position!(builder, entry)

            _memcpy!(builder, ctx, mod, parameters(llvm_f)[1], parameters(llvm_f)[2], parameters(llvm_f)[3], ConstantInt(T_int1, 0))
            ret!(builder)
        end
        call_function(llvm_f, Nothing, Tuple{LLVMPtr{UInt8,DestAS},LLVMPtr{UInt8,SrcAS},LT}, :dest_ptr, :src_ptr, :len)
    end
end
@inline memcpy!(dest_ptr::LLVMPtr{T,DestAS}, src_ptr::LLVMPtr{T,SrcAS}, len::Integer) where {T,DestAS,SrcAS} =
    memcpy!(reinterpret(LLVMPtr{UInt8,DestAS}, dest_ptr), reinterpret(LLVMPtr{UInt8,SrcAS}, src_ptr), UInt64(len))
@inline memcpy!(dest_ptr::Union{<:Ptr,<:LLVMPtr}, src_ptr::Union{<:Ptr,<:LLVMPtr}, len::Integer) =
    memcpy!(reinterpret(LLVMPtr{UInt8,0}, dest_ptr), reinterpret(LLVMPtr{UInt8,0}, src_ptr), UInt64(len))

@inline function ZeroInitRef(T)
    ref = Ref{T}()
    ref_llptr = reinterpret(LLVMPtr{T,0}, Base.unsafe_convert(Ptr{T}, ref))
    memset!(ref_llptr, UInt8(0), sizeof(T))
    ref
end
@inline function ZeroInitRef(T, val)
    ref = ZeroInitRef(T)
    ref[] = val
    ref
end
