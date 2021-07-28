abstract type HostMap{K,V} end
abstract type AbstractHashMap{K,V} <: HostMap{K,V} end
abstract type AbstractArrayMap{K,V} <: HostMap{K,V} end

function hostmap(map::API.Map; K, V)
    fd = API.fd(map)
    @assert fd > 0 "Map \"$(API.name(map))\" is not yet allocated"
    def = API.definition(map)
    map_type = API.BPFMapType(def.type)
    jltype = maptype_to_jltype(Val(map_type))
    jltype{K,V}(fd)
end

struct HashMap{K,V} <: AbstractHashMap{K,V}
    fd::Cint
end
maptype_to_jltype(::Val{API.BPF_MAP_TYPE_HASH}) = HashMap
maptype_to_jltype(::Val{API.BPF_MAP_TYPE_STACK_TRACE}) = HashMap
struct ArrayMap{K,V} <: AbstractArrayMap{K,V}
    fd::Cint
end
maptype_to_jltype(::Val{API.BPF_MAP_TYPE_ARRAY}) = ArrayMap

struct map_create_attr
    map_type::UInt32
    key_size::UInt32
    value_size::UInt32
    max_entries::UInt32
end

function HostMap(; map_type, key_type, value_type, max_entries)
    attr = Ref(map_create_attr(UInt32(map_type),
                               sizeof(key_type),
                               sizeof(value_type),
                               max_entries))
    fd = bpf(API.BPF_MAP_CREATE, attr)
    fd > 0 || Base.systemerror(fd)
    jltype = maptype_to_jltype(Val(map_type))
    jltype{key_type,value_type}(fd)
end

struct map_access_elem_attr
    map_fd::UInt32
    key::UInt64
    value_or_next::UInt64
    flags::UInt64
end

memset!(ptr::Ptr{T}) where T =
    ccall(:memset, Cvoid,
          (Ptr{T}, UInt8, UInt64),
          ptr, UInt8(0), sizeof(T))
"Creates a Ref{T} that's been zero-initialized before being stored. Necessary
to ensure that struct padding bytes are zeroed."
function ZeroInitRef(T, val; set=true)
    ref = Ref{T}()
    memset!(Base.unsafe_convert(Ptr{T}, ref))
    if set
        ref[] = val
    end
    ref
end
ZeroInitRef(val::T) where T = ZeroInitRef(T, val)
ZeroInitRef(::Type{T}) where T = ZeroInitRef(T, nothing; set=false)

function Base.getindex(map::AbstractHashMap{K,V}, idx) where {K,V}
    key = ZeroInitRef(K, idx)
    value = Ref{V}()
    key_ptr = Base.unsafe_convert(Ptr{K}, key)
    value_ptr = Base.unsafe_convert(Ptr{V}, value)
    attr = Ref(map_access_elem_attr(map.fd,
                                    key_ptr,
                                    value_ptr,
                                    0))
    ret = GC.@preserve key value begin
        bpf(API.BPF_MAP_LOOKUP_ELEM, attr)
    end
    ret >= 0 || Base.systemerror(ret)
    value[]
end
function Base.getindex(map::AbstractArrayMap{K,V}, idx) where {K,V}
    key = ZeroInitRef(K, idx-1)
    value = Ref{V}()
    key_ptr = Base.unsafe_convert(Ptr{K}, key)
    value_ptr = Base.unsafe_convert(Ptr{V}, value)
    attr = Ref(map_access_elem_attr(map.fd,
                                    key_ptr,
                                    value_ptr,
                                    0))
    ret = GC.@preserve key value begin
        bpf(API.BPF_MAP_LOOKUP_ELEM, attr)
    end
    ret >= 0 || Base.systemerror(ret)
    value[]
end

function Base.setindex!(map::AbstractHashMap{K,V}, value::U, idx) where {K,V,U}
    key_ref = ZeroInitRef(convert(K,idx))
    value_ref = ZeroInitRef(convert(V,value))
    key_ptr = Base.unsafe_convert(Ptr{K}, key_ref)
    value_ptr = Base.unsafe_convert(Ptr{V}, value_ref)
    attr = Ref(map_access_elem_attr(map.fd,
                                    key_ptr,
                                    value_ptr,
                                    0))
    ret = GC.@preserve key_ref value_ref begin
        bpf(API.BPF_MAP_UPDATE_ELEM, attr)
    end
    ret >= 0 || Base.systemerror(ret)
    value
end
function Base.setindex!(map::AbstractArrayMap{K,V}, value::U, idx) where {K,V,U}
    key_ref = ZeroInitRef(convert(K,idx-1))
    value_ref = ZeroInitRef(convert(V,value))
    key_ptr = Base.unsafe_convert(Ptr{K}, key_ref)
    value_ptr = Base.unsafe_convert(Ptr{V}, value_ref)
    attr = Ref(map_access_elem_attr(map.fd,
                                    key_ptr,
                                    value_ptr,
                                    0))
    ret = GC.@preserve key_ref value_ref begin
        bpf(API.BPF_MAP_UPDATE_ELEM, attr)
    end
    ret >= 0 || Base.systemerror(ret)
    value
end

function Base.delete!(map::AbstractHashMap{K,V}, idx) where {K,V}
    key = ZeroInitRef(K, idx)
    key_ptr = Base.unsafe_convert(Ptr{K}, key)
    attr = Ref(map_access_elem_attr(map.fd,
                                    key_ptr,
                                    0,
                                    0))
    GC.@preserve key begin
        @assert bpf(API.BPF_MAP_DELETE_ELEM, attr) >= 0
    end
    map
end

function Base.haskey(map::HostMap{K,V}, idx) where {K,V}
    key = ZeroInitRef(K, idx)
    value = Ref{V}()
    key_ptr = Base.unsafe_convert(Ptr{K}, key)
    value_ptr = Base.unsafe_convert(Ptr{V}, value)
    attr = Ref(map_access_elem_attr(map.fd,
                                    key_ptr,
                                    value_ptr,
                                    0))
    GC.@preserve key value begin
        bpf(API.BPF_MAP_LOOKUP_ELEM, attr) == 0
    end
end

function nextkey(map::HostMap{K,V}, idx) where {K,V}
    key = ZeroInitRef(K, idx)
    nkey = Ref{K}()
    key_ptr = Base.unsafe_convert(Ptr{K}, key)
    nkey_ptr = Base.unsafe_convert(Ptr{K}, nkey)
    attr = Ref(map_access_elem_attr(map.fd,
                                    key_ptr,
                                    nkey_ptr,
                                    0))
    ret = GC.@preserve key nkey begin
        bpf(API.BPF_MAP_GET_NEXT_KEY, attr)
    end
    if (ret == -1) && (Libc.errno() == Libc.ENOENT)
        return nothing
    end
    ret >= 0 || Base.systemerror(ret)
    nkey[]
end

struct HostMapKeySet{K,V,H<:HostMap{K,V}}
    map::H
end
function Base.length(hk::HostMapKeySet)
    ctr = 0
    for key in hk
        ctr += 1
    end
    ctr
end
Base.keys(map::H) where {K,V,H<:HostMap{K,V}} = HostMapKeySet{K,V,H}(map)
Base.IteratorSize(::Type{<:HostMapKeySet}) = Base.SizeUnknown()
Base.eltype(::Type{HostMapKeySet{K,V,H}}) where {K,V,H} = K
function Base.iterate(hmks::HostMapKeySet{K,V,H}) where {K,V,H}
    fakekey_ref = ZeroInitRef(K)
    realkey = if haskey(hmks.map, fakekey_ref[])
        fakekey_ref[]
    else
        nextkey(hmks.map, fakekey_ref[])
    end
    realkey === nothing && return nothing # empty
    return realkey, (realkey, realkey)
end
function Base.iterate(hmks::HostMapKeySet{K,V,H}, (lastkey, initial)) where {K,V,H}
    lastkey === nothing && return nothing
    nkey = nextkey(hmks.map, lastkey)
    if nkey === nothing || nkey == lastkey
        return nothing
    end
    return nkey, (nkey == initial ? nothing : nkey, initial)
end
Base.length(map::HostMap) = length(keys(map))
