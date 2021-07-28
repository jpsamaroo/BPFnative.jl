@inline function safe_load(ptr::Ref{T}) where T
    dest = Ref{T}()
    dest_ptr = Base.unsafe_convert(Ptr{T}, dest)
    src_ptr = Base.unsafe_convert(Ptr{T}, ptr)
    if probe_read_kernel(dest_ptr, sizeof(T), src_ptr) == 0
        return dest[]
    else
        return nothing
    end
end

@inline elemptr(ptr::Ptr{T}, ::Val{field}) where {T,field} =
    reinterpret(Ptr{API._fieldtype(T, Val(field))}, ptr + API.offsetof(T, Val(field)))
@inline arrptr(ptr::Ptr{T}, idx) where T =
    ptr + (sizeof(T)*(idx-1))
@inline function elemptr(ptr::Cptr{T}, ::Val{field}) where {T,field}
    S = API._fieldtype(typeof(ptr), Val(field))
    if S <: Cptr
        # unsafe, need to use helper
        ref = ZeroInitRef(S)
        ref_ptr = Base.unsafe_convert(Ptr{S}, ref)
        if probe_read_kernel(ref_ptr, sizeof(S), reinterpret(Ptr{S}, ptr)) != 0
            return nothing
        end
        return ref[]
    else
        return getproperty(ptr, field)
    end
end
@inline function elemptr(ptr::Cptr{T}) where T
    # unsafe, need to use helper
    ref = ZeroInitRef(T)
    ref_ptr = Base.unsafe_convert(Ptr{T}, ref)
    if probe_read_kernel(ref_ptr, sizeof(T), reinterpret(Ptr{T}, ptr)) != 0
        return nothing
    end
    return ref[]
end
@inline arrptr(ptr::Cptr{T}, idx) where T =
    getindex(ptr, idx)
@inline elemptr(::Nothing, field) = nothing
@inline arrptr(::Nothing, field) = nothing
@inline _toptr(ptr::Ptr) = ptr
@inline _toptr(ref::Base.RefValue{T}) where T = Base.unsafe_convert(Ptr{T}, ref)
@inline _toptr(ptr::Cptr) = ptr

"Returns a pointer to the final element referenced in `ex`, where the
parent object of `ex` is a `Ptr` or `Ref`."
macro elemptr(ex)
    @assert Meta.isexpr(ex, :(.)) || Meta.isexpr(ex, :ref) "@elemptr expects a struct field or array access"
    rootex = Expr(:block, Expr(:block), nothing)
    refex = rootex
    while true
        if Meta.isexpr(ex, :(.))
            refex.args[2] = :($elemptr(nothing, $(Val(ex.args[2].value))))
        elseif Meta.isexpr(ex, :ref)
            if length(ex.args) == 2
                refex.args[2] = :($arrptr(nothing, $(esc(ex.args[2]))))
            else
                refex.args[2] = :($elemptr(nothing))
            end
        else
            break
        end
        refex = refex.args[2]
        ex = ex.args[1]
    end
    refex.args[2] = :($_toptr($(esc(ex))))
    rootex
end
