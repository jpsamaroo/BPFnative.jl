@generated function offsetof(::Type{T}, ::Val{_field}) where {T<:CBinding.Cstruct,_field}
    offset = -1
    for field in CBinding.fields(T).parameters
        if field.parameters[1] == _field
            offset = field.parameters[2].parameters[4]
            break
        end
    end
    @assert offset >= 0 "Failed to find offset of $_field in $T"
    :($offset)
end
@generated function offsetof(::Type{T}, ::Val{_field}) where {T,_field}
    @assert isstructtype(T) "offsetof is only valid for structs"
    offset = -1
    for (idx,field) in enumerate(fieldnames(T))
        if field == _field
            offset = fieldoffset(T, idx)
            break
        end
    end
    @assert offset >= 0 "Failed to find offset of $_field in $T"
    :($offset)
end
"Returns the integer offset of `field` in `T`."
macro offsetof(T, field)
    :($offsetof($T, Val($field)))
end

@generated _fieldtype(::Type{T}, ::Val{field}) where {T,field} =
    :($(fieldtype(T, field)))
@generated _fieldtype(::Type{T}, ::Val{field}) where {T<:CBinding.Cstruct,field} =
    :($(CBinding.field(T, field).parameters[2]))
@inline _fieldtype(::Type{Cptr{T}}, ::Val{field}) where {T,field} =
    _fieldtype(T, Val(field))
