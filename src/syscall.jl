# Raw BPF calls

const SYS_bpf = 321

function bpf(cmd::API.BPFCmd, attr::Ref{T}) where {T}
    vec = zeros(UInt8, 120)
    GC.@preserve vec attr begin
        p_attr = Base.unsafe_convert(Ptr{Cvoid}, Base.cconvert(Ptr{Cvoid}, attr))
        ccall(:memcpy, Ptr{Cvoid}, (Ptr{UInt8},   Ptr{Cvoid}, Csize_t),
                                    pointer(vec), p_attr,     sizeof(T))
        ptr = Ptr{Cvoid}(pointer(vec))
        res = ccall(:syscall, Cint, (Clong,    Cint,      Ptr{Cvoid}, Cuint),
                                     SYS_bpf,  Cint(cmd), ptr,        Cuint(120)) # FIXME: sizeof(T)
        ccall(:memcpy, Ptr{Cvoid}, (Ptr{Cvoid}, Ptr{UInt8},   Csize_t),
                                    p_attr,     pointer(vec), sizeof(T))
        return res
    end
end
