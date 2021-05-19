const SOL_SOCKET = 1
const SO_PROTOCOL = 38
const SO_DETACH_BPF = 27
const SO_ATTACH_BPF = 50
function getsockopt(sock, level, optname, T)
    optval_ref = Ref{T}(zero(T))
    optlen_ref = Ref{Cint}(sizeof(T))
    GC.@preserve optval_ref begin
    ret = ccall(:getsockopt, Cint,
                             (Cint, Cint, Cint, Ptr{Cvoid}, Ptr{Cint}),
                             Base._fd(sock), level, optname, optval_ref, optlen_ref)
    end
    ret != 0 && Base.systemerror(ret)
    optval_ref[]
end
function setsockopt(sock, level, optname, optval)
    optval_ref = Ref{typeof(optval)}(optval)
    GC.@preserve optval_ref begin
    ret = ccall(:setsockopt, Cint,
                             (Cint, Cint, Cint, Ptr{Cvoid}, Cint),
                             Base._fd(sock), level, optname, optval_ref, sizeof(optval))
    end
    ret != 0 && Base.systemerror(ret)
    ret
end
