# BPF helpers

# TODO: Allow trailing arguments
@inline trace_printk(fmt::AbstractSizedBuffer) =
    bpfcall(API.trace_printk, Clong, Tuple{BufPtr, UInt32}, pointer(fmt), length(fmt))
@inline get_current_comm(buf::AbstractSizedBuffer) =
    bpfcall(API.get_current_comm, Clong, Tuple{BufPtr, UInt32}, pointer(buf), length(buf))
# TODO: Return Tuple{UInt32,UInt32}
@inline get_current_pid_tgid() = bpfcall(API.get_current_pid_tgid, UInt64)

function split_u64_u32(x::UInt64)
    lower = Base.unsafe_trunc(UInt32, x)
    upper = Base.unsafe_trunc(UInt32, (x & (UInt64(typemax(UInt32)) << 32)) >> 32)
    return lower, upper
end
