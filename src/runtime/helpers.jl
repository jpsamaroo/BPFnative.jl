# BPF helpers

bpfconvert(x) = x
bpfconvert(x::AbstractBuffer) = pointer(x)

@inline probe_read(buf::AbstractSizedBuffer, addr::BufPtr) =
    bpfcall(API.probe_read, Clong, Tuple{BufPtr, UInt32, BufPtr}, pointer(buf), length(buf), addr)
@inline ktime_get_ns() = bpfcall(API.ktime_get_ns, UInt64)
@inline trace_printk(fmt::AbstractSizedBuffer, x...) = # TODO: Allow trailing arguments
    bpfcall(API.trace_printk, Clong, Tuple{BufPtr, UInt32, typeof(bpfconvert.(x))...}, pointer(fmt), length(fmt), map(bpfconvert, x)...)
@inline get_prandom_u32() = bpfcall(API.get_prandom_u32, UInt32)
@inline get_smp_processor_id() = bpfcall(API.get_smp_processor_id, UInt32)
# TODO: skb_store_bytes
# TODO: l3_csum_replace
# TODO: l4_csum_replace
# TODO: tail_call
# TODO: clone_redirect
@inline get_current_pid_tgid() = bpfcall(API.get_current_pid_tgid, UInt64) # TODO: Return Tuple{UInt32,UInt32}
@inline get_current_uid_gid() = bpfcall(API.get_current_uid_gid, UInt64) # TODO: Return Tuple{UInt32,UInt32}
@inline get_current_comm(buf::AbstractSizedBuffer) =
    bpfcall(API.get_current_comm, Clong, Tuple{BufPtr, UInt32}, pointer(buf), length(buf))
# TODO: The rest!

function split_u64_u32(x::UInt64)
    lower = Base.unsafe_trunc(UInt32, x)
    upper = Base.unsafe_trunc(UInt32, (x & (UInt64(typemax(UInt32)) << 32)) >> 32)
    return lower, upper
end
