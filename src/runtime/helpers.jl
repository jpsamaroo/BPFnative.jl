# BPF helpers

const ptr_sk_buff = API.pointertype(API.sk_buff)
const ptr_task_struct = API.pointertype(API.task_struct)

bpfconvert(x) = x
bpfconvert(x::AbstractBuffer) = pointer(x)

@inline function refwrap(f, x::T) where T
    x_ref = Ref{T}(x)
    GC.@preserve x_ref begin
        f(Base.unsafe_convert(Ptr{T}, x_ref))
    end
end

@inline probe_read(buf::AbstractSizedBuffer, addr::BufPtr) =
    bpfcall(API.probe_read, Clong, Tuple{BufPtr, UInt32, BufPtr}, pointer(buf), length(buf), addr)

@inline ktime_get_ns() = bpfcall(API.ktime_get_ns, UInt64)

@inline trace_printk(fmt::AbstractSizedBuffer, x...) = # TODO: Allow only 3 trailing arguments
    bpfcall(API.trace_printk, Clong, Tuple{BufPtr, UInt32, typeof(bpfconvert.(x))...}, pointer(fmt), length(fmt), map(bpfconvert, x)...)

@inline get_prandom_u32() = bpfcall(API.get_prandom_u32, UInt32)

@inline get_smp_processor_id() = bpfcall(API.get_smp_processor_id, UInt32)

@inline skb_store_bytes(skb::ptr_sk_buff, offset::UInt32, from::Ptr{Cvoid}, len::UInt32, flags::UInt64) =
    bpfcall(API.skb_store_bytes, Clong, Tuple{ptr_sk_buff, UInt32, Ptr{Cvoid}, UInt32, UInt64}, skb, offset, from, len, flags)
@inline skb_store_bytes(skb::ptr_sk_buff, offset, from, len, flags) = refwrap(from) do from_ref
    skb_store_bytes(skb, unsafe_trunc(UInt32, offset), reinterpret(Ptr{Cvoid}, from_ref), unsafe_trunc(UInt32, len), unsafe_trunc(UInt64, flags))
end
@inline l3_csum_replace(skb::ptr_sk_buff, offset::UInt32, from::UInt64, to::UInt64, size::UInt64) =
    bpfcall(API.l3_csum_replace, Clong, Tuple{ptr_sk_buff, UInt32, UInt64, UInt64, UInt64}, skb, offset, from, to, size)
@inline l3_csum_replace(skb::ptr_sk_buff, offset, from, to, size) =
    l3_csum_replace(skb, unsafe_trunc(UInt32, offset), unsafe_trunc(UInt64, from), unsafe_trunc(UInt64, to), unsafe_trunc(UInt64, size))
@inline l4_csum_replace(skb::ptr_sk_buff, offset::UInt32, from::UInt64, to::UInt64, flags::UInt64) =
    bpfcall(API.l4_csum_replace, Clong, Tuple{ptr_sk_buff, UInt32, UInt64, UInt64, UInt64}, skb, offset, from, to, flags)
@inline l4_csum_replace(skb::ptr_sk_buff, offset, from, to, flags) =
    l4_csum_replace(skb, unsafe_trunc(UInt32, offset), unsafe_trunc(UInt64, from), unsafe_trunc(UInt64, to), unsafe_trunc(UInt64, flags))

# TODO: tail_call

@inline clone_redirect(skb::ptr_sk_buff, ifindex::UInt32, flags::UInt64) =
    bpfcall(API.clone_redirect, Clong, Tuple{ptr_sk_buff, UInt32, UInt64}, skb, ifindex, flags)

function split_u64_u32(x::UInt64)
    lower = Base.unsafe_trunc(UInt32, x)
    upper = Base.unsafe_trunc(UInt32, x >> 32)
    return lower, upper
end

@inline get_current_pid_tgid() = split_u64_u32(bpfcall(API.get_current_pid_tgid, UInt64))
@inline get_current_uid_gid() = split_u64_u32(bpfcall(API.get_current_uid_gid, UInt64))
@inline get_current_comm(buf::AbstractSizedBuffer) =
    bpfcall(API.get_current_comm, Clong, Tuple{BufPtr, UInt32}, pointer(buf), length(buf))

@inline get_stackid(ctx::T, map::M, flags::Integer) where {T,M<:RTMap} =
    bpfcall(API.get_stackid, Clong, Tuple{T, M, UInt64}, ctx, map, unsafe_trunc(UInt64,flags))
@inline function get_current_task()
    res = bpfcall(API.get_current_task, UInt64)
    if res > 0
        unsafe_load(reinterpret(ptr_task_struct, res))
    else
        nothing
    end
end
@inline get_stack(ctx::T, buf::AbstractSizedBuffer, flags::UInt64) where {T} =
    bpfcall(API.get_stack, Clong, Tuple{T, BufPtr, UInt32, UInt64}, ctx, pointer(buf), length(buf), flags)
@inline get_task_stack(ctx::ptr_task_struct, buf::AbstractSizedBuffer, flags::UInt64) where {T} =
    bpfcall(API.get_task_stack, Clong, Tuple{ptr_task_struct, BufPtr, UInt32, UInt64}, ctx, pointer(buf), length(buf), flags)

# TODO: The rest!
