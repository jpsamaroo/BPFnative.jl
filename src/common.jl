export BPFCmd, BPFMapType, BPFProgType, BPFAttachType, BPFHelper

@enum BPFCmd begin
    BPF_MAP_CREATE
    BPF_MAP_LOOKUP_ELEM
    BPF_MAP_UPDATE_ELEM
    BPF_MAP_DELETE_ELEM
    BPF_MAP_GET_NEXT_KEY
    BPF_PROG_LOAD
    BPF_OBJ_PIN
    BPF_OBJ_GET
    BPF_PROG_ATTACH
    BPF_PROG_DETACH
    BPF_PROG_TEST_RUN
    BPF_PROG_GET_NEXT_ID
    BPF_MAP_GET_NEXT_ID
    BPF_PROG_GET_FD_BY_ID
    BPF_MAP_GET_FD_BY_ID
    BPF_OBJ_GET_INFO_BY_FD
    BPF_PROG_QUERY
    BPF_RAW_TRACEPOINT_OPEN
    BPF_BTF_LOAD
    BPF_BTF_GET_FD_BY_ID
    BPF_TASK_FD_QUERY
    BPF_MAP_LOOKUP_AND_DELETE_ELEM
    BPF_MAP_FREEZE
    BPF_BTF_GET_NEXT_ID
    BPF_MAP_LOOKUP_BATCH
    BPF_MAP_LOOKUP_AND_DELETE_BATCH
    BPF_MAP_UPDATE_BATCH
    BPF_MAP_DELETE_BATCH
    BPF_LINK_CREATE
    BPF_LINK_UPDATE
end

@enum BPFMapType begin
    BPF_MAP_TYPE_UNSPEC
    BPF_MAP_TYPE_HASH
    BPF_MAP_TYPE_ARRAY
    BPF_MAP_TYPE_PROG_ARRAY
    BPF_MAP_TYPE_PERF_EVENT_ARRAY
    BPF_MAP_TYPE_PERCPU_HASH
    BPF_MAP_TYPE_PERCPU_ARRAY
    BPF_MAP_TYPE_STACK_TRACE
    BPF_MAP_TYPE_CGROUP_ARRAY
    BPF_MAP_TYPE_LRU_HASH
    BPF_MAP_TYPE_LRU_PERCPU_HASH
    BPF_MAP_TYPE_LPM_TRIE
    BPF_MAP_TYPE_ARRAY_OF_MAPS
    BPF_MAP_TYPE_HASH_OF_MAPS
    BPF_MAP_TYPE_DEVMAP
    BPF_MAP_TYPE_SOCKMAP
    BPF_MAP_TYPE_CPUMAP
    BPF_MAP_TYPE_XSKMAP
    BPF_MAP_TYPE_SOCKHASH
    BPF_MAP_TYPE_CGROUP_STORAGE
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
    BPF_MAP_TYPE_QUEUE
    BPF_MAP_TYPE_STACK
    BPF_MAP_TYPE_SK_STORAGE
    BPF_MAP_TYPE_DEVMAP_HASH
    BPF_MAP_TYPE_STRUCT_OPS
end

@enum BPFProgType begin
    BPF_PROG_TYPE_UNSPEC
    BPF_PROG_TYPE_SOCKET_FILTER
    BPF_PROG_TYPE_KPROBE
    BPF_PROG_TYPE_SCHED_CLS
    BPF_PROG_TYPE_SCHED_ACT
    BPF_PROG_TYPE_TRACEPOINT
    BPF_PROG_TYPE_XDP
    BPF_PROG_TYPE_PERF_EVENT
    BPF_PROG_TYPE_CGROUP_SKB
    BPF_PROG_TYPE_CGROUP_SOCK
    BPF_PROG_TYPE_LWT_IN
    BPF_PROG_TYPE_LWT_OUT
    BPF_PROG_TYPE_LWT_XMIT
    BPF_PROG_TYPE_SOCK_OPS
    BPF_PROG_TYPE_SK_SKB
    BPF_PROG_TYPE_CGROUP_DEVICE
    BPF_PROG_TYPE_SK_MSG
    BPF_PROG_TYPE_RAW_TRACEPOINT
    BPF_PROG_TYPE_CGROUP_SOCK_ADDR
    BPF_PROG_TYPE_LWT_SEG6LOCAL
    BPF_PROG_TYPE_LIRC_MODE2
    BPF_PROG_TYPE_SK_REUSEPORT
    BPF_PROG_TYPE_FLOW_DISSECTOR
    BPF_PROG_TYPE_CGROUP_SYSCTL
    BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
    BPF_PROG_TYPE_CGROUP_SOCKOPT
    BPF_PROG_TYPE_TRACING
    BPF_PROG_TYPE_STRUCT_OPS
    BPF_PROG_TYPE_EXT
    BPF_PROG_TYPE_LSM
end

@enum BPFAttachType begin
    BPF_CGROUP_INET_INGRESS
    BPF_CGROUP_INET_EGRESS
    BPF_CGROUP_INET_SOCK_CREATE
    BPF_CGROUP_SOCK_OPS
    BPF_SK_SKB_STREAM_PARSER
    BPF_SK_SKB_STREAM_VERDICT
    BPF_CGROUP_DEVICE
    BPF_SK_MSG_VERDICT
    BPF_CGROUP_INET4_BIND
    BPF_CGROUP_INET6_BIND
    BPF_CGROUP_INET4_CONNECT
    BPF_CGROUP_INET6_CONNECT
    BPF_CGROUP_INET4_POST_BIND
    BPF_CGROUP_INET6_POST_BIND
    BPF_CGROUP_UDP4_SENDMSG
    BPF_CGROUP_UDP6_SENDMSG
    BPF_LIRC_MODE2
    BPF_FLOW_DISSECTOR
    BPF_CGROUP_SYSCTL
    BPF_CGROUP_UDP4_RECVMSG
    BPF_CGROUP_UDP6_RECVMSG
    BPF_CGROUP_GETSOCKOPT
    BPF_CGROUP_SETSOCKOPT
    BPF_TRACE_RAW_TP
    BPF_TRACE_FENTRY
    BPF_TRACE_FEXIT
    BPF_MODIFY_RETURN
    BPF_LSM_MAC
end

@enum BPFHelper begin
    unspec
    map_lookup_elem
    map_update_elem
    map_delete_elem
    probe_read
    ktime_get_ns
    trace_printk
    get_prandom_u32
    get_smp_processor_id
    skb_store_bytes
    l3_csum_replace
    l4_csum_replace
    tail_call
    clone_redirect
    get_current_pid_tgid
    get_current_uid_gid
    get_current_comm
    get_cgroup_classid
    skb_vlan_push
    skb_vlan_pop
    skb_get_tunnel_key
    skb_set_tunnel_key
    perf_event_read
    redirect
    get_route_realm
    perf_event_output
    skb_load_bytes
    get_stackid
    csum_diff
    skb_get_tunnel_opt
    skb_set_tunnel_opt
    skb_change_proto
    skb_change_type
    skb_under_cgroup
    get_hash_recalc
    get_current_task
    probe_write_user
    current_task_under_cgroup
    skb_change_tail
    skb_pull_data
    csum_update
    set_hash_invalid
    get_numa_node_id
    skb_change_head
    xdp_adjust_head
    probe_read_str
    get_socket_cookie
    get_socket_uid
    set_hash
    setsockopt
    skb_adjust_room
    redirect_map
    sk_redirect_map
    sock_map_update
    xdp_adjust_meta
    perf_event_read_value
    perf_prog_read_value
    getsockopt
    override_return
    sock_ops_cb_flags_set
    msg_redirect_map
    msg_apply_bytes
    msg_cork_bytes
    msg_pull_data
    bind
    xdp_adjust_tail
    skb_get_xfrm_state
    get_stack
    skb_load_bytes_relative
    fib_lookup
    sock_hash_update
    msg_redirect_hash
    sk_redirect_hash
    lwt_push_encap
    lwt_seg6_store_bytes
    lwt_seg6_adjust_srh
    lwt_seg6_action
    rc_repeat
    rc_keydown
    skb_cgroup_id
    get_current_cgroup_id
    get_local_storage
    sk_select_reuseport
    skb_ancestor_cgroup_id
    sk_lookup_tcp
    sk_lookup_udp
    sk_release
    map_push_elem
    map_pop_elem
    map_peek_elem
    msg_push_data
    msg_pop_data
    rc_pointer_rel
    spin_lock
    spin_unlock
    sk_fullsock
    tcp_sock
    skb_ecn_set_ce
    get_listener_sock
    skc_lookup_tcp
    tcp_check_syncookie
    sysctl_get_name
    sysctl_get_current_value
    sysctl_get_new_value
    sysctl_set_new_value
    strtol
    strtoul
    sk_storage_get
    sk_storage_delete
    send_signal
    tcp_gen_syncookie
    skb_output
    probe_read_user
    probe_read_kernel
    probe_read_user_str
    probe_read_kernel_str
    tcp_send_ack
    send_signal_thread
    jiffies64
    read_branch_records
    get_ns_current_pid_tgid
    xdp_output
    get_netns_cookie
    get_current_ancestor_cgroup_id
    sk_assign
end

const PERF_MAX_STACK_DEPTH = 127

# Kernel structures

if has_vmlinux

const pt_regs = c".VMLinux.struct pt_regs"
pointertype(::Type{pt_regs}) = Cptr{pt_regs}

const xdp_md = c".VMLinux.struct xdp_md"
pointertype(::Type{xdp_md}) = Cptr{xdp_md}

const sk_buff = c".VMLinux.struct sk_buff"
pointertype(::Type{sk_buff}) = Cptr{sk_buff}

const task_struct = c".VMLinux.struct task_struct"
pointertype(::Type{task_struct}) = Cptr{task_struct}

else

## Perf/Ptrace

# TODO: pt_regs for other architectures
if Sys.ARCH == :x86_64
struct pt_regs
    r15::Culong
    r14::Culong
    r13::Culong
    r12::Culong
    rbp::Culong
    rbx::Culong
    r11::Culong
    r10::Culong
    r9::Culong
    r8::Culong
    rax::Culong
    rcx::Culong
    rdx::Culong
    rsi::Culong
    rdi::Culong
    orig_rax::Culong
    rip::Culong
    cs::Culong
    eflags::Culong
    rsp::Culong
    ss::Culong
end
else
struct pt_regs
    ebx::Clong
    ecx::Clong
    edx::Clong
    esi::Clong
    edi::Clong
    ebp::Clong
    eax::Clong
    xds::Cint
    xes::Cint
    xfs::Cint
    xgs::Cint
    orig_eax::Clong
    eip::Clong
    xcs::Cint
    eflags::Clong
    esp::Clong
    xss::Cint
end
end # x86_64
pointertype(::Type{pt_regs}) = Ptr{pt_regs}

## XDP

struct xdp_md
    data::UInt32
    data_end::UInt32
    data_meta::UInt32
    ingress_ifindex::UInt32
    rx_queue_index::UInt32
end
pointertype(::Type{xdp_md}) = Ptr{xdp_md}

## Sockets/TC

struct sk_buff
    len::UInt32
    pkt_type::UInt32
    mark::UInt32
    queue_mapping::UInt32
    protocol::UInt32
    vlan_present::UInt32
    vlan_tci::UInt32
    vlan_proto::UInt32
    priority::UInt32
    ingress_ifindex::UInt32
    ifindex::UInt32
    tc_index::UInt32
    cb::NTuple{5,UInt32}
    hash::UInt32
    tc_classid::UInt32
    data::UInt32
    data_end::UInt32
    napi_id::UInt32

    family::UInt32
    remote_ip4::UInt32           # Stored in network byte order
    local_ip4::UInt32            # Stored in network byte order
    remote_ip6::NTuple{4,UInt32} # Stored in network byte order
    local_ip6::NTuple{4,UInt32}  # Stored in network byte order
    remote_port::UInt32          # Stored in network byte order
    local_port::UInt32           # Stored in host byte order

    data_meta::UInt32
    flow_keys::Ptr{Cvoid} #__bpf_md_ptr(struct bpf_flow_keys *, flow_keys);
    tstamp::UInt64
    wire_len::UInt32
    gso_segs::UInt32
    sk::Ptr{Cvoid} #__bpf_md_ptr(struct bpf_sock *, sk);
    gso_size::UInt32
end
pointertype(::Type{sk_buff}) = Ptr{sk_buff}

const task_struct = Nothing
pointertype(::Type{task_struct}) = Ptr{task_struct}

end

@inline get_param(ctx::Cptr, ::Val{idx}) where idx =
    unsafe_load(_get_param(ctx, Val(idx)))
@inline get_param(ctx::Ptr, ::Val{idx}) where idx =
    _get_param(unsafe_load(ctx), Val(idx))

@static if Sys.ARCH == :x86_64
function _get_param(ctx, ::Val{idx}) where idx
    @assert 1 <= idx <= 5 "Invalid parameter index: $idx"
    idx == 1 && return ctx.di
    idx == 2 && return ctx.si
    idx == 3 && return ctx.dx
    idx == 4 && return ctx.cx
    idx == 5 && return ctx.r8
end
end
