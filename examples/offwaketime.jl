#= Copyright (c) 2016 Facebook

   This program is free software; you can redistribute it and/or
   modify it under the terms of version 2 of the GNU General Public
   License as published by the Free Software Foundation.

   Ported to Julia by Julian P Samaroo, 2021
=#

ccall(:jl_exit_on_sigint, Cvoid, (Cint,), 0)

if length(ARGS) > 0
    const out_path = ARGS[1]
    const root_pids = parse.(Cint, ARGS[2:end])
else
    const out_path = nothing
    const root_pids = [getpid()]
end
_all_pids = ()
for root_pid in root_pids
    global _all_pids = (_all_pids..., parse.(Int, readdir("/proc/$root_pid/task"))...)
end
const all_pids = _all_pids::NTuple

using BPFnative
import BPFnative: API, RT, Host, VMLinux
using CBinding

const MINBLOCK_US = 1
const TASK_COMM_LEN = 32

struct Key
    waker::NTuple{TASK_COMM_LEN,UInt8}
    target::NTuple{TASK_COMM_LEN,UInt8}
    wret::UInt32
    tret::UInt32
    wpid::UInt32
    tpid::UInt32
end

const counts = RT.RTMap(;name = "counts",
                   maptype = API.BPF_MAP_TYPE_HASH,
                   keytype = Key,
                   valuetype = UInt64,
                   maxentries = 10000)

const start = RT.RTMap(;name = "start",
                  maptype = API.BPF_MAP_TYPE_HASH,
                  keytype = UInt32,
                  valuetype = UInt64,
                  maxentries = 10000)

struct WokeBy
    name::NTuple{TASK_COMM_LEN,UInt8}
    ret::UInt32
    pid::UInt32
end

const wokeby = RT.RTMap(;name = "wokeby",
                   maptype = API.BPF_MAP_TYPE_HASH,
                   keytype = UInt32,
                   valuetype = WokeBy,
                   maxentries = 10000)

const stackmap = RT.RTMap(;name = "stackmap",
                     maptype = API.BPF_MAP_TYPE_STACK_TRACE,
                     keytype = UInt32,
                     valuetype = NTuple{API.PERF_MAX_STACK_DEPTH,UInt64},
                     maxentries = 10000)

# Syscall-specific data
#const 

function real_pid(ctx)
    level = unsafe_load(API.@elemptr(task.nsproxy.pid_ns_for_children.level))
    return unsafe_load(API.@elemptr(task.thread_pid.numbers[level].nr))
end

# kprobe/try_to_wake_up
function waker(ctx)
    task_ptr = API.get_param(ctx, Val(1))
    task_ptr = reinterpret(API.pointertype(API.task_struct), task_ptr)
    woke = RT.ZeroInitRef(WokeBy)

    if (pid = RT.safe_load(task_ptr.pid)) === nothing
        return 0
    end
    #=
    if !(pid in all_pids)
        return 0
    end
    =#

    RT.get_current_comm(RT.SizedBuffer(API.@elemptr(woke.name), TASK_COMM_LEN))
    sid = RT.get_stackid(ctx, stackmap, RT.BPF_F_FAST_STACK_CMP)
    if sid > 0
        unsafe_store!(API.@elemptr(woke.ret), unsafe_trunc(UInt32, sid))
        unsafe_store!(API.@elemptr(woke.pid), unsafe_trunc(UInt32, pid))
    end

    wokeby[pid] = woke[]
    return 0
end

@inline function update_counts(ctx, pid::UInt32, delta::UInt64)
    woke = RT.ZeroInitRef(WokeBy)
    key = RT.ZeroInitRef(Key)

    RT.get_current_comm(RT.SizedBuffer(API.@elemptr(key.target), TASK_COMM_LEN))
    tsid = RT.get_stackid(ctx, stackmap, RT.BPF_F_FAST_STACK_CMP)
    unsafe_store!(API.@elemptr(key.tret), reinterpret(UInt32, tsid))
    unsafe_store!(API.@elemptr(key.wret), 0)
    unsafe_store!(API.@elemptr(key.tpid), pid)
    unsafe_store!(API.@elemptr(key.wpid), 0)

    woke = wokeby[pid]
    if woke !== nothing
        unsafe_store!(API.@elemptr(key.wret), woke.ret)
        #RT.memcpy!(API.@elemptr(key.waker), woke.name, TASK_COMM_LEN)
        unsafe_store!(API.@elemptr(key.waker), woke.name)
        unsafe_store!(API.@elemptr(key.wpid), woke.pid)
        delete!(wokeby, pid)
    end

    GC.@preserve key begin
    _key = Base.unsafe_convert(Ptr{Key}, key)
    val = counts[_key]
    if val == C_NULL
        counts[_key] = 0
        #RT.map_update_elem(counts, _key, _val, UInt64(1)) # TODO: BPF_NOEXIST
        val = counts[_key]
        if val == C_NULL
            return 0
        end
    end
    counts[_key] = unsafe_load(val) + delta
    end
    return 0
end

# taken from /sys/kernel/debug/tracing/events/sched/sched_switch/format
struct sched_switch_args
    pad::UInt64
    prev_comm::NTuple{16,UInt8}
    prev_pid::Cint
    prev_prio::Cint
    prev_state::UInt64
    next_comm::NTuple{16,UInt8}
    next_pid::Cint
    next_prio::Cint
end
# tracepoint/sched/sched_switch
function oncpu(#=struct sched_switch_args *=#ctx::Ptr{sched_switch_args})
    #= record previous thread sleep time =#
    pid = unsafe_load(API.@elemptr(ctx.prev_pid))

    ts = RT.ktime_get_ns()
    start[pid] = ts
    #=
    if pid in all_pids
    end
    =#

    #= calculate current thread's delta time =#
    pid = RT.get_current_pid_tgid()[1]
    tsp = start[pid]
    if (tsp === nothing)
        #= missed start or filtered =#
        return 0
    end

    delta = RT.ktime_get_ns() - tsp
    delete!(start, pid)
    delta = delta ÷ 1000
    if (delta < MINBLOCK_US)
        return 0
    end

    return update_counts(ctx, pid, delta)
end

@info "KProbe"
kp = KProbe(waker, "try_to_wake_up"; license="GPL")
API.load(kp)

@info "Tracepoint"
tp = Tracepoint(oncpu, Tuple{Ptr{sched_switch_args}}, "sched", "sched_switch"; license="GPL", merge_with=[kp.obj])
API.load(tp)

host_counts = Host.hostmap(tp.obj, counts)
host_wokeby = Host.hostmap(tp.obj, wokeby)
host_stacks = Host.hostmap(tp.obj, stackmap)

println("Press enter to exit...")
try
    readline()
catch err
    if !(err isa InterruptException)
        rethrow(err)
    end
end

frames = Tuple{Symbol,UInt64,NTuple{(API.PERF_MAX_STACK_DEPTH*2),UInt64}}[]
proc_names = Dict{Symbol,UInt64}()
for key in keys(host_counts)
    if key.wret != 0 && key.tret != 0
        waker_str = String([key.waker...])
        target_str = String([key.target...])
        waker_sym = Symbol(replace(waker_str, '\0'=>""))
        target_sym = Symbol(replace(target_str, '\0'=>""))
        try
            #waker_addr = get!(()->rand(UInt64), proc_names, waker_sym)
            #target_addr = get!(()->rand(UInt64), proc_names, target_sym)
            waker_stack = host_stacks[key.wret]
            target_stack = host_stacks[key.tret]
            stacks = (reverse(waker_stack)..., target_stack...)
            push!(frames, (target_sym, host_counts[key], stacks))

            #= TODO: Log some extra info
            if occursin("julia", waker_str) || occursin("julia", target_str)
                println("[$waker_str ($(key.wpid)) | $target_str ($(key.tpid)): $(host_counts[key])]")
                println("====WAKER STACK====")
                print(Host.stack_to_string(waker_stack; reverse=true))
                println("===================")
                print(Host.stack_to_string(target_stack))
                println("====TARGET STACK====")
                println()
                if in(key.wpid, all_pids) || in(key.tpid, all_pids)
                    exit()
                end
            end
            =#
        catch err
            @error exception=err
        end
    end
end

API.unload(kp)
API.unload(tp)

@show length(frames)
data, lidict = Host.stack_to_frames(frames)

if out_path !== nothing
    using Serialization
    open(out_path, "w") do io
        serialize(io, (data, lidict))
    end
else
    using PProf, Profile

    pprof(data, lidict)
end
