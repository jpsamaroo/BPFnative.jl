using BPFnative; import BPFnative: RT, API, Host

#=
This example implements a monitor for some of the USDT probes added in
https://github.com/JuliaLang/julia/pull/43453. It monitors task creation,
running, and pausing for the current process.
=#

const MAXTASKS = 128
const child_parent_map = RT.RTMap(;name="child_parent_map", maptype=API.BPF_MAP_TYPE_HASH, keytype=UInt64, valuetype=UInt64, maxentries=MAXTASKS)
const run_map = RT.RTMap(;name="run_map", maptype=API.BPF_MAP_TYPE_HASH, keytype=UInt64, valuetype=Int64, maxentries=MAXTASKS)
const ptls_map = RT.RTMap(;name="ptls_map", maptype=API.BPF_MAP_TYPE_HASH, keytype=UInt64, valuetype=UInt64, maxentries=MAXTASKS)
const state_map = RT.RTMap(;name="state_map", maptype=API.BPF_MAP_TYPE_HASH, keytype=UInt64, valuetype=Int64, maxentries=MAXTASKS)
const process_events_map = RT.RTMap(;name="process_events_map", maptype=API.BPF_MAP_TYPE_ARRAY, keytype=Int32, valuetype=UInt64, maxentries=1)
const gc_state_map = RT.RTMap(;name="gc_state_map", maptype=API.BPF_MAP_TYPE_ARRAY, keytype=Int32, valuetype=Int32, maxentries=1)

new_task = USDT(getpid(), Base.julia_cmd().exec[1], "julia", "rt__new__task"; license="GPL") do ctx
    parent = something(API.get_param(ctx, Val(1)), UInt64(0))
    child = something(API.get_param(ctx, Val(2)), UInt64(0))
    ptls = something(API.get_param(ctx, Val(3)), UInt64(0))
    child_parent_map[child] = parent
    run_map[child] = 0
    ptls_map[child] = ptls
    state_map[child] = 0
    0
end
API.load(new_task)
run_task = USDT(getpid(), Base.julia_cmd().exec[1], "julia", "rt__run__task"; license="GPL", merge_with=[new_task]) do ctx
    task = something(API.get_param(ctx, Val(1)), UInt64(0))
    ptls = something(API.get_param(ctx, Val(2)), UInt64(0))
    old_count = something(run_map[task], 0)
    run_map[task] = old_count + 1
    ptls_map[task] = ptls
    state_map[task] = 1
    0
end
@assert run_task isa BPFnative.ProbeSet
println(run_task)
API.load(run_task)
pause_task = USDT(getpid(), Base.julia_cmd().exec[1], "julia", "rt__pause__task"; license="GPL", merge_with=[new_task]) do ctx
    task = reinterpret(UInt64, API.get_param(ctx, Val(1)))
    ptls = reinterpret(UInt64, API.get_param(ctx, Val(2)))
    ptls_map[task] = ptls
    state_map[task] = 2
    0
end
API.load(pause_task)
start_process_task = USDT(getpid(), Base.julia_cmd().exec[1], "julia", "rt__start__process__events"; license="GPL", merge_with=[new_task]) do ctx
    task = something(API.get_param(ctx, Val(1)), UInt64(0))
    process_events_map[1] = task
    state_map[task] = 3
    0
end
API.load(start_process_task)
finish_process_task = USDT(getpid(), Base.julia_cmd().exec[1], "julia", "rt__finish__process__events"; license="GPL", merge_with=[new_task]) do ctx
    task = something(API.get_param(ctx, Val(1)), UInt64(0))
    state_map[task] = 1
    0
end
API.load(finish_process_task)

#= TODO
multiq_state_task = new_task
for (probe, multiq_state) in [
    ("rt__multiq__insert__success", 1),
    ]
@eval multiq_state_task = USDT(getpid(), Base.julia_cmd().exec[1], "julia", $probe; license="GPL", merge_with=[multiq_state_task]) do ctx
    multiq_state_map[1] = $multiq_state
    0
end
API.load(multiq_state_task)
end
=#

gc_state_task = new_task
for (probe, gc_state) in [
    ("gc__begin", 1),
    ("gc__stop_the_world", 2),
    ("gc__mark__begin", 3),
    ("gc__mark__end", 1),
    ("gc__sweep__begin", 4),
    ("gc__sweep__end", 1),
    ("gc__end", 0),
    ("gc__finalizer", 5)]
    # TODO: Finalizer end?
@eval gc_state_task = USDT(getpid(), Base.julia_cmd().exec[1], "julia", $probe; license="GPL", merge_with=[gc_state_task]) do ctx
    gc_state_map[1] = $gc_state
    0
end
API.load(gc_state_task)
end

host_child_parent_map = Host.hostmap(new_task, child_parent_map)
host_run_map = Host.hostmap(new_task, run_map)
host_ptls_map = Host.hostmap(new_task, ptls_map)
host_state_map = Host.hostmap(new_task, state_map)
host_process_events_map = Host.hostmap(start_process_task, process_events_map)
host_gc_state_map = Host.hostmap(gc_state_task, gc_state_map)

f() = Libc.systemsleep(0.01)
@sync for i in 1:100
    Threads.@spawn f()
end

for task in keys(host_run_map)
    parent = try
        repr(host_child_parent_map[task])
    catch
        "???"
    end
    t = try
        repr(host_run_map[task])
    catch
        "???"
    end
    ptls = try
        repr(host_ptls_map[task])
    catch
        "???"
    end
    state = try
        x = host_state_map[task]
        if x == 0
            "created"
        elseif x == 1
            "running"
        elseif x == 2
            "paused"
        elseif x == 3
            "processing"
        end
    catch
        "???"
    end
    println("Task $task (parent $parent) (PTLS $ptls) (state $state) ran $t times")
end
ptask = host_process_events_map[1]
println("Last task processing events: $ptask")

# TODO: This technically should not work, since tasks are paused during GC
gc_state = host_gc_state_map[1]
if gc_state == 1
    println("GC: Running")
elseif gc_state == 2
    println("GC: Stopping the world")
elseif gc_state == 3
    println("GC: Marking")
elseif gc_state == 4
    println("GC: Sweeping")
elseif gc_state == 5
    println("GC: Running finalizers")
end
