using CEnum
using CBinding

module LibJulia
    using System
    @sys using libc.POSIX
    using CBinding

    let
        JULIA_DIR=Base.dirname(Base.dirname(Base.julia_cmd().exec[1]))
        println("Reading from $JULIA_DIR/include/julia")
        c`-I $(JULIA_DIR)/include/julia -L$(JULIA_DIR)/lib -L$(JULIA_DIR)/lib/julia -ljulia-internal`
    end
    c"""
        #undef _Atomic
        #define _Atomic(x) x
        #include <julia.h>
    """ij

end

# Make sure these are defined
LibJulia.jl_ptls_t
LibJulia.jl_task_t

using BPFnative; import BPFnative: RT, API, Host

#=
This example implements a monitor for some of the USDT probes added in
https://github.com/JuliaLang/julia/pull/43453. It monitors task creation,
running, pausing, UV loop processing, and sleep/wake transitions for the
current process' threads. It also tracks GC activity, including start/end, mark
and sweep, stop-the-world, and finalizer execution.
=#

const MAXTASKS = 1024
const rb_map = RT.RTMap(;name="rb_map", maptype=API.BPF_MAP_TYPE_PERF_EVENT_ARRAY, keytype=Cint, valuetype=UInt32, maxentries=MAXTASKS)
@cenum RuntimeEventKind begin
    TaskCreated
    TaskRunning
    TaskPaused
    TaskUVLoop
    GCRunning
    GCStopped
    GCWorldStopping
    GCMarking
    GCSweeping
    GCFinalizer
    ThreadWake
    ThreadWakeup
    ThreadSleep
    ThreadTaskQueueWake
    ThreadTaskWake
    ThreadUVWake
end
struct RuntimeEvent
    kind::RuntimeEventKind
    timestamp::UInt64
    arg1::UInt64
    arg2::UInt64
end

function submit_event!(ctx, kind::RuntimeEventKind, arg1=0, arg2=0)
    event_buf = RT.create_buffer(sizeof(RuntimeEvent))
    ts = RT.ktime_get_ns()
    event = RuntimeEvent(kind, ts, arg1, arg2)
    unsafe_store!(reinterpret(Ptr{RuntimeEvent}, pointer(event_buf)), event)
    RT.perf_event_output(ctx, rb_map, 0, event_buf)
end

new_task = USDT(getpid(), Base.julia_cmd().exec[1], "julia", "rt__new__task"; license="GPL") do ctx
    parent = something(API.get_param(ctx, Val(1)), UInt64(0))
    child = something(API.get_param(ctx, Val(2)), UInt64(0))
    submit_event!(ctx, TaskCreated, parent, child)
    0
end
API.load(new_task)
run_task = USDT(getpid(), Base.julia_cmd().exec[1], "julia", "rt__run__task"; license="GPL", merge_with=[new_task]) do ctx
    task = something(API.get_param(ctx, Val(1)), UInt64(0))
    submit_event!(ctx, TaskRunning, task)
    0
end
API.load(run_task)
pause_task = USDT(getpid(), Base.julia_cmd().exec[1], "julia", "rt__pause__task"; license="GPL", merge_with=[new_task]) do ctx
    task = reinterpret(UInt64, API.get_param(ctx, Val(1)))
    submit_event!(ctx, TaskPaused, task)
    0
end
API.load(pause_task)
start_process_task = USDT(getpid(), Base.julia_cmd().exec[1], "julia", "rt__start__process__events"; license="GPL", merge_with=[new_task]) do ctx
    task = something(API.get_param(ctx, Val(1)), UInt64(0))
    submit_event!(ctx, TaskUVLoop, task)
    0
end
API.load(start_process_task)
finish_process_task = USDT(getpid(), Base.julia_cmd().exec[1], "julia", "rt__finish__process__events"; license="GPL", merge_with=[new_task]) do ctx
    task = something(API.get_param(ctx, Val(1)), UInt64(0))
    submit_event!(ctx, TaskRunning, task)
    0
end
API.load(finish_process_task)

gc_state_task = new_task
for (probe, gc_state) in [
    ("gc__begin", GCWorldStopping),
    ("gc__stop_the_world", GCRunning),
    ("gc__mark__begin", GCMarking),
    ("gc__mark__end", GCRunning),
    ("gc__sweep__begin", GCSweeping),
    ("gc__sweep__end", GCRunning),
    ("gc__end", GCStopped),
    ("gc__finalizer", GCFinalizer)]
    # TODO: Finalizer end?
@eval gc_state_task = USDT(getpid(), Base.julia_cmd().exec[1], "julia", $probe; license="GPL", merge_with=[gc_state_task]) do ctx
    submit_event!(ctx, $gc_state)
    0
end
API.load(gc_state_task)
end

thread_state_task = new_task
for (probe, thread_state) in [
    ("rt__sleep__check__wake", ThreadWake), # TODO: Expose old_state arg
    ("rt__sleep__check__wakeup", ThreadWakeup),
    ("rt__sleep__check__sleep", ThreadSleep),
    ("rt__sleep__check__taskq__wake", ThreadTaskQueueWake),
    ("rt__sleep__check__task__wake", ThreadTaskWake),
    ("rt__sleep__check__uv__wake", ThreadUVWake),
    ]
@eval thread_state_task = USDT(getpid(), Base.julia_cmd().exec[1], "julia", $probe; license="GPL", merge_with=[thread_state_task]) do ctx
    ptls = something(API.get_param(ctx, Val(1)), UInt64(0))
    submit_event!(ctx, $thread_state, ptls)
    0
end
API.load(thread_state_task)
end

const ptls_to_tid = Dict{UInt64,Int}()

function sample_cb(ctx::Ptr{Dict{UInt64,Int}}, cpu::Cint, data::Ptr{RuntimeEvent}, size::UInt32)
    ptls_map = unsafe_load(ctx)
    event = unsafe_load(data)
    kind = event.kind

    Core.print("[$(event.timestamp)] (CPU $cpu) ")
    if kind == TaskCreated
        parent = event.arg1
        child = event.arg2
        tid = reinterpret(Cptr{LibJulia.jl_task_t}, parent).tid[]
        Core.println("(TID $tid) Task Created (parent $parent, child $child)")
    elseif kind == TaskRunning
        task = event.arg1
        tid = reinterpret(Cptr{LibJulia.jl_task_t}, task).tid[]
        Core.println("(TID $tid) Task Running (task $task)")
    elseif kind == TaskPaused
        task = event.arg1
        tid = reinterpret(Cptr{LibJulia.jl_task_t}, task).tid[]
        Core.println("(TID $tid) Task Paused (task $task)")
    elseif kind == TaskUVLoop
        task = event.arg1
        tid = reinterpret(Cptr{LibJulia.jl_task_t}, task).tid[]
        Core.println("(TID $tid) Task Running UV loop (task $task)")
    elseif kind == GCStopped
        Core.println("GC: Done")
    elseif kind == GCRunning
        Core.println("GC: Running")
    elseif kind == GCWorldStopping
        Core.println("GC: Stopping the world")
    elseif kind == GCMarking
        Core.println("GC: Marking")
    elseif kind == GCSweeping
        Core.println("GC: Sweeping")
    elseif kind == GCFinalizer
        Core.println("GC: Running finalizers")
    elseif kind == ThreadWake
        ptls = event.arg1
        tid = reinterpret(LibJulia.jl_ptls_t, ptls).tid[]
        Core.println("(TID $tid) Thread Wake")
    elseif kind == ThreadWakeup
        ptls = event.arg1
        tid = reinterpret(LibJulia.jl_ptls_t, ptls).tid[]
        Core.println("(TID $tid) Thread Wakeup")
    elseif kind == ThreadSleep
        ptls = event.arg1
        tid = reinterpret(LibJulia.jl_ptls_t, ptls).tid[]
        Core.println("(TID $tid) Thread Sleep")
    elseif kind == ThreadTaskQueueWake
        ptls = event.arg1
        tid = reinterpret(LibJulia.jl_ptls_t, ptls).tid[]
        Core.println("(TID $tid) Thread Task Queue Wake")
    elseif kind == ThreadTaskWake
        ptls = event.arg1
        tid = reinterpret(LibJulia.jl_ptls_t, ptls).tid[]
        Core.println("(TID $tid) Thread Task Wake")
    elseif kind == ThreadUVWake
        ptls = event.arg1
        tid = reinterpret(LibJulia.jl_ptls_t, ptls).tid[]
        Core.println("(TID $tid) Thread UV Wake")
    end

    return nothing
end
sample_cb_ptr = @cfunction(sample_cb, Cvoid, (Ptr{typeof(ptls_to_tid)}, Cint, Ptr{RuntimeEvent}, UInt32))
function lost_cb(ctx::Ptr, cpu::Cint, lost::UInt32)
    Core.println("(CPU $cpu) LOST $lost ENTRIES")
    ccall(:abort, Cvoid, ())
    nothing
end
lost_cb_ptr = @cfunction(lost_cb, Cvoid, (Ptr{typeof(ptls_to_tid)}, Cint, UInt32))
host_rb_map = Host.PerfBuffer{Cint,UInt32}(API.fd(API.findmap(new_task, "rb_map")), 32; sample_cb=sample_cb_ptr, lost_cb=lost_cb_ptr, ctx=Base.pointer_from_objref(ptls_to_tid))

while true
    ts = [Threads.@spawn sleep(sum(rand(1000))/1000) for i in 1:10]
    Host.poll(host_rb_map, 100)
    wait.(ts)
end
