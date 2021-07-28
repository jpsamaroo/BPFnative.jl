export KProbe, UProbe, USDT, Tracepoint, PerfEvent, XDP

using Libdl

abstract type AbstractProbe end

struct KProbe <: AbstractProbe
    obj::API.Object
    kfunc::String
    retprobe::Bool
end
function KProbe(f::Function, kfunc; retprobe=false, kwargs...)
    obj = API.Object(bpffunction(f, Tuple{API.pointertype(API.pt_regs)}; kwargs...))
    foreach(prog->API.set_kprobe!(prog), API.programs(obj))
    KProbe(obj, kfunc, retprobe)
end
struct UProbe#={F<:Function,T}=# <: AbstractProbe
    obj::API.Object
    pid::UInt32
    binpath::String
    addr::UInt64
    #=
    func::F
    sig::T
    =#
    retprobe::Bool
end
#=
function UProbe(f::Function, method, sig; retprobe=false, kwargs...)
    obj = API.Object(bpffunction(f, Tuple{API.pointertype(API.pt_regs)}; kwargs...))
    #foreach(prog->API.set_uprobe!(prog), API.programs(obj))
    foreach(prog->API.set_kprobe!(prog), API.programs(obj))
    UProbe(obj, method, sig, retprobe)
end
=#
function UProbe(f::Function, binpath, addr; pid=0, retprobe=false, kwargs...)
    obj = API.Object(bpffunction(f, Tuple{API.pointertype(API.pt_regs)}; kwargs...))
    #foreach(prog->API.set_uprobe!(prog), API.programs(obj))
    foreach(prog->API.set_kprobe!(prog), API.programs(obj))
    UProbe(obj, pid, binpath, addr, retprobe)
end
struct USDT <: AbstractProbe
    obj::API.Object
    pid::UInt32
    binpath::String
    addr::UInt64
    retprobe::Bool
end
function USDT(f::Function, pid, binpath, addr::UInt64; retprobe=false, kwargs...)
    obj = API.Object(bpffunction(f, Tuple{API.pointertype(API.pt_regs)}; kwargs...))
    #foreach(prog->API.set_uprobe!(prog), API.programs(obj))
    foreach(prog->API.set_kprobe!(prog), API.programs(obj))
    USDT(obj, pid, binpath, addr, retprobe)
end
function USDT(f::Function, pid, binpath, func::String; retprobe=false, kwargs...)
    probes = String(read(`bpftrace -p $pid -l`))
    probe_rgx = Regex("^usdt:/proc/$pid/root(.*):$func\$")
    note_rgx = r"Location: ([0-9a-fx]*),"
    for probe in split(probes, '\n')
        startswith(probe, "usdt:") || continue
        if occursin(Regex("$func\$"), probe)
            m = match(probe_rgx, probe)
            @assert m !== nothing "Unexpected bpftrace probe format"
            probe_file = m.captures[1]
            notes = String(read(`readelf -n $probe_file`))
            for line in split(notes, '\n')
                m = match(note_rgx, line)
                if m !== nothing
                    addr = parse(UInt64, m.captures[1])
                    return USDT(f, pid, probe_file, addr; retprobe, kwargs...)
                end
            end
            throw(ArgumentError("Failed to find STAPSDT location in $probe_file"))
        end
    end
    throw(ArgumentError("Failed to find $func in $binpath for process $pid"))
end
struct Tracepoint <: AbstractProbe
    obj::API.Object
    category::String
    name::String
end
function Tracepoint(f::Function, category, name; kwargs...)
    obj = API.Object(bpffunction(f, Tuple{API.pointertype(API.pt_regs)}; kwargs...))
    foreach(prog->API.set_tracepoint!(prog), API.programs(obj))
    Tracepoint(obj, category, name)
end

Base.show(io::IO, p::KProbe) =
    print(io, "KProbe ($(p.kfunc))")
Base.show(io::IO, p::UProbe) =
    print(io, "UProbe ($(p.addr) @ $(repr(p.binpath)))")
Base.show(io::IO, p::USDT) =
    print(io, "USDT (path $(p.binpath), pid $(p.pid))")
Base.show(io::IO, p::Tracepoint) =
    print(io, "Tracepoint ($(p.category)/$(p.name))")

function API.load(p::KProbe)
    API.load(p.obj)
    foreach(prog->API.attach_kprobe!(prog, p.retprobe, p.kfunc), API.programs(p.obj))
end
function API.load(p::UProbe)
    #=
    binpath = "$(Sys.BINDIR)/julia" # FIXME: Detect julia vs julia-debug
    ms = Base.method_instances(p.func, p.sig)
    @assert length(ms) == 1
    faddr = UInt64(ms[1].cache.specptr)
    iaddr = UInt64(dlsym(dlopen(binpath), :_init))
    addr = faddr - (iaddr - 0x1000) # FIXME: This doesn't work
    API.load(p.obj)
    foreach(prog->API.attach_uprobe!(prog, p.retprobe, UInt32(0), binpath, addr), API.programs(p.obj))
    =#
    API.load(p.obj)
    foreach(prog->API.attach_uprobe!(prog, p.retprobe, p.pid, p.binpath, p.addr), API.programs(p.obj))
end
function API.load(p::USDT)
    API.load(p.obj)
    foreach(prog->API.attach_uprobe!(prog, p.retprobe, p.pid, p.binpath, p.addr),
            API.programs(p.obj))
end
function API.load(p::Tracepoint)
    API.load(p.obj)
    foreach(prog->API.attach_tracepoint!(prog, p.category, p.name),
            API.programs(p.obj))
end

function API.unload(p::AbstractProbe)
    API.unload(p.obj)
end
