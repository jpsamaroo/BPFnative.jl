export KProbe, USDT, Tracepoint, PerfEvent, XDP

using Libdl

abstract type AbstractProbe end

"Merges maps from `other` into `obj`."
function merge_maps!(obj, other)
    for other_map in API.maps(other)
        for our_map in API.maps(obj)
            if API.name(our_map) == API.name(other_map)
                API.reuse_fd(our_map, API.fd(other_map))
            end
        end
    end
end

struct KProbe <: AbstractProbe
    obj::API.Object
    kfunc::String
    retprobe::Bool
end
function KProbe(f::Function, ::Type{T}, kfunc; merge_with=(), retprobe=false, kwargs...) where {T<:Tuple}
    obj = API.Object(bpffunction(f, T; kwargs...))
    foreach(prog->API.set_kprobe!(prog), API.programs(obj))
    for other in merge_with
        merge_maps!(obj, other)
    end
    KProbe(obj, kfunc, retprobe)
end
KProbe(f::Function, kfunc; kwargs...) =
    KProbe(f, Tuple{API.pointertype(API.pt_regs)}, kfunc; kwargs...)
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
function UProbe(f::Function, ::Type{T}, method, sig; merge_with=(), retprobe=false, kwargs...) where {T<:Tuple}
    obj = API.Object(bpffunction(f, T; kwargs...))
    #foreach(prog->API.set_uprobe!(prog), API.programs(obj))
    foreach(prog->API.set_kprobe!(prog), API.programs(obj))
    for other in merge_with
        merge_maps!(obj, other)
    end
    UProbe(obj, method, sig, retprobe)
end
UProbe(f::Function, method, sig; kwargs...) =
    UProbe(f, Tuple{API.pointertype(API.pt_regs)}, method, sig; kwargs...)
function UProbe(f::Function, binpath, addr; pid=0, retprobe=false, kwargs...)
    obj = API.Object(bpffunction(f, Tuple{API.pointertype(API.pt_regs)}; kwargs...))
    #foreach(prog->API.set_uprobe!(prog), API.programs(obj))
    foreach(prog->API.set_kprobe!(prog), API.programs(obj))
    UProbe(obj, pid, binpath, addr, retprobe)
end
=#
struct USDT <: AbstractProbe
    obj::API.Object
    pid::UInt32
    binpath::String
    addr::UInt64
    retprobe::Bool
end
function USDT(f::Function, ::Type{T}, pid, binpath, addr::UInt64; merge_with=(), retprobe=false, kwargs...) where {T<:Tuple}
    obj = API.Object(bpffunction(f, T; kwargs...))
    for other in merge_with
        merge_maps!(obj, other)
    end
    #foreach(prog->API.set_uprobe!(prog), API.programs(obj))
    foreach(prog->API.set_kprobe!(prog), API.programs(obj))
    USDT(obj, pid, binpath, addr, retprobe)
end
function USDT(f::Function, ::Type{T}, pid, binpath, func::String; retprobe=false, kwargs...) where {T<:Tuple}
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
                    return USDT(f, T, pid, probe_file, addr; retprobe, kwargs...)
                end
            end
            throw(ArgumentError("Failed to find STAPSDT location in $probe_file"))
        end
    end
    throw(ArgumentError("Failed to find $func in $binpath for process $pid"))
end
USDT(f::Function, pid, binpath, func::String; kwargs...) =
    USDT(f, Tuple{API.pointertype(API.pt_regs)}, pid, binpath, func; kwargs...)
struct Tracepoint <: AbstractProbe
    obj::API.Object
    category::String
    name::String
end
function Tracepoint(f::Function, ::Type{T}, category, name; merge_with=(), kwargs...) where {T<:Tuple}
    obj = API.Object(bpffunction(f, T; kwargs...))
    foreach(prog->API.set_tracepoint!(prog), API.programs(obj))
    for other in merge_with
        merge_maps!(obj, other)
    end
    Tracepoint(obj, category, name)
end
Tracepoint(f::Function, category, name; kwargs...) =
    Tracepoint(f, Tuple{API.pointertype(API.pt_regs)}, category, name; kwargs...)

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
#=
function API.load(p::UProbe)
    binpath = "$(Sys.BINDIR)/julia" # FIXME: Detect julia vs julia-debug
    ms = Base.method_instances(p.func, p.sig)
    @assert length(ms) == 1
    faddr = UInt64(ms[1].cache.specptr)
    iaddr = UInt64(dlsym(dlopen(binpath), :_init))
    addr = faddr - (iaddr - 0x1000) # FIXME: This doesn't work
    API.load(p.obj)
    foreach(prog->API.attach_uprobe!(prog, p.retprobe, UInt32(0), binpath, addr), API.programs(p.obj))
    API.load(p.obj)
    foreach(prog->API.attach_uprobe!(prog, p.retprobe, p.pid, p.binpath, p.addr), API.programs(p.obj))
end
=#
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
