export KProbe, UProbe, Tracepoint, PerfEvent, XDP

using Libdl

abstract type AbstractProbe end

struct KProbe <: AbstractProbe
    obj::API.Object
    kfunc::String
    retprobe::Bool
end
function KProbe(f::Function, kfunc; retprobe=false)
    obj = API.Object(bpffunction(f, Tuple{API.pt_regs}; btf=false))
    foreach(prog->API.set_kprobe!(prog), API.programs(obj))
    KProbe(obj, kfunc, retprobe)
end
struct UProbe{F<:Function,T} <: AbstractProbe
    obj::API.Object
    func::F
    sig::T
    retprobe::Bool
end
function UProbe(f::Function, method, sig; retprobe=false)
    obj = API.Object(bpffunction(f, Tuple{API.pt_regs}; btf=false))
    #foreach(prog->API.set_uprobe!(prog), API.programs(obj))
    foreach(prog->API.set_kprobe!(prog), API.programs(obj))
    UProbe(obj, method, sig, retprobe)
end
struct Tracepoint <: AbstractProbe
    obj::API.Object
    category::String
    name::String
end
function Tracepoint(f::Function, category, name)
    obj = API.Object(bpffunction(f, Tuple{API.pt_regs}; btf=false))
    foreach(prog->API.set_tracepoint!(prog), API.programs(obj))
    Tracepoint(obj, category, name)
end

Base.show(io::IO, p::KProbe) =
    print(io, "KProbe ($(p.kfunc)")
Base.show(io::IO, p::UProbe) =
    print(io, "UProbe ($(p.func)($(p.sig)))")
Base.show(io::IO, p::Tracepoint) =
    print(io, "Tracepoint ($(p.category)/$(p.name)")

function API.load(p::KProbe)
    API.load(p.obj)
    foreach(prog->API.attach_kprobe!(prog, p.retprobe, p.kfunc), API.programs(p.obj))
end
function API.load(p::UProbe)
    binpath = "$(Sys.BINDIR)/julia" # FIXME: Detect julia vs julia-debug
    ms = Base.method_instances(p.func, p.sig)
    @assert length(ms) == 1
    faddr = UInt64(ms[1].cache.specptr)
    iaddr = UInt64(dlsym(dlopen(binpath), :_init))
    addr = faddr - (iaddr - 0x1000) # FIXME: This doesn't work
    API.load(p.obj)
    foreach(prog->API.attach_uprobe!(prog, p.retprobe, UInt32(0), binpath, addr), API.programs(p.obj))
end
function API.load(p::Tracepoint)
    API.load(p.obj)
    foreach(prog->API.attach_tracepoint!(prog, p.category, p.name),
            API.programs(p.obj))
end

function API.unload(p::AbstractProbe)
    API.unload(p.obj)
end
