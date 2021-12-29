export KProbe, USDT, Tracepoint, PerfEvent, XDP

using Libdl
using ObjectFile

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

const NOTE_ARG_TYPE = @NamedTuple{size::Int,
                                  signed::Bool,
                                  reg::Symbol,
                                  offset::Union{Int,Nothing}}
const NOTE_TYPE = @NamedTuple{owner::String,
                              location::UInt64,
                              base::UInt64,
                              semaphore::UInt64,
                              provider::String,
                              func::String,
                              args::Vector{NOTE_ARG_TYPE}}

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
    args::Vector{NOTE_ARG_TYPE}
    retprobe::Bool
end
primitive type USDTContext{P,T1,T2,T3,T4,T5} Sys.WORD_SIZE end
@inline _context_reg(::Val{T}) where T = T
function infer_reg_type(size, signed)
    if size == 1
        signed ? Int8 : UInt8
    elseif size == 2
        signed ? Int16 : UInt16
    elseif size == 4
        signed ? Int32 : UInt32
    elseif size == 8
        signed ? Int64 : UInt64
    else
        NTuple{size,UInt8}
    end
end
@inline function API.get_param(ctx::USDTContext{P,T1,T2,T3,T4,T5}, ::Val{idx}) where {P,T1,T2,T3,T4,T5,idx}
    @assert 1<=idx<=5
    reg = idx == 1 ? T1 :
          idx == 2 ? T2 :
          idx == 3 ? T3 :
          idx == 4 ? T4 : T5
    reg = _context_reg(reg)
    # FIXME: Size
    ptr = reinterpret(P, ctx)
    reg, offset, size, signed = reg
    T = infer_reg_type(size, signed)
    if offset !== nothing
        ptr = unsafe_load(getproperty(ptr, reg))
        ptr = reinterpret(Ptr{T}, ptr) + offset
        dest = Ref{T}()
        GC.@preserve dest begin
            dest_ptr = Base.unsafe_convert(Ptr{T}, dest)
            if RT.probe_read_user(dest_ptr, sizeof(T), ptr) == 0
                return dest[]
            else
                return nothing
            end
        end
    else
        return unsafe_load(reinterpret(Ptr{T}, getproperty(ptr, reg)))
    end
end
function USDT(f::Function, ::Type{T}, pid, binpath, addr::UInt64, args=[]; merge_with=(), retprobe=false, kwargs...) where {T<:Tuple}
    obj = API.Object(bpffunction(f, T; kwargs...))
    for other in merge_with
        merge_maps!(obj, other)
    end
    #foreach(prog->API.set_uprobe!(prog), API.programs(obj))
    foreach(prog->API.set_kprobe!(prog), API.programs(obj))
    USDT(obj, pid, binpath, addr, args, retprobe)
end

"Reads and returns the STAPSDT notes in the binary file `bin`."
function read_notes(bin)
    open(bin) do io
        elf = readmeta(io)
        sec = only(filter(x->section_name(x)==".note.stapsdt",
                          collect(Sections(elf))))
        sec_size = section_size(sec)

        notes = NOTE_TYPE[]
        seek(sec, 0)
        pos = 0
        off = position(io)
        while pos < sec_size
            # Extract fields
            type = read(io, UInt32)
            size = read(io, UInt32)
            _ = read(io, UInt32)
            owner = readuntil(io, '\0')
            location = read(io, UInt64)
            base = read(io, UInt64)
            semaphore = read(io, UInt64)
            provider = readuntil(io, '\0')
            func = readuntil(io, '\0')
            _args = readuntil(io, '\0')

            # Parse arguments
            _args = split(_args, ' ')
            args = NOTE_ARG_TYPE[]
            for arg in _args
                m = match(r"([\-0-9]*)@([\-_0-9a-z]*)\(?%([a-z]*[0-9]*)\)?", arg)
                if m !== nothing
                    sz, offset, reg = m.captures
                    sz = parse(Int, sz)
                    signed = sz < 0
                    sz = abs(sz)
                    reg = Symbol(reg)
                    if offset == ""
                        offset = nothing
                    else
                        offset = try
                            parse(Int, offset)
                        catch
                            0 # TODO: Is this right? This is probably PC-relative?
                        end
                    end
                    push!(args, (;size=sz, signed, reg, offset))
                else
                    @assert isempty(arg) "Failed to parse argument: $arg"
                end
            end

            push!(notes, (;owner, location, base, semaphore, provider, func, args))

            # Seek to next note
            pos += size + sizeof(owner)+1 + (4*3)
            pos = cld(pos, 4) * 4
            seek(io, off+pos)
        end

        notes
    end
end
function USDT(f::Function, pid, binpath, provider::String, func::String; retprobe=false, kwargs...) where {T<:Tuple}
    # FIXME: Find libs without bpftrace
    probes = String(read(`bpftrace -p $pid -l`))
    probe_rgx = Regex("^usdt:/proc/$pid/root(.*):$provider:$func\$")
    for probe in split(probes, '\n')
        startswith(probe, "usdt:") || continue
        if occursin(Regex("$provider:$func\$"), probe)
            m = match(probe_rgx, probe)
            @assert m !== nothing "Unexpected bpftrace probe format"
            probe_file = m.captures[1]
            notes = read_notes(probe_file)
            # TODO: Support multiple hook points
            note = only(filter(x->x.func==func, notes))
            addr = note.location
            args = note.args
            Ts = [Val(length(args) >= i ? (args[i].reg, args[i].offset, args[i].size, args[i].signed) : nothing) for i in 1:5]
            P = API.pointertype(API.cpu_user_regs)
            C = USDTContext{P,Ts...}
            return USDT(f, Tuple{C}, pid, probe_file, addr, args; retprobe, kwargs...)
        end
    end
    throw(ArgumentError("Failed to find $func in $binpath for process $pid"))
end
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
