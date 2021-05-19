import .API: BPFProgType

const bpf_object = Ptr{Cvoid}
struct Object
    obj::bpf_object
end
const bpf_program = Ptr{Cvoid}
struct Program
    prog::bpf_program
end
const bpf_link = Ptr{Cvoid}
struct Link
    link::bpf_link
end
const bpf_map = Ptr{Cvoid}
struct Map
    map::bpf_map
end
const perf_buffer = Ptr{Cvoid}
struct PerfBuffer
    buf::perf_buffer
end

@enum libbpf_print_level begin
    LIBBPF_WARN
    LIBBPF_INFO
    LIBBPF_DEBUG
end

bpfprintfn(fn) = ccall((:libbpf_set_print, libbpf), Ptr{Cvoid}, (Ptr{Cvoid},), fn)

Base.@kwdef struct bpf_object_open_opts
    sz::Csize_t = sizeof(bpf_object_open_opts)
    object_name::Cstring = C_NULL
    relaxed_maps::Bool = false
    relaxed_core_relocs::Bool = false
    pin_root_path::Cstring = C_NULL
    attach_prog_fd::UInt32 = 0
    kconfig::Cstring = C_NULL
end

struct bpf_object_load_attr
    obj::bpf_object
    log_level::Cint
    target_btf_path::Cstring
end

function Object(path::String)
    obj = ccall((:bpf_object__open, libbpf), bpf_object, (Cstring,), path)
    @assert Int(obj) > 0
    Object(obj)
end
function Object(data::Vector{UInt8}; kwargs...)
    opts = Ref(bpf_object_open_opts(; kwargs...))
    obj = GC.@preserve opts begin
    ccall((:bpf_object__open_mem, libbpf), bpf_object, (Ptr{UInt8},Csize_t,Ptr{bpf_object_open_opts}), data, length(data), opts)
    end
    @assert Int(obj) > 0
    Object(obj)
end
function Base.close(obj::Object)
    ccall((:bpf_object__close, libbpf), Cvoid, (bpf_object,), obj[])
    nothing
end
function kernel_version(obj::Object)
    raw = ccall((:bpf_object__kversion, libbpf), Cuint, (bpf_object,), obj[])
    VersionNumber(raw & (0xFF << 16), raw & (0xFF << 8), raw * 0xFF)
end
function name(obj::Object)
    name = ccall((:bpf_object__name, libbpf), Cstring, (bpf_object,), obj[])
    @assert Int(pointer(name)) > 0
    unsafe_string(name)
end
function load(obj::Object; log_level=LIBBPF_WARN, target_btf_path=C_NULL)
    opts = Ref(bpf_object_load_attr(obj[], Cint(log_level), target_btf_path))
    res = GC.@preserve opts begin
    ccall((:bpf_object__load_xattr, libbpf), Cint, (Ptr{bpf_object_load_attr},), opts)
    end
    @assert res == 0
    nothing
end
function unload(obj::Object)
    res = ccall((:bpf_object__unload, libbpf), Cint, (bpf_object,), obj[])
    @assert res == 0
    nothing
end

## maps

struct MapDef
    type::Cuint
    key_size::Cuint
    value_size::Cuint
    max_entries::Cuint
    map_flags::Cuint
end

function findmap(obj::Object, name::String)
    map = ccall((:bpf_object__find_map_by_name, libbpf), bpf_map, (bpf_object,Cstring), obj[], name)
    map == C_NULL && error("Map $name not found")
    @assert Int(map) > 0
    Map(map)
end
function maps(obj::Object)
    maps = Map[]
    map = C_NULL
    while true
        map = ccall((:bpf_map__next, libbpf), bpf_map, (bpf_map, bpf_object), map, obj[])
        map == C_NULL && break
        push!(maps, Map(map))
    end
    maps
end
function name(map::Map)
    name = ccall((:bpf_map__name, libbpf), Cstring, (bpf_map,), map[])
    @assert Int(pointer(name)) > 0
    unsafe_string(name)
end
function fd(obj::Object, name::String)
    fd = ccall((:bpf_object__find_map_fd_by_name, libbpf), Cint, (bpf_object,Cstring), obj[], name)
    @assert fd != 0
    fd
end
function fd(map::Map)
    fd = ccall((:bpf_map__fd, libbpf), Cint, (bpf_map,), map[])
    @assert fd != 0
    fd
end
function definition(map::Map)
    def = ccall((:bpf_map__def, libbpf), Ptr{MapDef}, (bpf_map,), map[])
    @assert Int(def) > 0
    unsafe_load(def)
end
function resize!(map::Map, sz::Integer)
    ret = ccall((:bpf_map__resize, libbpf), Cint, (bpf_map,UInt32), map[], UInt32(sz))
    @assert ret == 0
    nothing
end
function reuse_fd(map::Map, fd::Integer)
    ret = ccall((:bpf_map_reuse_fd, libbpf), Cint, (bpf_map,Cint), map[], Cint(fd))
    @assert ret == 0
    nothing
end

## programs

function programs(obj::Object)
    progs = Program[]
    prog = C_NULL
    while true
        prog = ccall((:bpf_program__next, libbpf), bpf_program, (bpf_program, bpf_object), prog, obj[])
        prog == C_NULL && break
        push!(progs, Program(prog))
    end
    progs
end
function load(prog::Program, license::String, kern_version::UInt32)
    ret = ccall((:bpf_program__load, libbpf), Cint, (bpf_program,Cstring,UInt32), prog[], license, kern_version)
    @assert ret == 0
    nothing
end
function name(prog::Program)
    name = ccall((:bpf_program__name, libbpf), Cstring, (bpf_program,), prog[])
    @assert reinterpret(Int, name) > 0
    unsafe_string(name)
end
function title(prog::Program, needs_copy::Bool=false)
    title = ccall((:bpf_program__title, libbpf), Cstring, (bpf_program,Bool), prog[], needs_copy)
    @assert reinterpret(Int, title) > 0
    unsafe_string(title)
end
function fd(prog::Program)
    ccall((:bpf_program__fd, libbpf), Cint, (bpf_program,), prog[])
end

# program types

function type(prog::Program)
    BPFProgType(ccall((:bpf_program__get_type, libbpf), Cint, (bpf_program,), prog[]))
end
function set_socket_filter!(prog::Program)
    @assert ccall((:bpf_program__set_socket_filter, libbpf), Cint, (bpf_program,), prog[]) == 0;
end
function set_xdp!(prog::Program)
    @assert ccall((:bpf_program__set_xdp, libbpf), Cint, (bpf_program,), prog[]) == 0;
end
function set_perf_event!(prog::Program)
    @assert ccall((:bpf_program__set_perf_event, libbpf), Cint, (bpf_program,), prog[]) == 0;
end
function set_tracepoint!(prog::Program)
    @assert ccall((:bpf_program__set_tracepoint, libbpf), Cint, (bpf_program,), prog[]) == 0;
end
function set_kprobe!(prog::Program)
    @assert ccall((:bpf_program__set_kprobe, libbpf), Cint, (bpf_program,), prog[]) == 0;
end

# program attaching

function attach_perf_event!(prog::Program, fd::Cint)
    link = ccall((:bpf_program__attach_perf_event, libbpf), bpf_link, (bpf_program, Cint), prog[], fd)
    @assert Int(link) > 0
    Link(link)
end
function attach_kprobe!(prog::Program, retprobe::Bool, name::String)
    link = ccall((:bpf_program__attach_kprobe, libbpf), bpf_link, (bpf_program, Bool, Cstring), prog[], retprobe, name)
    @assert Int(link) > 0
    Link(link)
end
function attach_uprobe!(prog::Program, retprobe::Bool, pid::Cuint, name::String, func_offset::Csize_t)
    link = ccall((:bpf_program__attach_uprobe, libbpf), bpf_link, (bpf_program, Bool, Cuint, Cstring, Csize_t), prog[], retprobe, pid, name, func_offset)
    @assert Int(link) > 0
    Link(link)
end
function attach_tracepoint!(prog::Program, category::String, name::String)
    link = ccall((:bpf_program__attach_tracepoint, libbpf), bpf_link, (bpf_program, Cstring, Cstring), prog[], category, name)
    @assert Int(link) > 0
    Link(link)
end

# perf buffers

Base.@kwdef struct perf_buffer_opts
    sample_cb::Ptr{Cvoid} = C_NULL
    lost_cb::Ptr{Cvoid} = C_NULL
    ctx::Ptr{Cvoid} = C_NULL
end

function PerfBuffer(map_fd::Cint, page_cnt::Integer, opts::perf_buffer_opts=perf_buffer_opts())
    opts_ref = Ref{perf_buffer_opts}(opts)
    buf = GC.@preserve opts_ref begin
        opts_ptr = Base.unsafe_convert(Ptr{perf_buffer_opts}, opts_ref)
        ccall((:perf_buffer__new, libbpf), perf_buffer, (Cint,Csize_t,Ptr{perf_buffer_opts}), map_fd, Csize_t(page_cnt), opts_ptr)
    end
    @assert Int(buf) > 0
    PerfBuffer(buf)
end
function poll(buf::PerfBuffer, timeout_ms::Integer)
    ccall((:perf_buffer__poll, libbpf), Cint, (perf_buffer,Cint), buf[], Cint(timeout_ms))
end

## user-facing API

for (T,field) in ((Object,:obj), (Program,:prog), (Map,:map), (Link,:link))
    #= TODO
    @eval @inline Base.getproperty(x::$T, sym::Symbol) =
                      Base.getproperty(x, Val(sym))
    @eval @inline Base.setproperty!(x::$T, val, sym::Symbol) =
                      Base.setproperty!(x, val, Val(sym))
    =#
    @eval @inline Base.getindex(x::$T) = x.$field
end

function load(f, x)
    load(x)
    try
        f()
    finally
        unload(x)
    end
end
