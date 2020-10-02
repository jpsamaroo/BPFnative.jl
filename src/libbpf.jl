import .API: BPFProgType

const bpf_object = Ptr{Cvoid}
const bpf_program = Ptr{Cvoid}
const bpf_link = Ptr{Cvoid}

@enum libbpf_print_level begin
    LIBBPF_WARN
    LIBBPF_INFO
    LIBBPF_DEBUG
end

bpfprintfn(fn) = ccall((:libbpf_set_print, :libbpf), Ptr{Cvoid}, (Ptr{Cvoid},), fn)

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

function bpfobjopen(path::String)
    ccall((:bpf_object__open, :libbpf), bpf_object, (Cstring,), path)
end
function bpfobjopen(data::Vector{UInt8}; kwargs...)
    opts = Ref(bpf_object_open_opts(; kwargs...))
    GC.@preserve opts begin
    ccall((:bpf_object__open_mem, :libbpf), bpf_object, (Ptr{UInt8},Csize_t,Ptr{bpf_object_open_opts}), data, length(data), opts)
    end
end
function bpfobjclose(obj::bpf_object)
    ccall((:bpf_object__close, :libbpf), Cvoid, (bpf_object,), obj)
end
function bpfobjkernelversion(obj::bpf_object)
    raw = ccall((:bpf_object__kversion, :libbpf), Cuint, (bpf_object,), obj)
    VersionNumber(raw & (0xFF << 16), raw & (0xFF << 8), raw * 0xFF)
end
function bpfobjname(obj::bpf_object)
    unsafe_string(ccall((:bpf_object__name, :libbpf), Cstring, (bpf_object,), obj))
end
function bpfobjload(obj::bpf_object; log_level=LIBBPF_WARN, target_btf_path=C_NULL)
    opts = Ref(bpf_object_load_attr(obj, Cint(log_level), target_btf_path))
    GC.@preserve opts begin
    ccall((:bpf_object__load_xattr, :libbpf), Cint, (Ptr{bpf_object_load_attr},), opts)
    end
end
function bpfobjunload(obj::bpf_object)
    ccall((:bpf_object__unload, :libbpf), Cint, (bpf_object,), obj)
end

## maps

const bpf_map = Ptr{Cvoid}
struct bpf_map_def
    type::Cuint
    key_size::Cuint
    value_size::Cuint
    max_entries::Cuint
    map_flags::Cuint
end

function bpfmap(obj::bpf_object, name::String)
    map = ccall((:bpf_object__find_map_by_name, :libbpf), bpf_map, (bpf_object,Cstring), obj, name)
    map == C_NULL && error("Map $name not found")
    map
end
function bpfmaps(obj::bpf_object)
    maps = bpf_map[]
    map = C_NULL
    while true
        map = ccall((:bpf_map__next, :libbpf), bpf_map, (bpf_map, bpf_object), map, obj)
        map == C_NULL && break
        push!(maps, map)
    end
    maps
end
function bpfmapname(map::bpf_map)
    unsafe_string(ccall((:bpf_map__name, :libbpf), Cstring, (bpf_map,), map))
end
function bpfmapfd(obj::bpf_object, name::String)
    ccall((:bpf_object__find_map_fd_by_name, :libbpf), Cint, (bpf_object,Cstring), obj, name)
end
function bpfmapfd(map::bpf_map)
    ccall((:bpf_map__fd, :libbpf), Cint, (bpf_map,), map)
end
function bpfmapdef(map::bpf_map)
    unsafe_load(ccall((:bpf_map__def, :libbpf), Ptr{bpf_map_def}, (bpf_map,), map))
end
function bpfmapresize!(map::bpf_map, sz::Integer)
    ccall((:bpf_map__resize, :libbpf), Cint, (bpf_map,UInt32), map, UInt32(sz))
end

## programs

function bpfprogs(obj::bpf_object)
    progs = bpf_program[]
    prog = C_NULL
    while true
        prog = ccall((:bpf_program__next, :libbpf), bpf_program, (bpf_program, bpf_object), prog, obj)
        prog == C_NULL && break
        push!(progs, prog)
    end
    progs
end
function bpfprogload(prog::bpf_program, license::String, kern_version::UInt32)
    ccall((:bpf_program__load, :libbpf), Cint, (bpf_program,Cstring,UInt32), prog, license, kern_version)
end
function bpfprogname(prog::bpf_program)
    unsafe_string(ccall((:bpf_program__name, :libbpf), Cstring, (bpf_program,), prog))
end
function bpfprogtitle(prog::bpf_program, needs_copy::Bool=false)
    unsafe_string(ccall((:bpf_program__title, :libbpf), Cstring, (bpf_program,Bool), prog, needs_copy))
end

# program types

function bpfprogtype(prog::bpf_program)
    BPFProgType(ccall((:bpf_program__get_type, :libbpf), Cint, (bpf_program,), prog))
end
function bpfprogsetxdp!(prog::bpf_program)
    ccall((:bpf_program__set_xdp, :libbpf), Cint, (bpf_program,), prog)
end
function bpfprogsetperfevent!(prog::bpf_program)
    ccall((:bpf_program__set_perf_event, :libbpf), Cint, (bpf_program,), prog)
end
function bpfprogsettracepoint!(prog::bpf_program)
    ccall((:bpf_program__set_tracepoint, :libbpf), Cint, (bpf_program,), prog)
end
function bpfprogsetkprobe!(prog::bpf_program)
    ccall((:bpf_program__set_kprobe, :libbpf), Cint, (bpf_program,), prog)
end

# program attaching

function bpfprogattachtracepoint(prog::bpf_program, category::String, name::String)
    ccall((:bpf_program__attach_tracepoint, :libbpf), bpf_link, (bpf_program, Cstring, Cstring), prog, category, name)
end
function bpfprogattachperfevent(prog::bpf_program, fd::Cint)
    ccall((:bpf_program__attach_perf_event, :libbpf), bpf_link, (bpf_program, Cint), prog, fd)
end
function bpfprogattachkprobe(prog::bpf_program, retprobe::Bool, name::String)
    ccall((:bpf_program__attach_kprobe, :libbpf), bpf_link, (bpf_program, Bool, Cstring), prog, retprobe, name)
end
