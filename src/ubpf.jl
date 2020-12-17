export call, verify, load_elf

struct ebpf_inst
    opcode::UInt8
    dst_src::UInt8
    offset::Int16
    imm::Int32
end
const ubpf_jit_fn = Ptr{Cvoid}
const ext_func = Ptr{Cvoid}
Base.@kwdef struct ubpf_vm
    insts::Ptr{ebpf_inst}
    num_insts::UInt16
    jitted::ubpf_jit_fn = C_NULL
    jitted_size::Csize_t = 0
    ext_funcs::Ptr{ext_func} = C_NULL
    ext_func_names::Ptr{Cstring} = C_NULL
    bounds_check_enabled::Bool = true
end
ubpf_vm(exe::Vector{ebpf_inst}; kwargs...) =
    ubpf_vm(pointer(exe), length(exe); kwargs...)
ubpf_vm(exe::Vector{UInt8}; kwargs...) =
    ubpf_vm(reinterpret(Ptr{ebpf_inst}, pointer(exe)),
            div(length(exe),sizeof(ebpf_inst));
            kwargs...)

call(exe::Vector{UInt8}, mem::Vector{UInt8}; kwargs...) =
    call(collect(reinterpret(ebpf_inst, exe)), mem; kwargs...)
function call(exe::Vector{ebpf_inst}, mem::Vector{UInt8}; kwargs...)
    GC.@preserve exe mem begin
        vm = ubpf_vm(exe; kwargs...)
        if verify(vm) == 0
            unsafe_call(vm, mem)
        else
            error("BPF verification failed")
        end
    end
end
function verify(vm::ubpf_vm)
    vm_ref = Ref(vm)
    GC.@preserve vm_ref begin
        ccall((:ubpf_verify, libubpf), Cint, (Ptr{ubpf_vm},), vm_ref)
    end
end
function unsafe_call(vm::ubpf_vm, mem::Union{<:Ptr,<:Integer}, mem_len::Integer)
    vm_ref = Ref(vm)
    mem = sizeof(mem) < sizeof(Ptr{Cvoid}) ? UInt(mem) : mem
    GC.@preserve vm_ref mem begin
        ccall((:ubpf_exec, libubpf), UInt64,
              (Ptr{ubpf_vm}, Ptr{Cvoid}, Csize_t),
              vm_ref, reinterpret(Ptr{Cvoid}, mem), mem_len)
    end
end
function unsafe_call(vm::ubpf_vm, mem::Vector{UInt8})
    vm_ref = Ref(vm)
    GC.@preserve vm_ref mem begin
        ccall((:ubpf_exec, libubpf), UInt64,
              (Ptr{ubpf_vm}, Ptr{Cvoid}, Csize_t),
              vm_ref, mem, length(mem))
    end
end
function load_elf(vm::ubpf_vm, exe::Vector{UInt8})
    vm_ref = Ref(vm)
    errmsg = Ref{Cstring}()
    ret = GC.@preserve vm_ref errmsg begin
        ccall((:ubpf_load_elf, libubpf), Cint,
              (Ptr{ubpf_vm}, Ptr{UInt8}, Csize_t, Ptr{Cstring}),
              vm_ref, pointer(exe), length(exe), errmsg)
    end
    if ret != 0
        error(unsafe_string(errmsg[]))
    end
    vm_ref[]
end
load_elf(path::String) = load_elf(read(path))
