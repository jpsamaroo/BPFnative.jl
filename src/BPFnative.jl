module BPFnative

using LLVM, LLVM.Interop
using InteractiveUtils
using Libdl
using GPUCompiler
using CBinding
using Preferences

# Kernel Internal API
const use_vmlinux = parse(Bool, @load_preference("use_vmlinux", "false"))
if use_vmlinux
    const has_vmlinux = try
        using VMLinuxBindings
        c"VMLinuxBindings.struct pt_regs"
        true
    catch err
        @warn "Failed to load Linux Kernel definitions: $err"
        false
    end
else
    const has_vmlinux = false
end
function enable_vmlinux(ans::Bool=true)
    ans_str = repr(ans)
    if ans_str != repr(use_vmlinux)
        @set_preferences!("use_vmlinux"=>ans_str)
        @info "$(ans ? "Enabled" : "Disabled") loading vmlinux; please restart Julia for changes to take effect"
    end
end

# Common API
module API
if !parse(Bool, get(ENV, "JULIA_BPFNATIVE_DISABLE_ARTIFACTS", "0"))
    using Libbpf_jll
else
    const libbpf = "libbpf"
end
import ..BPFnative: has_vmlinux
import ..CBinding
import ..CBinding: @c_str, Cptr
if has_vmlinux
    import ..VMLinuxBindings
    const VMLinux = VMLinuxBindings
end
include("utils.jl")
include("common.jl")
include("libbpf.jl")
include("libcap.jl")
if Sys.islinux()
include("network.jl")
end
end

# Runtime API
module RT
import ..API
using ..LLVM
using ..LLVM.Interop
import Core: LLVMPtr
import ..CBinding
import ..CBinding: @c_str, Cptr
include("runtime/maps_core.jl")
include("runtime/bpfcall.jl")
include("runtime/maps.jl")
include("runtime/buffers.jl")
include("runtime/helpers.jl")
include("runtime/intrinsics.jl")
include("runtime/constants.jl")
include("runtime/utils.jl")
end

# Host API
module Host
import ..API
include("host/syscall.jl")
include("host/maps.jl")
include("host/socket.jl")
include("host/kallsyms.jl")
end

# Compiler
include("compiler.jl")
include("reflection.jl")

# Easy-to-use probes
include("probes.jl")

# Useful utilities
include("extra.jl")
include("xdp.jl")

end # module
