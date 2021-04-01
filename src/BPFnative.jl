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
        @debug "Loading vmlinux..."
        vmlinux_load_time = @timed include("vmlinux.jl")
        @debug "Loaded vmlinux in $(vmlinux_load_time.time) seconds"
        true
    catch err
        @warn "Failed to load/generate Linux Kernel definitions: $err"
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
if has_vmlinux
    import ..CBinding: @c_str, Cptr
    import ..VMLinux
else
    macro c_str(str)
    str
    end
end
include("common.jl")
include("libbpf.jl")
end

# Runtime API
module RT
import ..API
include("runtime_maps.jl")
include("misc.jl")
end

# Host API
module Host
import ..API
include("syscall.jl")
include("host_maps.jl")
end

# Compiler
include("compiler.jl")
include("reflection.jl")

# Easy-to-use probes
include("probes.jl")

# Useful utilities
include("xdp.jl")

end # module
