module BPFnative

using LLVM, LLVM.Interop
using InteractiveUtils
using Libdl
using GPUCompiler

# Host API
module API
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

# Kernel Internal API
module Kernel
try
    include(joinpath(@__DIR__, "..", "gen", "vmlinux.jl"))
catch err
    @warn "Failed to load Linux Kernel definitions: $err"
end
end

# Compiler
include("compiler.jl")
include("reflection.jl")

# Easy-to-use probes
include("probes.jl")

# Useful utilities
include("xdp.jl")

end # module
