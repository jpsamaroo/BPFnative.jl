module BPFnative

using LLVM, LLVM.Interop
using InteractiveUtils
using Libdl
using GPUCompiler

include("c_helpers.jl")
include("libbpf.jl")
include("maps.jl")
include("compiler.jl")
include("execution.jl")
include("reflection.jl")

# Some useful utilities
include("xdp.jl")

end # module
