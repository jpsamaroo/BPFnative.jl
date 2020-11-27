export bpffunction, bpfasm

# Compilation support

struct BPFCompilerParams <: AbstractCompilerParams end

BPFCompilerJob = CompilerJob{BPFCompilerTarget,BPFCompilerParams}

GPUCompiler.runtime_module(::BPFCompilerJob) = BPFnative


## host-side API

"""
    bpffunction(f, tt=Tuple{}; kwargs...)

Compiles a function invocation into eBPF bytecode.

The following keyword arguments are supported:
- `name`: override the name that the kernel will have in the generated code
- `license::String=""`: license for the kernel source code and resulting object
- `prog_section::String=""`: ELF section that the kernel will be placed in
- `btf::Bool=true`: Whether to generate BTF debuginfo or not

The output of this function is automatically cached, i.e. you can simply call
`bpffunction` in a hot path without degrading performance. New code will be
generated automatically when the function changes or when different types or
keyword arguments are provided.
"""
function bpffunction(f::Core.Function, tt::Type=Tuple{}; name=nothing, kwargs...)
    source = FunctionSpec(f, tt, false, name)
    GPUCompiler.cached_compilation(bpffunction_cache,
                                   bpffunction_compile,
                                   bpffunction_link,
                                   source; kwargs...)
end

const bpffunction_cache = Dict{UInt,Any}()

# actual compilation
function bpffunction_compile(source::FunctionSpec; format=:obj, license="",
                             prog_section="prog", btf=true, kwargs...)
    # compile to BPF
    target = BPFCompilerTarget(; license, prog_section)
    params = BPFCompilerParams()
    job = CompilerJob(target, source, params)
    args = GPUCompiler.compile(format, job; validate=true, libraries=false, strip=!btf)
    format == :llvm && return collect.(codeunits.(string.(args))) # TODO: Make more efficient
    return collect(codeunits(args[1]))
end
bpffunction_link(@nospecialize(source::FunctionSpec), exe; kwargs...) = exe
