module BPFnative

using LLVM
using LLVM.Interop
import CUDAapi: @debug, @trace
using InteractiveUtils

const optlevel = Ref{Int}()

function __init__()
    # TODO: Do I need this?
    @assert LLVM.InitializeNativeTarget() == false
    # TODO: Should this go elsewhere?
    InitializeBPFAsmPrinter()
    # TODO: Can we just do -Os due to eBPF limitations?
    optlevel[] = Base.JLOptions().opt_level
end

include("irgen.jl")
include("helpers.jl")

"""
    analyze(func, tt, march = :SKL)

Analyze a given function `func` with the type signature `tt`.
The specific method needs to be annotated with the `IACA` markers.
Supported `march` are :HSW, :BDW, :SKL, and :SKX.

# Example

```julia
function mysum(A)
    acc = zero(eltype(A))
    for i in eachindex(A)
        mark_start()
        @inbounds acc += A[i]
    end
    mark_end()
    return acc
end

analyze(mysum, Tuple{Vector{Float64}})
```

# Advanced usage
## Switching opt-level

```julia
MCAnalyzer.optlevel[] = 3
analyze(mysum, Tuple{Vector{Float64}}, :SKL)
```

## Changing the optimization pipeline

```julia
myoptimize!(tm, mod) = ...
analyze(mysum, Tuple{Vector{Float64}}, :SKL, myoptimize!)
```

## Changing the analyzer tool

```julia
MCAnalyzer.analyzer[] = MCAnalyzer.llvm_mca
analyze(mysum, Tuple{Vector{Float64}})
```
"""
function analyze(@nospecialize(func), @nospecialize(tt), optimize!::Core.Function = jloptimize!)
    dir = pwd()
    objfile = joinpath(dir, "a.out")
    asmfile = joinpath(dir, "a.S")
    mod, _ = irgen(func, tt)
    target_machine(mod) do tm
        optimize!(tm, mod)
        LLVM.emit(tm, mod, LLVM.API.LLVMAssemblyFile, asmfile)
        LLVM.emit(tm, mod, LLVM.API.LLVMObjectFile, objfile)
    end
    return nothing
end

nameof(f::Core.Function) = String(typeof(f).name.mt.name)

function target_machine(lambda, mod::LLVM.Module)
    InitializeBPFTarget()
    InitializeBPFTargetInfo()
    triple = LLVM.triple(mod)
    target = LLVM.Target(triple)
    InitializeBPFTargetMC()
    # BPF doesn't have a cpu or features, right?
    LLVM.TargetMachine(lambda, target, triple, "", "")
end

"""
    jloptimize!(tm, mod)

Runs the Julia optimizer pipeline.
"""
function jloptimize!(tm::LLVM.TargetMachine, mod::LLVM.Module)
    ModulePassManager() do pm
        add_library_info!(pm, triple(mod))
        add_transform_info!(pm, tm)
        ccall(:jl_add_optimization_passes, Nothing,
              (LLVM.API.LLVMPassManagerRef, Cint),
               LLVM.ref(pm), optlevel[])
        run!(pm, mod)
    end
end

#= TODO: Use this to call kernel functions?
"""
    mark_start()

Insert `iaca` and `llvm-mca` start markers at this position.
"""
function mark_start()
    @asmcall("""
    movl \$\$111, %ebx
    .byte 0x64, 0x67, 0x90
    # LLVM-MCA-BEGIN
    """, "~{memory},~{ebx}", true)
end
=#

include("reflection.jl")

end # module
