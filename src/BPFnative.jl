module BPFnative

using LLVM
using LLVM.Interop
using LLVM.API
import CUDAapi: @debug, @trace
using InteractiveUtils

export bpfgen

const optlevel = Ref{Int}()

function __init__()
    # TODO: Do I need this?
    @assert LLVM.InitializeNativeTarget() == false
    InitializeBPFAsmPrinter()
    # TODO: Can we just do -Os due to eBPF limitations?
    optlevel[] = Base.JLOptions().opt_level
end

include("irgen.jl")
include("helpers.jl")

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

include("reflection.jl")

"""
    bpfgen(io, license::String, f, types; optimize! = jloptimize!)

Generates a BPF kernel with the specified license and writes it to `io`.
"""
function bpfgen(io::IO, license::String,
                @nospecialize(func::Core.Function), @nospecialize(types=Tuple);
                optimize!::Core.Function = jloptimize!)
    tt = Base.to_tuple_type(types)
    mod, llvmf = irgen(func, tt)
    obj = target_machine(mod) do tm
        optimize!(tm, mod)
        # FIXME: Add license section to mod
        LLVM.emit(tm, mod, LLVM.API.LLVMObjectFile)
    end
    write(io, obj)
end

end # module
