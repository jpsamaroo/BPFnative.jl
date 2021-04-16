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

function GPUCompiler.finish_module!(job::BPFCompilerJob, mod::LLVM.Module)
    #= TODO: Fix upstream and re-enable if needed
    invoke(GPUCompiler.finish_module!,
           Tuple{CompilerJob{BPFCompilerTarget}, LLVM.Module},
           job, mod)
    =#

    for func in LLVM.functions(mod)
        if LLVM.name(func) == "gpu_signal_exception"
            throw(GPUCompiler.KernelError(job, "eBPF does not support exceptions"))
        end
        # Set entry section for loaders like libbpf
        LLVM.section!(func, job.target.prog_section)
    end

    # Set license
    license = job.target.license
    if license != ""
        ctx = LLVM.context(mod)
        i8 = LLVM.Int8Type(ctx)
        glob = GlobalVariable(mod, LLVM.ArrayType(i8, length(license)+1), "_license")
        linkage!(glob, LLVM.API.LLVMExternalLinkage)
        constant!(glob, true)
        section!(glob, "license")
        str = ConstantArray(Vector{UInt8}(license*'\0'), ctx)
        @assert context(glob) == context(str) == ctx
        initializer!(glob, str)
    end

    # Set all map definitions as external linkage
    for gv in filter(x->(section(x)=="maps")||(section(x)==".maps"), collect(LLVM.globals(mod)))
        linkage!(gv, LLVM.API.LLVMExternalLinkage)
    end

    ModulePassManager() do pm
        if Base.JLOptions().debug_level > 1
            # Validate contexts, for my sanity
            add!(pm, ModulePass("BPFValidateContexts", validate_contexts!))
        end
        # Promote `@malloc` intrinsics
        add!(pm, FunctionPass("BPFHeapToStack", heap_to_stack!))
        run!(pm, mod)
    end
end

"Validates LLVM contexts of all the things."
function validate_contexts!(mod::LLVM.Module)
    ctx = LLVM.context(mod)
    for fn in LLVM.functions(mod)
        @assert context(fn) == ctx "Failed validation: $fn"
        for bb in LLVM.blocks(fn)
            for insn in LLVM.instructions(bb)
                @assert context(insn) == ctx "Failed validation: $insn"
                for op in LLVM.operands(insn)
                    @assert context(op) == ctx "Failed validation: $op"
                end
            end
        end
    end
    for gv in LLVM.globals(mod)
        @assert context(gv) == ctx "Failed validation: $gv"
    end
    false
end

"Promotes `@malloc` intrinsics to allocas."
function heap_to_stack!(fn::LLVM.Function)
    changed = false
    ctx = LLVM.context(fn)
    for bb in LLVM.blocks(fn)
        for insn in LLVM.instructions(bb)
            if insn isa LLVM.CallInst && LLVM.name(LLVM.called_value(insn)) == "malloc"
                sz = convert(Int64, LLVM.operands(insn)[1])
                T_i8 = LLVM.Int8Type(ctx)
                T_pi8 = LLVM.PointerType(T_i8)
                T_buf = LLVM.ArrayType(T_i8, sz)
                Builder(ctx) do builder
                    # Place alloca at beginning of entry
                    position!(builder, first(LLVM.instructions(first(LLVM.blocks(fn)))))
                    buf = alloca!(builder, T_buf)
                    # Replace malloc with bitcast'd alloca
                    position!(builder, insn)
                    new_insn = bitcast!(builder, buf, T_pi8)
                    replace_uses!(insn, new_insn)
                    unsafe_delete!(LLVM.parent(insn), insn)
                end
                changed = true
            end
        end
    end
    changed
end
