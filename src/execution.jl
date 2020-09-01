# Native execution support

export @bpf, bpfconvert, bpffunction, bpfemit

struct BPFModule
    mod::LLVM.Module
    entry::String
end


## host-side API

"""
    bpffunction(f, tt=Tuple{}; kwargs...)

Compiles a function invocation into BPF.

The following keyword arguments are supported:
- `name`: override the name that the kernel will have in the generated code
- `license`: license for

The output of this function is automatically cached, i.e. you can simply call `bpffunction`
in a hot path without degrading performance. New code will be generated automatically, when
when function changes, or when different types or keyword arguments are provided.
"""
function bpffunction(f::Core.Function, tt::Type=Tuple{}; name=nothing, kwargs...)
    source = FunctionSpec(f, tt, false, name)
    GPUCompiler.cached_compilation(_bpffunction, source; kwargs...)::BPFModule
end

# actual compilation
function _bpffunction(source::FunctionSpec; license="", prog_section="prog", kwargs...)
    # compile to BPF
    target = BPFCompilerTarget(;kwargs...)
    params = BPFCompilerParams()
    job = CompilerJob(target, source, params)
    obj, entry = GPUCompiler.compile(:llvm, job; libraries=false)
    entry_name = LLVM.name(entry)
    triple!(obj, "bpf")

    # mark entry as a valid eBPF program
    LLVM.section!(entry, prog_section)

    # FIXME: don't create a dummy function
    #glob = GlobalVariable(obj, convert(LLVMType, Int8), "_license")
    #initializer!(glob, LLVM.API.LLVMConstString(license, UInt32(length(license)), Int32(0)))
    f = JuliaContext() do ctx
        f = LLVM.Function(obj, "license_func", LLVM.FunctionType(LLVM.VoidType(ctx)))
        Builder(ctx) do builder
            entry = BasicBlock(f, "entry", ctx)
            position!(builder, entry)
            glob = globalstring!(builder, license, "_license")
            constant!(glob, true)
            LLVM.section!(glob, "license")
            ret!(builder)
        end
        f
    end
    unsafe_delete!(obj, f)

    # set all maps as external linkage
    for gv in filter(x->section(x)=="maps", collect(LLVM.globals(obj)))
        linkage!(gv, LLVM.API.LLVMExternalLinkage)
    end

    BPFModule(obj, entry_name)
end
function bpfemit(mod::BPFModule; asm=false)
    # emit and compile binary
    # TODO: compile without using llc
    toolsdir = joinpath(Sys.BINDIR, "..", "tools")
    format = asm ? :asm : :obj
    mktemp() do cpath, cio
        mktemp() do lpath, lio
            write(lio, mod.mod)
            flush(lio)
            run(`$(joinpath(toolsdir, "llc")) -march=bpfel --filetype=$format -o $cpath $lpath`)
        end
        read(cpath)
    end
end
bpfobjopen(mod::BPFModule) = bpfobjopen(bpfemit(mod))
