struct BPFCompilerParams <: AbstractCompilerParams end

BPFCompilerJob = CompilerJob{BPFCompilerTarget,BPFCompilerParams}

GPUCompiler.runtime_module(::BPFCompilerJob) = BPFnative
