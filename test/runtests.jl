using BPFnative
#using Test

#=
function g(x)
    return nothing
end

#BPFnative.code_llvm(g, (Int32,))
BPFnative.code_native(g, (Int32,))
=#

function f(x)
    #a = x + 1
    return BPFnative.myextfunc(Int32(2)*x+Int32(1))
end

@info "LLVM for f(x)"
BPFnative.code_llvm(f, (Int32,))
@info "BPF bytecode for f(x)"
BPFnative.code_native(f, (Int32,))
#BPFnative.analyze(f, (Int32,))
