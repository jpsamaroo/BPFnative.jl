using BPFnative
#using Test

#athing = BPFnative.bpfcall(Val(:bpf_map_update_elem), Int32, Int64(1), Int32(1))
#@show athing
function f(x)
    a = BPFnative.bpfcall(Val(:bpf_map_lookup_elem), Int32, Int64(1), Int32(1))
    return Int32(0)
end

@info "LLVM IR for f(x)"
BPFnative.code_llvm(f, (Int32,))
@info "BPF assembly for f(x)"
BPFnative.code_native(f, (Int32,))
@info "Writing BPF bytecode to kernel.o"
file = open("kernel.o", "w")
bpfgen(file, "", f, (Int32,))
close(file)
