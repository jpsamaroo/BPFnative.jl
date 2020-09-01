# BPFnative.jl

## Instructions for use
* Recompile Julia's LLVM with the appropriate line in deps/llvm.mk as such:
  `LLVM_TARGETS := host;NVPTX;AMDGPU;BPF`
* `] build LLVM` to rebuild LLVM
* Run `bpfgen(io, license, f, tt)` to generate a BPF kernel with license
  `license`, from function `f` with input types `tt`. The kernel's object file
  (ELF format) will be written to `io`.
* If your kernel is an XDP filter, load it on the appropriate interface with:
  `ip link set dev myiface xdp obj mybpfkernel.o verbose`. `iproute2` will
  output some information on your kernel, which is useful for debugging when
  the Linux kernel refuses to load your kernel (this is common). When you're
  done with that kernel, unload it with `ip link set dev myiface xdp off`.

## Acknowledgments
Thanks to @vchuravy for MCAnalyzer.jl, and @maleadt for CUDAnative.jl, both of
which this package's code is derived from and inspired by! Also thanks to both
of them for bearing with my terribly annoying questions :)
