# BPFnative.jl

BPFnative provides the ability to write eBPF filters in Julia. Additionally,
wrappers to the [libbpf](https://github.com/libbpf/libbpf) library are provided
to make it easy to load eBPF programs into the Linux kernel in for a variety of
use cases.

## Acknowledgments
Thanks to @vchuravy for MCAnalyzer.jl, and @maleadt for CUDAnative.jl, both of
which this package's code is derived from and inspired by! Also thanks to both
of them for bearing with my terribly annoying questions :)
