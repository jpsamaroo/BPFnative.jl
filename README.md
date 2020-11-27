# BPFnative.jl

BPFnative provides the ability to write eBPF filters in Julia. Additionally,
wrappers to the [libbpf](https://github.com/libbpf/libbpf) library are provided
to make it easy to load eBPF programs into the Linux kernel in for a variety of
use cases.

## Filter Licensing

Disclaimer: I am not a lawyer, so the following information may be completely
incorrect. If you are a lawyer or have equivalent experience, and believe the
following information to be misleading or incorrect, please file an issue/PR.

Because the Linux kernel exposes BPF helpers functions which are only
available to GPL-licensed programs, BPFnative provides the option to allow BPF
kernels to be generated under the GPL license, or whatever license is
provided to `bpffunction()`. The subsequently generated kernel and
source that generates it would then be considered to be licensed as
specified. The default license is the empty string "", which may be construed
to imply a lack of a license (proprietary).

BPFnative itself is of course just a compiler, so it may retain its MIT
license. However, users should keep in mind that whatever license they specify
to `bpffunction()` is the license that they must adhere to. This means
that, for example, if a user were to generate a GPL-licensed BPF kernel with
BPFnative's compiler, the user would be obligated to adhere to the terms of
the GPL license, and specifically, would be required to provide the source
code used to generate their BPF kernel, as well as distributing a copy or
reference to the GPL license itself.

## Acknowledgments
Thanks to @vchuravy for MCAnalyzer.jl, and @maleadt for CUDAnative.jl, both of
which this package's code is derived from and inspired by! Also thanks to both
of them for bearing with my terribly annoying questions :)
