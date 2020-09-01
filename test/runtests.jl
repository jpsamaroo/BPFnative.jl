using BPFnative
import BPFnative: API
using Test

@testset "libbpf" begin
    function kernel(x)
        mymap = BPFMap("mymap", UInt32(API.BPF_MAP_TYPE_ARRAY), UInt32, UInt32)
        elem = bpf_map_lookup_elem(mymap, UInt32(1))
        return UInt32(0)
    end
    mod = bpffunction(kernel, Tuple{UInt32}; name="mykern", prog_section="mysection", license="MIT")
    obj = BPFnative.bpfobjopen(mod)
    @test length(BPFnative.bpfobjname(obj)) > 0
    @testset "maps" begin
        @test length(BPFnative.bpfmaps(obj)) == 1
        map = BPFnative.bpfmaps(obj)[1]
        @test BPFnative.bpfmapname(map) == "mymap"
        @test BPFnative.bpfmapfd(obj, "mymap") == -1
        @test BPFnative.bpfmapfd(map) == -1
        def = BPFnative.bpfmapdef(map)
        @test def.type == UInt32(API.BPF_MAP_TYPE_ARRAY)
        @test def.key_size == def.value_size == 4
        @test def.max_entries == 1
        @test def.map_flags == 0
        BPFnative.bpfmapresize!(map, 2)
        @test BPFnative.bpfmapdef(map).max_entries == 2
    end
    @testset "programs" begin
        @test length(BPFnative.bpfprogs(obj)) == 1
        prog = BPFnative.bpfprogs(obj)[1]
        @test BPFnative.bpfprogtitle(prog) == "mysection"
        @test occursin("mykern", BPFnative.bpfprogname(prog))
        @test BPFnative.bpfprogtype(prog) == API.BPF_PROG_TYPE_UNSPEC
        BPFnative.bpfprogsetkprobe!(prog)
        @test BPFnative.bpfprogtype(prog) == API.BPF_PROG_TYPE_KPROBE
    end
end
@testset "codegen" begin
    function kernel(x)
        mymap = BPFMap("mymap", UInt32(API.BPF_MAP_TYPE_ARRAY), UInt32, UInt32, 3)
        elem = bpf_map_lookup_elem(mymap, UInt32(1))
        if UInt64(elem) != 0
            elem = unsafe_load(elem)
            if bpf_map_update_elem(mymap, UInt32(1), elem, UInt64(0)) == 0
                if bpf_map_delete_elem(mymap, UInt32(1)) == 0
                    return UInt32(1)
                else
                    return UInt32(2)
                end
            end
        end
        return UInt32(0)
    end
    mod = bpffunction(kernel, Tuple{Int})
    asm = String(bpfemit(mod; asm=true))
    @test occursin("mymap ll", asm)
    @test count("mymap,@object", asm) == 1
end
if homedir() == "/root"
    # Run root-only tests
    # TODO: Perf
    # TODO: XDP
end
