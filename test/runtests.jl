using BPFnative
import BPFnative: API, RT, Host
using Test

# Useful for debugging libbpf loader failures
if !isfile(joinpath(@__DIR__, "bpf-print.so"))
    try
        run(`gcc -shared -fPIC -o bpf-print.so bpf-print.c`)
    catch
        @warn "Failed to build bpf-print.so"
    end
end
using Libdl
try
    libptr = dlopen(joinpath(@__DIR__, "bpf-print.so"))
    fptr = dlsym(libptr, "jl_bpf_print")
    BPFnative.API.bpfprintfn(fptr)
catch
    @warn "Failed to load bpf-print.so, skipping"
end

using InteractiveUtils

@testset "codegen" begin
    map_types = (UInt8, UInt16, UInt32, UInt64,
                 Int8,  Int16,  Int32,  Int64)
    @testset "empty" begin
        function kernel(x)
            return 0
        end
        asm = String(bpffunction(kernel, Tuple{Int}; format=:asm, license="abc"))
        @test occursin(".section\tlicense,", asm)
        @test occursin("_license,@object", asm)
        @test occursin(".asciz\t\"abc\"", asm)
    end
    @testset "map helpers" begin
        function kernel(x)
            mymap = RT.RTMap(;name="mymap", maptype=API.BPF_MAP_TYPE_HASH, keytype=UInt32, valuetype=UInt32, maxentries=3)
            elem = mymap[1]
            if elem !== nothing
                mymap[1] = elem+1
                if something(mymap[1], 0) > 3
                    delete!(mymap, 1)
                end
            else
                mymap[1] = 0
            end
            return 0
        end
        asm = String(bpffunction(kernel, Tuple{Int}; format=:asm))
        @test occursin("mymap ll", asm)
        @test count("mymap,@object", asm) == 1
    end
    @testset "map indexing" begin
        for K in map_types, V in map_types
            @testset "map[$K] = $V" begin
                mymap = RT.RTMap(;name="mymap", maptype=API.BPF_MAP_TYPE_HASH, keytype=K, valuetype=V, maxentries=1)
                oK, oV = one(K), one(V)
                function kernel(x)
                    mymap[oK] = oV
                    return 0
                end
                asm = String(bpffunction(kernel, Tuple{Int}; format=:asm))
                @test occursin("mymap ll", asm)
                @test count("mymap,@object", asm) == 1
            end
        end
    end
    @testset "buffers/strings" begin
        @testset "buffer: simple" begin
            function kernel(x)
                buf = RT.create_buffer(4)
                RT.trace_printk(buf)
            end
            asm = String(bpffunction(kernel, Tuple{Int}; format=:asm))
            @test !occursin("gpu_gc_pool_alloc", asm)
        end
        @testset "string: simple" begin
            function kernel(x)
                str = RT.@create_string("hello!")
                RT.trace_printk(str)
            end
            asm = String(bpffunction(kernel, Tuple{Int}; format=:asm))
            @test !occursin("gpu_gc_pool_alloc", asm)
        end
        @testset "divergent execution" begin
            function kernel(x)
                if x > 1
                    RT.trace_printk(RT.@create_string("Greater"))
                else
                    RT.trace_printk(RT.@create_string("Lesser"))
                end
            end
            asm = String(bpffunction(kernel, Tuple{Int}; format=:asm))
            # TODO: Test that allocas sit in top of first block
        end
    end
end
@testset "libbpf" begin
    function kernel(x)
        mymap = RT.RTMap(;name="mymap", maptype=API.BPF_MAP_TYPE_ARRAY, keytype=UInt32, valuetype=UInt32)
        elem = mymap[1]
        return 0
    end
    exe = bpffunction(kernel, Tuple{UInt32}; name="mykern", prog_section="mysection", license="MIT")
    obj = API.Object(exe)
    @test length(API.name(obj)) > 0
    @testset "maps" begin
        @test length(API.maps(obj)) == 1
        map = API.maps(obj)[1]
        @test API.name(map) == "mymap"
        @test API.fd(obj, "mymap") == -1
        @test API.fd(map) == -1
        def = API.definition(map)
        @test def.type == UInt32(API.BPF_MAP_TYPE_ARRAY)
        @test def.key_size == def.value_size == 4
        @test def.max_entries == 1
        @test def.map_flags == 0
        API.resize!(map, 2)
        @test API.definition(map).max_entries == 2
    end
    @testset "programs" begin
        @test length(API.programs(obj)) == 1
        prog = API.programs(obj)[1]
        @test API.title(prog) == "mysection"
        @test occursin("mykern", API.name(prog))
        @test API.type(prog) == API.BPF_PROG_TYPE_UNSPEC
        API.set_kprobe!(prog)
        @test API.type(prog) == API.BPF_PROG_TYPE_KPROBE
    end
end
run_root_tests = parse(Bool, get(ENV, "BPFNATIVE_ROOT_TESTS", "0"))
if run_root_tests
    @info "Running root-only tests"
    @testset "probes" begin
        @testset "kprobe" begin
            kp = KProbe("ksys_write") do regs
                return 0
            end
            API.load(kp)
            API.unload(kp)
            @testset "retprobe" begin
                kp = KProbe("ksys_write"; retprobe=true) do regs
                    return 0
                end
                API.load(kp)
                API.unload(kp)
            end
        end
        @test_skip "uprobe"
        #= FIXME
        @testset "uprobe" begin
            up = UProbe(+, Tuple{Int,Int}) do regs
                return 0
            end
            API.load(up)
            API.unload(up)
            @testset "retprobe" begin
                up = UProbe(+, Tuple{Int,Int}; retprobe=true) do regs
                    return 0
                end
                API.load(up)
                API.unload(up)
            end
        end
        =#
        @testset "tracepoint" begin
            p = Tracepoint("clk", "clk_enable") do regs
                return 0
            end
            API.load(p)
            API.unload(p)
        end
        # TODO: perf_event
        # TODO: xdp
    end
    @testset "bpf syscall" begin
        @testset "array" begin
            h = Host.HostMap(;map_type=API.BPF_MAP_TYPE_ARRAY, key_type=Int32, value_type=Int64, max_entries=1)
            @test h[1] == 0
            h[1] = 42
            @test h[1] == 42
            @test_throws Exception h[0]
            @test_throws Exception h[2]
        end
        @testset "hash" begin
            h = Host.HostMap(;map_type=API.BPF_MAP_TYPE_HASH, key_type=Int32, value_type=Int64, max_entries=1)
            @test !haskey(h, 1)
            h[1] = 42
            @test haskey(h, 1)
            @test h[1] == 42
            @test_throws Exception h[2] = 43
            @test_throws Exception h[2]
            delete!(h, 1)
            @test !haskey(h, 1)
            h[2] = 43
            @test h[2] == 43
        end
    end
    @testset "map interfacing" begin
        function kp_func(regs)
            mymap = RT.RTMap(;name="mymap", maptype=API.BPF_MAP_TYPE_ARRAY, keytype=UInt32, valuetype=UInt32)
            elem = mymap[1]
            if elem !== nothing
                mymap[1] = 42
            else
                mymap[1] = 1
            end
            return 0
        end
        kp = KProbe(kp_func, "ksys_write")
        API.load(kp) do
            map = first(API.maps(kp.obj))
            hmap = Host.hostmap(map; K=UInt32, V=UInt32)
            run(`sh -c "echo 123 >/dev/null"`)
            @test hmap[1] == 42
        end
    end
    @testset "helpers" begin
        # XXX: The below helper kernels are marked as GPL for the purpose of
        # testing that the helper works as expected, however they are still
        # licensed according to the MIT license. If you actually use GPL-only
        # helpers in your kernels, make sure you adhere to the GPL license!
        @test_skip "probe_read"
        @testset "ktime_get_ns" begin
            kp = KProbe("ksys_write"; license="GPL") do x
                mymap = RT.RTMap(;name="mymap", maptype=API.BPF_MAP_TYPE_ARRAY, keytype=UInt32, valuetype=UInt64)
                mymap[1] = RT.ktime_get_ns()
                0
            end
            API.load(kp) do
                map = first(API.maps(kp.obj))
                hmap = Host.hostmap(map; K=UInt32, V=UInt32)
                run(`sh -c "echo 123 >/dev/null"`)
                old = hmap[1]
                run(`sh -c "echo 123 >/dev/null"`)
                @test hmap[1] > old
            end
        end
        @testset "trace_printk" begin
            kp = KProbe("ksys_write"; license="GPL") do x
                y = 1234
                z = RT.@create_string("1234")
                RT.trace_printk(RT.@create_string("%d==%s"), y, z)
                0
            end
            API.load(kp) do
                run(`sh -c "echo 123 >/dev/null"`)
                run(`grep -q -m 1 '1234==1234' /sys/kernel/debug/tracing/trace_pipe`)
            end
        end
        @testset "get_prandom_u32" begin
            kp = KProbe("ksys_write"; license="GPL") do x
                mymap = RT.RTMap(;name="mymap", maptype=API.BPF_MAP_TYPE_ARRAY, keytype=UInt32, valuetype=UInt32)
                mymap[1] = RT.get_prandom_u32()
                0
            end
            API.load(kp) do
                map = first(API.maps(kp.obj))
                hmap = Host.hostmap(map; K=UInt32, V=UInt32)
                run(`sh -c "echo 123 >/dev/null"`)
                old = hmap[1]
                run(`sh -c "echo 123 >/dev/null"`)
                @test hmap[1] != old
            end
        end
        @testset "get_smp_processor_id" begin
            @eval const CPU_THREADS = Sys.CPU_THREADS # Sys.CPU_THREADS is not const
            kp = KProbe("ksys_write"; license="GPL") do x
                mymap = RT.RTMap(;name="mymap", maptype=API.BPF_MAP_TYPE_ARRAY, keytype=UInt32, valuetype=UInt32, maxentries=CPU_THREADS+1)
                mymap[RT.get_smp_processor_id()+1] = 1
                0
            end
            API.load(kp) do
                map = first(API.maps(kp.obj))
                hmap = Host.hostmap(map; K=UInt32, V=UInt32)
                for i in 1:100
                    run(`sh -c "echo 123 >/dev/null"`)
                end
                for idx in 1:Sys.CPU_THREADS
                    @test hmap[idx] == 1
                end
                @test !haskey(hmap, Sys.CPU_THREADS+1)
            end
        end
    end
end
