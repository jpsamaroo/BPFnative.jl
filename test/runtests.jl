using BPFnative
import BPFnative: API, RT, Host
using Sockets
using Test
using UProbes

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
                k = @eval begin
                    function kernel(x)
                        mymap = RT.RTMap(;name="mymap", maptype=API.BPF_MAP_TYPE_HASH, keytype=$K, valuetype=$V, maxentries=1)
                        oK, oV = $(one(K)), $(one(V))
                        mymap[oK] = oV
                        return 0
                    end
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
@testset "sockets" begin
    srv = listen(4789)
    chan = Channel{Int}()
    function open_socks(srv, port)
        s_sock = @async accept(srv)
        c_sock = connect(port)
        s_sock = fetch(s_sock)
        s_sock, c_sock
    end
    @testset "attach" begin
        s_sock, c_sock = open_socks(srv, 4789)
        write(s_sock, 1)
        @test read(c_sock, Int) == 1
        dummy_filter(ctx) = 64
        bytecode = bpffunction(dummy_filter, Tuple{Ptr{Cvoid}}; btf=false, prog_section="socket_filter")
        obj = API.Object(bytecode)
        API.load(obj)
        filt = API.fd(first(API.programs(obj)))
        @test Host.setsockopt(c_sock, Host.SOL_SOCKET, Host.SO_ATTACH_BPF, filt) == 0
        @test Host.getsockopt(c_sock, Host.SOL_SOCKET, Host.SO_PROTOCOL, UInt64) == API.Network.IPPROTO_TCP
        write(s_sock, 1)
        @test read(c_sock, Int) == 1
        @test Host.setsockopt(c_sock, Host.SOL_SOCKET, Host.SO_DETACH_BPF, filt) == 0
        close(s_sock)
        close(c_sock)
    end
    @testset "packet counting" begin
        s_sock, c_sock = open_socks(srv, 4789)
        function count_filter(ctx)
            mymap = RT.RTMap(name="mymap", maptype=API.BPF_MAP_TYPE_ARRAY, keytype=Int32, valuetype=UInt8, maxentries=1)
            mymap[1] = something(mymap[1], 0) + 1
            255
        end
        bytecode = bpffunction(count_filter, Tuple{Ptr{Cvoid}}; btf=false, prog_section="socket_filter")
        obj = API.Object(bytecode)
        API.load(obj)
        filt = API.fd(first(API.programs(obj)))
        Host.setsockopt(c_sock, Host.SOL_SOCKET, Host.SO_ATTACH_BPF, filt)
        write(s_sock, 1)
        read(c_sock, UInt8)
        hmap = Host.hostmap(first(API.maps(obj)); K=Int32, V=UInt8)
        @test hmap[1] > 0
        close(s_sock)
        close(c_sock)
    end
    @testset "packet reading" begin
        s_sock, c_sock = open_socks(srv, 4789)
        function modify_filter(ctx)
            mymap = RT.RTMap(name="mymap", maptype=API.BPF_MAP_TYPE_ARRAY, keytype=Int32, valuetype=UInt8, maxentries=1)
            doff = RT.load_byte(ctx, API.@offsetof(API.Network.tcphdr, :doff))
            doff = (doff >> 4) * 4
            mymap[1] = RT.load_byte(ctx, doff)
            255
        end
        bytecode = bpffunction(modify_filter, Tuple{API.pointertype(API.sk_buff)}; btf=false, prog_section="socket_filter")
        obj = API.Object(bytecode)
        API.load(obj)
        filt = API.fd(first(API.programs(obj)))
        Host.setsockopt(c_sock, Host.SOL_SOCKET, Host.SO_ATTACH_BPF, filt)
        write(s_sock, 0x42)
        read(c_sock, UInt8)
        hmap = Host.hostmap(first(API.maps(obj)); K=Int32, V=UInt8)
        @test hmap[1] == 0x42
        close(s_sock)
        close(c_sock)
    end
    close(srv)
end
run_root_tests = parse(Bool, get(ENV, "BPFNATIVE_ROOT_TESTS", "0"))
if run_root_tests
    # FIXME: Test with and without VMLinuxBindings
    #@assert BPFnative.has_vmlinux

    test_file, test_io = mktemp(;cleanup=true)
    @info "Running root-only tests"

    # Some useful toplevel defs
    const myarrmap = RT.RTMap(;name="myarrmap",
                               maptype=API.BPF_MAP_TYPE_ARRAY,
                               keytype=UInt32,
                               valuetype=UInt32,
                               maxentries=1)
    const myhashmap = RT.RTMap(;name="myhashmap",
                                maptype=API.BPF_MAP_TYPE_HASH,
                                keytype=UInt32,
                                valuetype=UInt32,
                                maxentries=1)
    const mystrmap = RT.RTMap(;name="mystrmap",
                               maptype=API.BPF_MAP_TYPE_HASH,
                               keytype=UInt32,
                               valuetype=NTuple{4,UInt8},
                               maxentries=1)
    struct PerfBlob
        pid::UInt64
        cookie::UInt64
    end
    const myperfmap = RT.RTMap(;name="myperfmap",
                                maptype=API.BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                                keytype=Cint,
                                valuetype=UInt32,
                                maxentries=2)
    function perf_sample_cb(ctx::Ptr{Bool}, cpu::Cint, data::Ptr{PerfBlob}, size::UInt32)
        data = unsafe_load(data)
        @test size >= sizeof(PerfBlob)
        @test data.cookie == 0x12345678
        unsafe_store!(ctx, true)
        nothing
    end
    perf_sample_cb_ptr = @eval @cfunction(perf_sample_cb, Nothing, (Ptr{Bool}, Cint, Ptr{PerfBlob}, UInt32))
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
        #@testset "uprobe" begin
        #    up = UProbe(+, Tuple{Int,Int}) do regs
        #        return 0
        #    end
        #    API.load(up)
        #    API.unload(up)
        #    @testset "retprobe" begin
        #        up = UProbe(+, Tuple{Int,Int}; retprobe=true) do regs
        #            return 0
        #        end
        #        API.load(up)
        #        API.unload(up)
        #    end
        #end
        @testset "tracepoint" begin
            p = Tracepoint("clk", "clk_enable") do regs
                return 0
            end
            API.load(p)
            API.unload(p)
        end
        if BPFnative.has_vmlinux
            @testset "usdt" begin
                function f(arg)
                    # FIXME: if @query(:julia, :test, typeof(arg))
                        @probe(:julia, :test, arg)
                    #end
                    arg
                end
                f(1)
                julia_path = Base.julia_cmd().exec[1]
                usdtmap = RT.RTMap(;name="usdtmap",
                                    maptype=API.BPF_MAP_TYPE_HASH,
                                    keytype=Int32,
                                    valuetype=Int32,
                                    maxentries=1)
                usdt = USDT(getpid(), julia_path, "julia", "test") do ctx
                    usdtmap[1] = 1 # TODO: Get 1st (Cint) argument
                    0
                end
                API.load(usdt) do
                    f(1)
                    host_usdtmap = Host.hostmap(usdt, usdtmap)
                    @test host_usdtmap[1] == 1
                    host_usdtmap[1] = 2
                    @test host_usdtmap[1] == 2
                    f(1)
                    @test host_usdtmap[1] == 1
                end
            end
        else
            @test_skip "USDT"
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
            elem = myarrmap[1]
            if elem !== nothing
                myarrmap[1] = 42
            else
                myarrmap[1] = 1
            end
            return 0
        end
        kp = KProbe(kp_func, "ksys_write")
        API.load(kp) do
            map = first(API.maps(kp.obj))
            hmap = Host.hostmap(map; K=UInt32, V=UInt32)
            write(test_io, "1"); flush(test_io)
            @test hmap[1] == 42

            # Convenience ctor
            hmap2 = Host.hostmap(kp.obj, myarrmap)
            @test hmap.fd == hmap2.fd
        end
    end
    @testset "map merging" begin
        kp1 = KProbe("ksys_write") do regs
            myhashmap[1] = 42
            return 0
        end
        API.load(kp1)
        kp2 = KProbe("ksys_write"; merge_with=(kp1.obj,)) do regs
            if myhashmap[1] === nothing
                myhashmap[1] = 43
            end
            return 0
        end
        API.load(kp2)
        host_mymap1 = Host.hostmap(kp1.obj, myhashmap)
        host_mymap2 = Host.hostmap(kp2.obj, myhashmap)
        write(test_io, "1"); flush(test_io)
        @test host_mymap1[1] == host_mymap2[1]
        API.unload.((kp1, kp2))
    end
    @testset "memory intrinsics" begin
        kp = KProbe("ksys_write") do regs
            buf = RT.@create_string("hi!")
            mystrmap[1] = ntuple(x->UInt8(0), 4)
            key = Ref{UInt32}(1)
            key_ptr = Base.unsafe_convert(Ptr{UInt32}, key)
            GC.@preserve key begin
                value_ptr = mystrmap[key_ptr]
                if reinterpret(UInt64, value_ptr) != 0
                    RT.memcpy!(value_ptr, pointer(buf), 4)
                end
            end
            return 0
        end
        API.load(kp) do
            host_mymap = Host.hostmap(kp.obj, mystrmap)
            write(test_io, "1"); flush(test_io)
            @test String(reinterpret(UInt8, collect(host_mymap[1]))) == "hi!\0"
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
                write(test_io, "1"); flush(test_io)
                old = hmap[1]
                write(test_io, "1"); flush(test_io)
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
                write(test_io, "1"); flush(test_io)
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
                write(test_io, "1"); flush(test_io)
                old = hmap[1]
                write(test_io, "1"); flush(test_io)
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
                    write(test_io, "1"); flush(test_io)
                end
                was_set = false
                for idx in 1:Sys.CPU_THREADS
                    if hmap[idx] == 1
                        was_set = true
                    end
                end
                @test was_set
                @test !haskey(hmap, Sys.CPU_THREADS+1)
            end
        end
        @testset "skb_store_bytes and (l3/l4)_csum_replace" begin
            function kernel(ctx)
                eth_hdr = API.Network.@ETH_HLEN()
                ver = (RT.load_byte(ctx, eth_hdr) & 0xF0) >> 4
                ihl = (RT.load_byte(ctx, eth_hdr) & 0xF)
                if (ver != 4) || (ihl > 5)
                    return 0
                end
                ip_proto = RT.load_byte(ctx, eth_hdr + API.@offsetof(API.Network.iphdr, :protocol))
                if ip_proto != API.Network.IPPROTO_TCP
                    return 0
                end
                ip_hdr = eth_hdr + sizeof(API.Network.iphdr)
                doff = RT.load_byte(ctx, ip_hdr + API.@offsetof(API.Network.tcphdr, :doff))
                doff = (doff >> 4) * 4
                doff += ip_hdr
                oldbyte = RT.load_byte(ctx, doff)
                if oldbyte != 0x1
                    return 0
                end
                newbyte = 0x2
                ret = RT.skb_store_bytes(ctx, doff, newbyte, sizeof(newbyte), 0)
                if ret < 0
                    RT.trace_printk(RT.@create_string("Store failed: %d"), ret)
                    return 2
                end
                0
            end
            str = bpffunction(kernel, Tuple{API.pointertype(API.sk_buff)}; prog_section="classifier", license="GPL")
            path, io = mktemp(;cleanup=true)
            write(io, str); flush(io)
            run(`ip link add name jlbpf_test type veth peer name jlbpf_test2`)
            try
                run(`ip link set jlbpf_test up`)
                run(`ip netns add jlbpf_ns`)
                try
                    run(`ip link set jlbpf_test2 netns jlbpf_ns`)
                    run(`ip netns exec jlbpf_ns ip addr add 10.45.98.2/24 dev jlbpf_test2`)
                    run(`ip netns exec jlbpf_ns ip link set jlbpf_test2 up`)
                    run(`ip addr add 10.45.98.1/24 dev jlbpf_test`)
                    run(`ip netns exec jlbpf_ns ip route add default via 10.45.98.1`)
                    run(`ip netns exec jlbpf_ns tc qdisc add dev jlbpf_test2 clsact`)
                    run(`ip netns exec jlbpf_ns tc filter add dev jlbpf_test2 ingress bpf da obj $path`)
                    jl = run(`ip netns exec jlbpf_ns $(unsafe_string(Base.JLOptions().julia_bin)) -e 'using Sockets;l=listen(IPv4("10.45.98.2"),8765);s=accept(l);write(s,read(s,UInt8))'`; wait=false)
                    sleep(1)
                    try
                        sock = connect("10.45.98.2", 8765)
                        write(sock, 0x1)
                        @test read(sock, UInt8) == 0x2
                    catch err
                        kill(jl)
                        rethrow(err)
                    end
                finally
                    run(`ip netns del jlbpf_ns`)
                end
            finally
                run(`ip link del dev jlbpf_test`)
            end
        end
        @testset "get_current_pid_tgid" begin
            kp = KProbe("ksys_write") do x
                mymap = RT.RTMap(;name="mymap",maptype=API.BPF_MAP_TYPE_HASH,keytype=UInt32,valuetype=UInt32,maxentries=2)
                pid, tgid = RT.get_current_pid_tgid()
                mymap[tgid] = pid
                0
            end
            API.load(kp) do
                map = first(API.maps(kp.obj))
                hmap = Host.hostmap(map; K=UInt32, V=UInt32)
                write(test_io, "1"); flush(test_io)
                # FIXME: Why doesn't this work?
                #@test haskey(hmap, getpid())
                #@test hmap[getpid()] == getpid()
            end
        end
        iob = IOBuffer()
        run(pipeline(`id -u`; stdout=iob))
        euid = parse(Int, chomp(String(take!(iob))))
        @testset "get_current_uid_gid" begin
            kp = KProbe("ksys_write") do x
                mymap = RT.RTMap(;name="mymap",maptype=API.BPF_MAP_TYPE_HASH,keytype=UInt32,valuetype=UInt32,maxentries=2)
                uid, gid = RT.get_current_uid_gid()
                mymap[uid] = gid
                0
            end
            API.load(kp) do
                map = first(API.maps(kp.obj))
                hmap = Host.hostmap(map; K=UInt32, V=UInt32)
                write(test_io, "1"); flush(test_io)
                @test haskey(hmap, euid)
                @test hmap[euid] == euid # Not sure if a good idea, but eh
            end
        end
        # TODO: get_current_comm
        @testset "perf_event_output" begin
            # From Linux's samples/bpf/trace_output_*
            kp = KProbe("ksys_write"; license="GPL") do ctx
                buf = RT.create_buffer(sizeof(PerfBlob))
                GC.@preserve buf begin
                    buf_ptr = reinterpret(Ptr{PerfBlob}, pointer(buf))
                    unsafe_store!(buf_ptr, PerfBlob(0x42, 0x12345678))
                end
                RT.perf_event_output(ctx, myperfmap, 0, buf)
                0
            end
            API.load(kp) do
                map = first(API.maps(kp.obj))
                cb_ref = Ref{Bool}(false)
                GC.@preserve cb_ref begin
                    pb = Host.PerfBuffer{Cint,UInt32}(API.fd(map), 8; sample_cb=perf_sample_cb_ptr, ctx=Base.unsafe_convert(Ptr{Bool}, cb_ref))
                    for i in 1:10
                        Host.poll(pb, 100)
                        write(test_io, "1"); flush(test_io)
                    end
                    @test cb_ref[]
                end
            end
        end
        @testset "get_stackid" begin
            # from BCC's stackcount
            struct StackKey
                tgid::UInt32
                sid::Clong
            end
            kp = KProbe("ksys_write"; license="GPL") do x
                stacks = RT.RTMap(;name="stacks",maptype=API.BPF_MAP_TYPE_STACK_TRACE,keytype=UInt32,valuetype=NTuple{API.PERF_MAX_STACK_DEPTH,UInt64},maxentries=10000)
                counts = RT.RTMap(;name="counts",maptype=API.BPF_MAP_TYPE_HASH,keytype=StackKey,valuetype=UInt32,maxentries=10000)
                pid, tgid = RT.get_current_pid_tgid()
                sid = RT.get_stackid(x, stacks, 0)
                key = StackKey(tgid, sid)
                old_count = get(counts, key, 0)
                counts[key] = old_count + 1
                0
            end
            API.load(kp) do
                stacks = Host.hostmap(API.findmap(kp.obj, "stacks"); K=UInt32, V=NTuple{API.PERF_MAX_STACK_DEPTH,UInt64})
                counts = Host.hostmap(API.findmap(kp.obj, "counts"); K=StackKey, V=UInt32)
                write(test_io, "1"); flush(test_io)
                ks = collect(keys(counts))
                @test length(ks) > 0
                key = first(ks)
                # TODO: Should we be able to find a key with getpid() == key.tgid?
                @test haskey(counts, key)
                # TODO: This is potentially racy
                @test haskey(stacks, key.sid)
                @test occursin("sys_write", Host.stack_to_string(stacks[key.sid]))
            end
        end
    end
    if BPFnative.has_vmlinux
        @testset "struct accessors" begin
            kp = KProbe("ksys_write"; license="GPL") do ctx
                task = RT.get_current_task()
                reinterpret(UInt64, task) == 0 && return 1
                cpu = RT.@elemptr(task.on_cpu[])
                if cpu !== nothing
                    if cpu == RT.get_smp_processor_id()
                        myhashmap[1] = cpu
                    end
                end
                0
            end
            API.load(kp) do
                host_myhashmap = Host.hostmap(kp.obj, myhashmap)
                write(test_io, "1"); flush(test_io)
                @test haskey(host_myhashmap, 1)
            end
        end
    else
        @test_skip "struct accessors"
    end
end
