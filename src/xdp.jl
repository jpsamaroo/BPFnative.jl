export xdp_load, xdp_unload

@enum xdp_action begin
    XDP_ABORTED
    XDP_DROP
    XDP_PASS
    XDP_TX
    XDP_REDIRECT
end

function xdp_load(iface::String, bpf::Vector{UInt8})
    mktemp() do path, io
        write(io, bpf)
        flush(io)
        run(`ip link set $iface xdp obj $path verbose`)
    end
end
function xdp_unload(iface::String)
    run(`ip link set $iface xdp off`)
end
