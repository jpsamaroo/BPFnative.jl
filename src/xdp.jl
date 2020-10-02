export xdp_load, xdp_unload

@enum xdp_action begin
    XDP_ABORTED
    XDP_DROP
    XDP_PASS
    XDP_TX
    XDP_REDIRECT
end

struct xdp_md
    data::UInt32
    data_end::UInt32
    data_meta::UInt32
    ingress_ifindex::UInt32
    rx_queue_index::UInt32
end

function xdp_load(iface::String, mod::BPFModule)
    mktemp() do path, io
        write(io, mod.data)
        flush(io)
        run(`ip link set $iface xdp obj $path verbose`)
    end
end
function xdp_unload(iface::String)
    run(`ip link set $iface xdp off`)
end
