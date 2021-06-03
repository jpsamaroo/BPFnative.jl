function find_ksym(addr::UInt64)
    start, stop = UInt64(0), addr
    rgx = r"([0-9abcdef]*) ([a-zA-Z]) ([0-9a-zA-Z_\-]*)"
    last_addr = start
    last_kind = "?"
    last_name = ""
    for line in readlines(open("/proc/kallsyms", "r"))
        m = match(rgx, line)
        @assert m !== nothing
        start_addr, kind, name = m.captures
        start_addr = parse(UInt64, "0x"*start_addr)
        if start_addr > stop
            return last_addr, last_kind, last_name
        elseif start_addr == stop
            return addr, kind, name
        end
        last_addr = addr
        last_kind = kind
        last_name = name
    end
end
function stack_to_string(nt::NTuple{N,UInt64}) where N
    iob = IOBuffer()
    for i in 1:N
        addr = nt[i]
        if addr == UInt64(0)
            break
        end
        println(iob, "$(find_ksym(addr)[3])")
    end
    String(take!(iob))
end
