const KALLSYMS_CACHE = Ref{Vector{String}}()
const KALLSYMS_REGEX = r"([0-9abcdef]*) ([a-zA-Z]) ([0-9a-zA-Z_\-]*)"
function find_ksym(addr::UInt64)
    start, stop = UInt64(0), addr
    if !isassigned(KALLSYMS_CACHE)
        KALLSYMS_CACHE[] = readlines("/proc/kallsyms")
    end
    L = 1
    R = length(KALLSYMS_CACHE[])
    start_addr = start
    kind = "?"
    name = ""
    while L <= R
        M = floor(Int, (L + R) / 2)
        m = match(KALLSYMS_REGEX, KALLSYMS_CACHE[][M])
        @assert m !== nothing
        start_addr, kind, name = m.captures
        start_addr = parse(UInt64, "0x"*start_addr)
        if L == R
            return start_addr, kind, name
        elseif start_addr == stop
            return start_addr, kind, name
        elseif start_addr < stop
            L = M + 1
        else
            R = M - 1
        end
    end
    return start_addr, kind, name
end
function stack_to_string(nt::NTuple{N,UInt64}; reverse=false) where N
    iob = IOBuffer()
    order = reverse ? (N:-1:1) : (1:N)
    for i in order
        addr = nt[i]
        if addr == UInt64(0)
            continue
        end
        println(iob, "$(find_ksym(addr)[3])")
    end
    String(take!(iob))
end
function stack_to_frames(nts::Vector{Tuple{Symbol,UInt64,NTuple{N,UInt64}}}) where N
    data = UInt64[]
    lidict = Dict{UInt64, Vector{Base.StackTraces.StackFrame}}()
    for (proc,count,nt) in nts
        for i in 1:count
            for addr in nt
                if addr != 0
                    name = find_ksym(addr)[3]
                    frame = Base.StackTraces.StackFrame(Symbol(name), proc, -1, nothing, true, false, addr)
                    lidict[addr] = [frame]
                    push!(data, addr)
                end
            end
            push!(data, 0)
        end
    end
    data, lidict
end
