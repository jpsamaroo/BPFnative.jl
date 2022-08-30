const libcap = "/usr/lib/libcap.so"

const CAP_PERFMON = Cint(39)
const CAP_BPF = Cint(39)
const CAP_EFFECTIVE = Cint(0)
const CAP_SET = Cint(1)

function add_cap_bpf!()
    caps = ccall((:cap_get_proc, libcap), Ptr{Cvoid}, ())
    cap_list = [CAP_BPF,CAP_PERFMON]
    @assert ccall((:cap_set_flag, libcap), Cint,
                  (Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}, Cint),
                  caps, CAP_EFFECTIVE, length(cap_list), cap_list, CAP_SET) != 1
    @assert ccall((:cap_set_proc, libcap), Cint, (Ptr{Cvoid},), caps) != -1
    @assert ccall((:cap_free, libcap), Cint, (Ptr{Cvoid},), caps) != -1
    return
end
