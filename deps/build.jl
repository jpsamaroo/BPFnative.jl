using Clang, Clang.LibClang

common_file = joinpath(@__DIR__, "..", "gen", "vmlinux_common.jl")
c_str = try
    iob = IOBuffer()
    run(pipeline(`bpftool btf dump file /sys/kernel/btf/vmlinux format c`; stdout=iob))
    String(take!(iob))
catch err
    @warn "Generating vmlinux headers failed: $(sprint(io->Base.showerror(io, err)))"
    touch(common_file)
    exit(0)
end

path = "/tmp/vmlinux.c"
open(path, "w") do io
    write(io, c_str)
    flush(io)
end

ctx = DefaultContext()
parse_header!(ctx, path)

for trans_unit = ctx.trans_units
    root_cursor = getcursor(trans_unit)
    ctx.children = children(root_cursor)

    for (i, child) in enumerate(ctx.children)
        child_name = name(child)
        child_kind = kind(child)
        ctx.children_index = i
        try
            wrap!(ctx, child)
        catch err
            @warn "Failed to write $child_name: $err"
        end
    end
end

open(common_file, "w") do f
    print_buffer(f, dump_to_buffer(ctx.common_buffer))
end
# TODO: Fix Clang so it does this for us
run(`sed -i 's/{module}/{_module}/' $common_file`)
