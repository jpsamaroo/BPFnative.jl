import Pkg

Pkg.update()

root_directory = dirname(@__DIR__)

bpfnative = Pkg.PackageSpec(path = root_directory)
Pkg.develop(bpfnative)
Pkg.build()
Pkg.precompile()
Pkg.test("BPFnative")
