# Buffers/strings

abstract type AbstractBuffer end
abstract type AbstractSizedBuffer end
abstract type AbstractUnsizedBuffer end

const BufPtr = Core.LLVMPtr{UInt8,0}

@inline @generated function create_buffer(::Val{N}) where N
    Context() do ctx
        T_i8 = LLVM.Int8Type(ctx)
        T_pi8 = LLVM.PointerType(T_i8)
        T_i64 = LLVM.Int64Type(ctx)
        T_buf = LLVM.ArrayType(T_i8, N)
        llvm_f, _ = create_function(T_pi8)
        mod = LLVM.parent(llvm_f)
        Builder(ctx) do builder
            entry = BasicBlock(llvm_f, "entry"; ctx)
            position!(builder, entry)

            # Allocate stack buffer
            malloc_ft = LLVM.FunctionType(T_pi8, [T_i64])
            malloc_f = LLVM.Function(mod, "malloc", malloc_ft)
            buf_len = ConstantInt(T_i64, N)
            buf_ptr = call!(builder, malloc_f, [buf_len])

            # Zero-out buffer
            zero_value = ConstantInt(T_i8, 0)
            _memset!(builder, ctx, mod, buf_ptr, zero_value, buf_len, ConstantInt(LLVM.Int1Type(ctx), 0))

            ret!(builder, buf_ptr)
        end
        call_function(llvm_f, BufPtr)
    end
end

"""
    SizedBuffer <: AbstractSizedBuffer

Represents a buffer/string with a known size.
"""
struct SizedBuffer <: AbstractSizedBuffer
    ptr::BufPtr
    length::UInt32
end
SizedBuffer(buf::AbstractSizedBuffer) = SizedBuffer(pointer(buf), length(buf))
SizedBuffer(ptr::Ptr, length) = SizedBuffer(reinterpret(BufPtr, ptr), length)
Base.pointer(str::SizedBuffer) = str.ptr
Base.length(str::SizedBuffer) = str.length
@inline create_buffer(N::Int) = SizedBuffer(create_buffer(Val(N)), N)
macro create_string(str::String)
    N = length(str)+1
    :(SizedBuffer(create_string($(Val(Symbol(str)))), $N))
end

@inline @generated function create_string(::Val{str}) where str
    Context() do ctx
        _str = String(str)
        T_i8 = LLVM.Int8Type(ctx)
        T_pi8 = LLVM.PointerType(T_i8)
        T_i64 = LLVM.Int64Type(ctx)
        T_i1 = LLVM.Int1Type(ctx)
        T_buf = LLVM.ArrayType(T_i8, length(_str)+1)
        llvm_f, _ = create_function(T_pi8)
        mod = LLVM.parent(llvm_f)
        Builder(ctx) do builder
            entry = BasicBlock(llvm_f, "entry"; ctx)
            position!(builder, entry)

            # Allocate string
            str_ptr = globalstring_ptr!(builder, _str)
            gv = operands(str_ptr)[1]
            #set_used!(mod, gv)

            # Allocate stack buffer
            malloc_ft = LLVM.FunctionType(T_pi8, [T_i64])
            malloc_f = LLVM.Function(mod, "malloc", malloc_ft)
            buf_ptr = call!(builder, malloc_f, [ConstantInt(T_i64, length(_str)+1)])

            # Copy string into stack buffer
            memcpy_ft = LLVM.FunctionType(LLVM.VoidType(ctx), [T_pi8, T_pi8, T_i64, T_i1])
            memcpy_f = LLVM.Function(mod, "llvm.memcpy.p0i8.p0i8.i64", memcpy_ft)
            call!(builder, memcpy_f, [buf_ptr, str_ptr, ConstantInt(T_i64, length(_str)+1), ConstantInt(T_i1, 0)])

            # Return stack buffer
            ret!(builder, buf_ptr)
        end
        call_function(llvm_f, BufPtr)
    end
end

"""
    UnsizedBuffer <: AbstractUnsizedBuffer

Represents a buffer/string with an unknown size.
"""
struct UnsizedBuffer <: AbstractUnsizedBuffer
    ptr::BufPtr
end
UnsizedBuffer(buf::AbstractBuffer) = UnsizedBuffer(pointer(buf))
UnsizedBuffer(ptr::Ptr) = UnsizedBuffer(reinterpret(BufPtr, ptr))
Base.pointer(str::UnsizedBuffer) = str.ptr
Base.length(str::UnsizedBuffer) = missing
