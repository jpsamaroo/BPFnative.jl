#include <stdio.h>

enum libbpf_print_level {
        LIBBPF_WARN,
        LIBBPF_INFO,
        LIBBPF_DEBUG,
};

int jl_bpf_print(enum libbpf_print_level level, const char *fmt, va_list ap) {
    return vfprintf(stderr, fmt, ap);
}
