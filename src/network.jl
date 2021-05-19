module Network
    using CBinding
    c`-std=c99 -fparse-all-comments`
    const c"__u8" = UInt8
    const c"__u16" = UInt16
    const c"__u32" = UInt32
    const c"__be8" = UInt8
    const c"__be16" = UInt16
    const c"__be32" = UInt32
    const c"__sum16" = UInt16
    c"#include <linux/if_ether.h>"j
    c"#include <linux/ip.h>"j
    c"#include <linux/in.h>"j
    c"#include <linux/tcp.h>"j
end
