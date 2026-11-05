const assert = require("assert");
const fs = require("fs");

const kernel = "release/src-rt-6.x.4708/linux/linux-2.6.36/";
const socket = fs.readFileSync(`${kernel}net/socket.c`, "utf8");
const tcp = fs.readFileSync(`${kernel}net/ipv4/tcp.c`, "utf8");
const target = fs.readFileSync("release/src-rt/target.mak", "utf8");
const makefile = fs.readFileSync("release/src-rt/Makefile", "utf8");

function section(source, start, end) {
    const startIndex = source.indexOf(start);
    assert.notStrictEqual(startIndex, -1, `missing section start: ${start}`);
    const endIndex = source.indexOf(end, startIndex + start.length);
    assert.notStrictEqual(endIndex, -1, `missing section end: ${end}`);
    return source.slice(startIndex, endIndex);
}

const recvfrom = section(
    socket,
    "SYSCALL_DEFINE6(recvfrom",
    "asmlinkage long sys_recv"
);
assert.match(
    recvfrom,
    /#if defined\(MSG_KERNSPACE\) && defined\(MSG_NOCATCHSIG\)\s*flags &= ~\(MSG_KERNSPACE \| MSG_NOCATCHSIG\);\s*#endif/
);
assert(recvfrom.includes("msg.msg_flags = 0;"));
assert(
    recvfrom.indexOf("msg.msg_flags = 0;") <
    recvfrom.indexOf("sock_recvmsg(sock, &msg")
);

const recvmsg = section(
    socket,
    "static int __sys_recvmsg",
    "SYSCALL_DEFINE3(recvmsg"
);
assert.match(
    recvmsg,
    /#if defined\(MSG_KERNSPACE\) && defined\(MSG_NOCATCHSIG\)\s*flags &= ~\(MSG_KERNSPACE \| MSG_NOCATCHSIG\);\s*#endif/
);
assert(
    recvmsg.indexOf("flags &= ~(MSG_KERNSPACE | MSG_NOCATCHSIG);") <
    recvmsg.indexOf("sock_recvmsg)(sock, msg_sys")
);
assert(
    recvmsg.includes(
        "msg_sys->msg_flags = flags & (MSG_CMSG_CLOEXEC|MSG_CMSG_COMPAT);"
    )
);

assert.match(
    tcp,
    /\(msg->msg_flags & MSG_KERNSPACE\)\s*&&\s*segment_eq\(get_fs\(\), KERNEL_DS\)/
);
const kernelRecv = section(
    socket,
    "int kernel_recvmsg(",
    "EXPORT_SYMBOL(kernel_recvmsg)"
);
assert(
    kernelRecv.indexOf("set_fs(KERNEL_DS)") <
    kernelRecv.indexOf("sock_recvmsg(sock, msg")
);

const dslNone = target.match(/DSL-AC68U-NONE\s*:=([\s\S]*?)\nexport DSL-AC68U/);
assert(dslNone, "DSL-AC68U feature exclusion list missing");
assert(dslNone[1].includes("BCM_RECVFILE=y"));
assert(makefile.includes('echo "# CONFIG_BCM_RECVFILE is not set" >>$(1);'));

const MSG_KERNSPACE = 0x40000;
const kernelCopyAllowed = (msgFlags, addressLimit) =>
    !!(msgFlags & MSG_KERNSPACE) && addressLimit === "KERNEL_DS";
assert.strictEqual(kernelCopyAllowed(MSG_KERNSPACE, "USER_DS"), false);
assert.strictEqual(kernelCopyAllowed(MSG_KERNSPACE, "KERNEL_DS"), true);

console.log("recvfile kernel-space receive guards pass");