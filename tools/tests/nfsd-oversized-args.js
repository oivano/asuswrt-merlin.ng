"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

const sourcePath = path.join(
    __dirname,
    "../../release/src-rt-6.x.4708/linux/linux-2.6.36/fs/nfsd/nfssvc.c"
);
const source = fs.readFileSync(sourcePath, "utf8");
const helper = source.match(
    /static bool nfs_request_too_big\(struct svc_rqst \*rqstp,[\s\S]*?\n}\n/
);
assert(helper, "oversized request guard exists");
assert(helper[0].includes("rqstp->rq_prog != NFS_PROGRAM"), "ACL RPC is exempt");
assert(helper[0].includes("rqstp->rq_vers >= 4"), "NFSv4 is exempt");
assert(
    helper[0].includes("proc->pc_xdrressize < XDR_QUADLEN(PAGE_SIZE)"),
    "small replies are exempt"
);
assert(helper[0].includes("rqstp->rq_arg.len > PAGE_SIZE"), "oversize boundary is strict");

const dispatchStart = source.indexOf("nfsd_dispatch(struct svc_rqst *rqstp");
const guardCall = source.indexOf("if (nfs_request_too_big(rqstp, proc))", dispatchStart);
const decodeCall = source.indexOf("xdr = proc->pc_decode;", dispatchStart);
assert(dispatchStart >= 0 && guardCall > dispatchStart, "dispatch invokes the guard");
assert(guardCall < decodeCall, "guard runs before pc_decode");
assert(source.includes("*statp = rpc_garbage_args;", guardCall), "oversize calls return GARBAGE_ARGS");

function rejects({ program = 100003, version = 3, length, replyWords }) {
    if (program !== 100003 || version >= 4)
        return false;
    if (replyWords > 0 && replyWords < Math.ceil(4096 / 4))
        return false;
    return length > 4096;
}

assert(rejects({ length: 4097, replyWords: 1200 }), "large READ reply rejects a long call");
assert(!rejects({ length: 4096, replyWords: 1200 }), "one-page argument remains allowed");
assert(!rejects({ length: 4097, replyWords: 100 }), "small-reply procedure remains allowed");
assert(!rejects({ program: 100227, length: 4097, replyWords: 1200 }), "ACL program remains allowed");
assert(!rejects({ version: 4, length: 4097, replyWords: 1200 }), "NFSv4 remains allowed");

console.log("nfsd oversized-args regression checks passed");