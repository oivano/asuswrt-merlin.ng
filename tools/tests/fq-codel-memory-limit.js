"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "../..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const kernel = read("release/src-rt-6.x.4708/linux/linux-2.6.36/net/sched/sch_fq_codel.c");
const qos = read("release/src/router/rc/qos.c");
const usb = read("release/src/router/rc/usb.c");

function functionBody(source, signature) {
    const start = source.indexOf(signature);
    assert.notStrictEqual(start, -1, `missing ${signature}`);
    const open = source.indexOf("{", start);
    let depth = 0;
    for (let index = open; index < source.length; index++) {
        if (source[index] === "{") depth++;
        if (source[index] === "}" && --depth === 0)
            return source.slice(open, index + 1);
    }
    assert.fail(`unterminated ${signature}`);
}

assert.ok(kernel.includes("#define FQ_CODEL_MEMORY_LIMIT (2U * 1024 * 1024)"));
const charge = functionBody(kernel, "static u64 fq_codel_skb_mem");
assert.ok(charge.includes("skb->truesize"));
assert.ok(charge.includes("skb_shinfo(skb)->frag_list"));
assert.ok(charge.includes("fq_codel_skb_mem(frag)"));
assert.ok(charge.includes("FQ_CODEL_MEMORY_LIMIT + 1ULL"));

const drop = functionBody(kernel, "static unsigned int fq_codel_drop");
assert.ok(drop.includes("q->memories[i] > maxmem"));
assert.ok(drop.includes("q->memory_used -= mem"));
assert.ok(drop.includes("sch->qstats.backlog -= len"));
assert.ok(drop.indexOf("sch->qstats.backlog -= len") < drop.indexOf("kfree_skb(skb)"));

const enqueue = functionBody(kernel, "static int fq_codel_enqueue");
assert.ok(enqueue.includes("q->memory_used <= q->memory_limit"));
assert.ok(enqueue.includes("while (sch->q.qlen > q->limit || q->memory_used > q->memory_limit)"));
assert.ok(enqueue.includes("qdisc_tree_decrease_qlen(sch, drop_count - !!dropped_same_flow)"));

const dequeue = functionBody(kernel, "static struct sk_buff *dequeue(");
assert.ok(dequeue.includes("q->memories[idx] -= mem"));
assert.ok(dequeue.includes("q->memory_used -= mem"));
assert.ok(kernel.includes("q->memory_limit = FQ_CODEL_MEMORY_LIMIT"));

const gro = functionBody(usb, "void enable_gro(int interval)");
assert.ok(gro.includes("interval > 0 && (IS_TQOS() || IS_BW_QOS())"));
assert.ok(gro.includes("interval = 0;"));
assert.ok(functionBody(qos, "int start_iQos(void)").includes("enable_gro(0)"));
assert.ok(functionBody(qos, "void stop_iQos(void)").includes('pids("smbd")'));

const memoryLimit = 2 * 1024 * 1024;
function chargeModel(skb) {
    let memory = skb.truesize;
    if (memory > memoryLimit) return memoryLimit + 1;
    for (const frag of skb.fragList || []) {
        const fragMemory = chargeModel(frag);
        if (fragMemory > memoryLimit - memory) return memoryLimit + 1;
        memory += fragMemory;
    }
    return memory;
}

const aggregate = {
    truesize: 12000,
    fragList: [
        { truesize: 70000 },
        { truesize: 80000, fragList: [{ truesize: 50000 }] },
    ],
};
assert.strictEqual(chargeModel(aggregate), 212000);

const flows = [[1.6 * 1024 * 1024], [1.4 * 1024 * 1024]];
flows[0].push(1.2 * 1024 * 1024);
let drops = 0;
const queuedMemory = () => flows.flat().reduce((sum, memory) => sum + memory, 0);
while (queuedMemory() > memoryLimit) {
    const fattest = flows.reduce((best, flow, index) =>
        flow.reduce((sum, memory) => sum + memory, 0) >
            flows[best].reduce((sum, memory) => sum + memory, 0) ? index : best, 0);
    flows[fattest].shift();
    drops++;
}
assert.strictEqual(drops, 2);
assert.ok(queuedMemory() <= memoryLimit);
assert.ok(10 * memoryLimit <= 256 * 1024 * 1024);

console.log("fq_codel memory-limit regression checks passed");