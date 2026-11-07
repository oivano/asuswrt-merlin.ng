const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const sourcePath = path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/net/sched/act_ipt.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const initStart = source.indexOf('static int tcf_ipt_init(');
const initEnd = source.indexOf('\nstatic int tcf_ipt_cleanup(', initStart);
assert(initStart >= 0 && initEnd > initStart, 'missing tcf_ipt_init');
const init = source.slice(initStart, initEnd);

assert.match(source, /#include <linux\/rcupdate\.h>/,
    'RCU callback declarations must be explicit');
assert.match(source,
    /static void tcf_ipt_free_rcu\(struct rcu_head \*head\)\s*\{\s*kfree\(container_of\(head, struct tcf_common, tcfc_rcu\)\);\s*\}/,
    'created action must be freed through its common RCU head');
assert.match(init,
    /err1:\s*if \(ret == ACT_P_CREATED\)\s*\{\s*gen_kill_estimator\(&pc->tcfc_bstats, &pc->tcfc_rate_est\);\s*call_rcu\(&pc->tcfc_rcu, tcf_ipt_free_rcu\);\s*\} else \{\s*tcf_ipt_release\(ipt, bind\);\s*\}/,
    'failure cleanup must kill a created estimator and RCU-defer free');
assert.doesNotMatch(init, /err1:[\s\S]*?kfree\(pc\)/,
    'failure path must not directly free a hashed or estimator-registered action');

console.log('tc-ipt-init-error: ok');