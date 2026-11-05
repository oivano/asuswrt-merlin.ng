const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = directory => fs.readFileSync(path.join(root,
    'release/src/router/igmpproxy/src', directory), 'utf8');
const request = source('request.c');
const callout = source('callout.c');
const header = source('igmpproxy.h');
const body = (text, start, end) => {
    const offset = text.indexOf(start);
    assert.ok(offset >= 0, `missing ${start}`);
    const limit = text.indexOf(end, offset + start.length);
    assert.ok(limit > offset, `missing ${end}`);
    return text.slice(offset, limit);
};

const acceptLeave = body(request, 'void acceptLeaveMessage(', 'void sendGroupSpecificMemberQuery(');
const query = body(request, 'void sendGroupSpecificMemberQuery(', 'void sendGeneralMembershipQuery(');
const cleanup = body(callout, 'void free_all_callouts(', 'void age_callout_queue(');
const clearTimer = body(callout, 'int timer_clearTimer(', '/**\n * debugging utility\n');

assert.match(acceptLeave, /gvDesc\s*=\s*\(GroupVifDesc\*\)\s*malloc\(sizeof\(GroupVifDesc\)\);\s*if\s*\(gvDesc\s*==\s*NULL\)\s*\{[^}]*return;/s,
    'leave allocation failure returns before descriptor use');
assert.ok(acceptLeave.indexOf('if (gvDesc == NULL)') < acceptLeave.indexOf('setRouteLastMemberMode(group)'),
    'allocation failure does not alter route last-member state');
assert.match(query, /if\s*\(!lastMemberGroupAge\(gvDesc->group\)\)\s*\{\s*free\(gvDesc\);\s*return;/,
    'terminal route/probe completion releases descriptor');
assert.match(query, /timer_setTimerWithCleanup\([\s\S]*?sendGroupSpecificMemberQuery,\s*gvDesc,\s*free\)\s*<\s*0\)\s*\{[\s\S]*?free\(gvDesc\);/,
    'failed timer allocation releases descriptor');
assert.match(header, /typedef void \(\*timer_data_cleanup_f\)\(void \*\);/);
assert.match(header, /int timer_setTimerWithCleanup\(int, timer_f, void \*, timer_data_cleanup_f\);/);
assert.match(callout, /node->cleanup\s*=\s*cleanup;/,
    'scheduled timer records its data cleanup function');
assert.match(cleanup, /if\s*\(p->cleanup\s*&&\s*p->data\)\s*p->cleanup\(p->data\);/,
    'shutdown releases pending timer data');
assert.match(clearTimer, /if\s*\(ptr->cleanup\)\s*ptr->cleanup\(ptr->data\);\s*else\s*free\(ptr->data\);/,
    'timer cancellation uses the registered data cleanup');
assert.match(query, /if\s*\(gvDesc->started\)\s*\{[\s\S]*?\}\s*else\s*\{\s*gvDesc->started\s*=\s*1;/,
    'callback retains the descriptor while its query sequence continues');

console.log('PASS: igmpproxy leave-query descriptor ownership across failure, completion, cancellation, and shutdown');