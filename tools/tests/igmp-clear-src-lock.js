const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/igmp.c'), 'utf8');
const functionStart = source.indexOf('static void ip_mc_clear_src(struct ip_mc_list *pmc)\n{');
const functionEnd = source.indexOf('\n}', functionStart);
assert.notEqual(functionStart, -1, 'ip_mc_clear_src must exist');
assert.notEqual(functionEnd, -1, 'ip_mc_clear_src must have a closing brace');
const body = source.slice(functionStart, functionEnd);
const lockStart = body.indexOf('spin_lock_bh(&pmc->lock);');
const unlockStart = body.indexOf('spin_unlock_bh(&pmc->lock);');
assert.ok(lockStart >= 0 && unlockStart > lockStart,
    'source list detachment and state reset must be protected by pmc->lock');

const locked = body.slice(lockStart, unlockStart);
for (const statement of [
    'tomb = pmc->tomb;',
    'pmc->tomb = NULL;',
    'sources = pmc->sources;',
    'pmc->sources = NULL;',
    'pmc->sfmode = MCAST_EXCLUDE;',
    'pmc->sfcount[MCAST_INCLUDE] = 0;',
    'pmc->sfcount[MCAST_EXCLUDE] = 1;'
]) {
    assert.ok(locked.includes(statement), `${statement} must run under pmc->lock`);
}

const unlocked = body.slice(unlockStart);
assert.match(unlocked, /for \(psf=tomb; psf; psf=nextpsf\)/,
    'detached tomb nodes must be freed after unlocking');
assert.match(unlocked, /for \(psf=sources; psf; psf=nextpsf\)/,
    'detached source nodes must be freed after unlocking');
assert.doesNotMatch(unlocked, /pmc->(?:tomb|sources)/,
    'free loops must not traverse lists still reachable from pmc');

console.log('PASS: ip_mc_clear_src detaches and resets under lock, then frees detached lists; source check only');