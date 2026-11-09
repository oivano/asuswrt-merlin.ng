const assert = require('assert');
const fs = require('fs');

const root = `${__dirname}/../..`;
const source = fs.readFileSync(`${root}/release/src/router/rc/erp_monitor.c`, 'utf8');

function functionBody(signature) {
    const start = source.indexOf(signature);
    assert.notStrictEqual(start, -1, `missing function ${signature}`);
    const open = source.indexOf('{', start);
    let depth = 0;
    for (let index = open; index < source.length; index++) {
        if (source[index] === '{') depth++;
        else if (source[index] === '}' && --depth === 0) return source.slice(open, index + 1);
    }
    assert.fail(`unterminated function ${signature}`);
}

assert.doesNotMatch(source, /ERP_(?:FOLDER|GPHY|IPV[46]_ARP)/);
assert.match(source, /pipe\(pfd\)/);
assert.match(source, /fork\(\)/);
assert.match(source, /execvp\(argv\[0\], argv\)/);
assert.match(source, /waitpid\(child, &status, 0\)/);

const arp = functionBody('static int erp_check_arp_stat(');
const gphy = functionBody('static int erp_check_gphy_stat(');
assert.match(arp, /erp_pipe_open\(argv, &child\)/);
assert.match(arp, /"ip", "-f", "inet6", "neigh", "show", "dev", nvram_safe_get\("lan_ifname"\)/);
assert.match(arp, /"ip", "-f", "inet", "neigh", "show", "dev", nvram_safe_get\("lan_ifname"\)/);
assert.match(arp, /%127s %\*s %19s %\*s/);
assert.match(arp, /%\*s %\*s %\*s %19s/);
assert.match(gphy, /"ATE", "Get_WanLanStatus"/);
assert.strictEqual((gphy.match(/%1\[\^;\]/g) || []).length, 31,
    'every GPHY value conversion must fit a two-byte destination');
assert.match(gphy, /\) != 9\) continue/);
assert.match(gphy, /\) != 7\) continue/);
assert.match(gphy, /\) != 6\) continue/);
assert.match(gphy, /\) != 5\) continue/);
assert.match(gphy, /\) != 4\) continue/);
assert.doesNotMatch(arp, /fopen\(ERP_|doSystem\([^\n]*>/);
assert.doesNotMatch(gphy, /fopen\(ERP_|doSystem\([^\n]*>/);

console.log('erp_monitor scratch-file and parser-bound checks passed');