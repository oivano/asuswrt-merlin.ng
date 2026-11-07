const assert = require('assert');
const fs = require('fs');

const cases = [
    [
        'release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/netfilter/ip_tables.c',
        'ipt_getinfo',
    ],
    [
        'release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/netfilter/ip6_tables.c',
        'ip6t_getinfo',
    ],
];

for (const [file, type] of cases) {
    const source = fs.readFileSync(file, 'utf8');
    const start = source.indexOf('static int get_info(');
    assert(start >= 0, `${file}: get_info must exist`);
    const openingBrace = source.indexOf('{', start);
    let depth = 0;
    let end = openingBrace;
    for (; end < source.length; end++) {
        if (source[end] === '{') depth++;
        if (source[end] === '}' && --depth === 0) break;
    }
    const body = source.slice(openingBrace, end + 1);
    const pattern = new RegExp(
        `struct ${type} info;[\\s\\S]*?` +
        `memset\\(&info, 0, sizeof\\(info\\)\\);[\\s\\S]*?` +
        `info\\.valid_hooks = t->valid_hooks;[\\s\\S]*?` +
        `strcpy\\(info\\.name, name\\);[\\s\\S]*?` +
        `copy_to_user\\(user, &info, \\*len\\)`
    );
    assert(pattern.test(body), `${file}: get_info reply must be zeroed before copy_to_user`);
}

console.log('IPv4 and IPv6 get_info replies are zero-initialized');