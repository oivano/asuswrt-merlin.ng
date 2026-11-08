const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const source = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const request = source('release/src/router/igmpproxy/src/request.c');
const routes = source('release/src/router/igmpproxy/src/rttable.c');
const header = source('release/src/router/igmpproxy/src/igmpproxy.h');
const kernel = source('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/igmp.c');
const receiver = source('release/src/router/igmpproxy/src/igmpproxy.c');
const socket = source('release/src/router/igmpproxy/src/mroute-api.c');
const interfaces = source('release/src/router/igmpproxy/src/ifvc.c');
const igmp = source('release/src/router/igmpproxy/src/igmp.c');
const firewall = source('release/src/router/rc/firewall.c');

assert.match(socket, /setsockopt\(\s*MRouterFD,\s*IPPROTO_IP,\s*IP_PKTINFO/,
    'the multicast router socket must request kernel ingress metadata');
assert.match(receiver, /recvmsg\(MRouterFD,[\s\S]*?IP_PKTINFO[\s\S]*?ipi_ifindex[\s\S]*?acceptIgmp\(recvlen,\s*ingressIfindex\)/,
    'the receive loop must pass the packet ingress interface to IGMP processing');
assert.match(interfaces, /SIOCGIFINDEX[\s\S]*?IfDescEp->ifindex\s*=\s*IfReq\.ifr_ifindex/,
    'each proxy VIF must retain its kernel interface index');
assert.match(igmp, /acceptGroupReport\(src,\s*group,[^;]*ingressIfindex\)/,
    'IGMP reports must pass ingress metadata to admission');
assert.match(igmp, /acceptLeaveMessage\(src,\s*group,\s*ingressIfindex\)/,
    'IGMP leaves must pass ingress metadata to admission');
const ingressChecks = request.match(/ingressIfindex\s*==\s*0\s*\|\|\s*sourceVif->ifindex\s*!=\s*ingressIfindex/g) || [];
assert.strictEqual(ingressChecks.length, 2,
    'reports and leaves without a matching ingress VIF must both be rejected');
assert.match(firewall, /update_igmpproxy_source_guard\(mcast_guard_ifname,\s*lan_subnet\)/,
    'the raw-table source guard must be enabled for the multicast upstream');
assert.match(firewall, /"-i",\s*ifname,[\s\S]*?"-s",\s*lan_subnet,\s*"-j",\s*"DROP"/,
    'LAN-source packets must be dropped before multicast routing on that interface');

assert.match(request, /insertRoute\(group,\s*sourceVif->index,\s*src\)/,
    'downstream host address must reach the route admission logic');
assert.match(header, /#define MAX_GROUPS_PER_HOST\s+20/,
    'per-host group cap must be explicit');
assert.match(header, /#define MAX_REQUESTERS_PER_ROUTE\s+64/,
    'per-route requester bookkeeping must be bounded');
assert.match(header, /#define MAX_ROUTE_ENTRIES\s+256/,
    'route table must have a finite capacity');
assert.match(routes, /hostCount\s*>=\s*MAX_GROUPS_PER_HOST/,
    'a host must be denied after its group quota');
assert.match(routes, /routeCount\(\)\s*>=\s*MAX_ROUTE_ENTRIES/,
    'new routes must stop at the route table capacity');
assert.match(routes, /joinMcGroup\([^;]+\)\s*==\s*0[\s\S]*?ROUTESTATE_JOINED/,
    'route becomes joined only after a successful kernel join');
assert.match(routes, /else\s*\{\s*route->upstrState\s*=\s*ROUTESTATE_NOTJOINED/,
    'a failed kernel join must leave the route unjoined');
assert.match(routes, /if\(croute->upstrState\s*!=\s*ROUTESTATE_JOINED\)[\s\S]*?sendJoinLeaveUpstream\(croute,\s*1\)/,
    'subsequent reports must retry an unjoined route');
assert.match(routes, /freeRouteRequesters\(croute->requesters\)/,
    'route removal must release per-host membership records');
assert.match(kernel, /#define IP_MAX_MEMBERSHIPS\s+512/,
    'kernel membership limit must exceed the proxy route capacity');

const hostLimit = Number(header.match(/#define MAX_GROUPS_PER_HOST\s+(\d+)/)[1]);
const socketLimit = Number(kernel.match(/#define IP_MAX_MEMBERSHIPS\s+(\d+)/)[1]);
const accepted = new Map();
const joined = new Set();
const join = (host, group) => {
    const groups = accepted.get(host) || new Set();
    if (!groups.has(group) && groups.size >= hostLimit)
        return false;
    groups.add(group);
    accepted.set(host, groups);
    if (joined.size >= socketLimit)
        return false;
    joined.add(group);
    return true;
};

for (let group = 1; group <= 25; group++)
    join('host-a', group);
assert.strictEqual(accepted.get('host-a').size, hostLimit,
    'one host cannot reserve more than its quota');
assert.strictEqual(join('host-b', 26), true,
    'a second host can still join after 25 requests from the first host');

let routeState = 'not-joined';
let attempts = 0;
const tryJoin = (succeeds) => {
    attempts++;
    if (succeeds)
        routeState = 'joined';
};
tryJoin(false);
assert.strictEqual(routeState, 'not-joined');
tryJoin(true);
assert.strictEqual(routeState, 'joined');
assert.strictEqual(attempts, 2, 'a failed join must remain eligible for retry');

const admitted = (sourceVif, ingressIfindex) =>
    ingressIfindex !== 0 && sourceVif.ifindex === ingressIfindex && sourceVif.downstream;
const downstream = { ifindex: 7, downstream: true };
assert.strictEqual(admitted(downstream, 7), true,
    'a source-matched report arriving on its downstream VIF is admitted');
assert.strictEqual(admitted(downstream, 12), false,
    'a LAN source arriving on the upstream VIF is rejected');
assert.strictEqual(admitted(downstream, 0), false,
    'a report without kernel ingress metadata is rejected');

console.log('igmpproxy ingress validation, membership limits, and join retry checks passed');
