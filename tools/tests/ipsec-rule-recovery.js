const assert = require('node:assert/strict');
const fs = require('node:fs');

const services = fs.readFileSync('release/src/router/rc/services.c', 'utf8');
const wan = fs.readFileSync('release/src/router/rc/wan.c', 'utf8');
assert(!services.includes('rc_ipsec_config_init();'),
    'do not start IPsec from start_services before WAN setup');
assert.equal((wan.match(/wait_ntp_repeat\(WAIT_FOR_NTP_READY_TIME, WAIT_FOR_NTP_READY_LOOP\); \/\/wait for ntp_ready, for rc_ipsec_config_init\(\)\.\n\s*rc_ipsec_config_init\(\);/g) || []).length, 2,
    'initialize IPsec only after WAN/NTP readiness');

const source = fs.readFileSync('release/src/router/strongswan/src/libcharon/plugins/kernel_netlink/kernel_netlink_net.c', 'utf8');
const start = source.indexOf('static void process_rule(');
const end = source.indexOf('CALLBACK(receive_events', start);
assert(start >= 0 && end > start);
const handler = source.slice(start, end);
assert(handler.includes('hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*msg))'));
assert(handler.includes('memcpy(&table, RTA_DATA(rta), sizeof(table))'));
assert(handler.includes('memcpy(&priority, RTA_DATA(rta), sizeof(priority))'));
assert(handler.includes('manage_rule(this, RTM_NEWRULE, msg->rtm_family, table,'));
assert(handler.includes('this->process_rules && table != RT_TABLE_LOCAL'));
assert.equal((source.match(/if \(this->process_rules \|\| this->routing_table\)/g) || []).length, 2,
    'rule recovery must be subscribed and dispatched even with process_rules disabled');
const shutdown = source.slice(source.indexOf('METHOD(kernel_net_t, destroy, void,'),
    source.indexOf('kernel_netlink_net_t *kernel_netlink_net_create()'));
assert(shutdown.indexOf('DESTROY_IF(this->socket_events)') >= 0 &&
    shutdown.indexOf('DESTROY_IF(this->socket_events)') < shutdown.indexOf('manage_rule(this, RTM_DELRULE'),
    'stop recovery before intentionally removing rules during shutdown');
const ownership = handler.match(/if \((this->routing_table && table == this->routing_table)\)/);
const deletion = handler.match(/if \((hdr->nlmsg_type == RTM_DELRULE[\s\S]*?)\)\s*\{/);
assert(ownership && deletion, 'owned deletion recovery guard must exist');
function expression(value) {
    return value.replace(/this->/g, 'settings.').replace(/hdr->/g, 'event.')
        .replace(/msg->/g, 'event.');
}
const recover = new Function('settings', 'event', 'table', 'priority', 'have_priority',
    'const RTM_DELRULE = 33, AF_INET = 2, AF_INET6 = 10; return Boolean((' +
    expression(ownership[1]) + ') && (' + expression(deletion[1]) + '));');
const settings = { routing_table: 220, routing_table_prio: 220 };
const removed = { nlmsg_type: 33, rtm_family: 2 };
assert(recover(settings, removed, 220, 220, true));
assert(recover(settings, { ...removed, rtm_family: 10 }, 220, 220, true));
assert(!recover(settings, { ...removed, nlmsg_type: 32 }, 220, 220, true));
assert(!recover(settings, removed, 254, 220, true));
assert(!recover(settings, removed, 220, 131, true));
assert(!recover(settings, removed, 220, 220, false));
assert(!recover(settings, { ...removed, rtm_family: 0 }, 220, 220, true));
assert(!recover({ routing_table: 0, routing_table_prio: 220 }, removed, 0, 220, true));
assert(recover({ routing_table: 1000, routing_table_prio: 300 }, removed, 1000, 300, true));

function lookup(rules, destination) {
    if (rules.has(220) && destination !== 'peer') return 'ipsec0';
    return 'vlan4';
}
const rules = new Set([0, 220, 32766, 32767]);
assert.equal(lookup(rules, 'internet'), 'ipsec0');
for (const stage of ['boot', 'renewal']) {
    rules.delete(220);
    assert.equal(lookup(rules, 'internet'), 'vlan4', stage + ' reproduces bypass');
    if (recover(settings, removed, 220, 220, true)) rules.add(220);
    assert.equal(lookup(rules, 'internet'), 'ipsec0');
    assert.equal(lookup(rules, 'peer'), 'vlan4');
}
console.log('IPsec rule recovery: source-derived guards and boot/renewal policy model passed (not compiled C or hardware).');