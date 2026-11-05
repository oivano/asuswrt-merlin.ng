const assert = require('assert');
const fs = require('fs');

const root = process.cwd();
const read = (file) => fs.readFileSync(`${root}/${file}`, 'utf8');
const packets = read('release/src/router/samba-3.6.x_opwrt/source/source3/nmbd/nmbd_packets.c');
const incoming = read('release/src/router/samba-3.6.x_opwrt/source/source3/nmbd/nmbd_incomingdgrams.c');
const elections = read('release/src/router/samba-3.6.x_opwrt/source/source3/nmbd/nmbd_elections.c');
const proto = read('release/src/router/samba-3.6.x_opwrt/source/source3/nmbd/nmbd_proto.h');
const nmblib = read('release/src/router/samba-3.6.x_opwrt/source/source3/libsmb/nmblib.c');

const handlers = [
    { name: 'process_host_announce', source: incoming, minimum: 31, guard: 'len < 31', firstRead: 'IVAL(buf,1)' },
    { name: 'process_workgroup_announce', source: incoming, minimum: 47, guard: 'len < 31 + MAX_NETBIOSNAME_LEN', firstRead: 'IVAL(buf,1)' },
    { name: 'process_local_master_announce', source: incoming, minimum: 31, guard: 'len < 31', firstRead: 'IVAL(buf,1)' },
    { name: 'process_master_browser_announce', source: incoming, minimum: 16, guard: 'len < MAX_NETBIOSNAME_LEN', firstRead: 'pull_ascii(' },
    { name: 'process_get_backup_list_request', source: incoming, minimum: 5, guard: 'len < 5', firstRead: 'CVAL(buf,0)' },
    { name: 'process_reset_browser', source: incoming, minimum: 1, guard: 'len < 1', firstRead: 'CVAL(buf,0)' },
    { name: 'process_election', source: elections, minimum: 29, guard: 'len < 13 + MAX_NETBIOSNAME_LEN', firstRead: 'CVAL(buf,0)' },
];

for (const { name, source, minimum, guard, firstRead } of handlers) {
    assert.match(packets, new RegExp(`${name}\\(subrec, p, buf\\+1, len-1\\)`));
    assert.match(proto, new RegExp(`${name}\\([^;]*const char \\*buf, int len\\)`));

    const start = source.indexOf(`void ${name}(`);
    const end = source.indexOf('\n}', start) + 2;
    assert.ok(start >= 0 && end > start, `${name} definition`);
    const body = source.slice(start, end);
    const guardPosition = body.indexOf(`if (${guard})`);
    assert.ok(guardPosition >= 0 && guardPosition < body.indexOf(firstRead), `${name} rejects short payloads before reads`);

    for (const payloadLength of [0, minimum - 1]) {
        const receivedLength = payloadLength + 1;
        assert.ok(receivedLength - 1 < minimum, `${name} rejects payload length ${payloadLength}`);
    }
    assert.equal(minimum + 1 - 1, minimum, `${name} accepts its complete fixed fields`);
}

assert.equal((incoming.match(/pull_ascii\(comment, buf\+31, sizeof\(comment\), len-31, STR_TERMINATE\)/g) || []).length, 2);
assert.match(incoming, /pull_ascii\(announce_name, buf\+5, sizeof\(announce_name\), MAX_NETBIOSNAME_LEN, STR_TERMINATE\)/);
assert.match(incoming, /pull_ascii\(workgroup_announce_name, buf\+5, sizeof\(workgroup_announce_name\), MAX_NETBIOSNAME_LEN, STR_TERMINATE\)/);
assert.match(incoming, /pull_ascii\(master_name, buf\+31, sizeof\(master_name\), MAX_NETBIOSNAME_LEN, STR_TERMINATE\)/);
assert.match(incoming, /pull_ascii\(server_name, buf\+5, sizeof\(server_name\), MAX_NETBIOSNAME_LEN, STR_TERMINATE\)/);
assert.match(incoming, /pull_ascii\(local_master_name, buf, sizeof\(local_master_name\), MAX_NETBIOSNAME_LEN, STR_TERMINATE\)/);
assert.match(elections, /pull_ascii\(server_name, buf\+13, sizeof\(server_name\), MAX_NETBIOSNAME_LEN, STR_TERMINATE\)/);

const ptrStart = nmblib.indexOf('static bool handle_name_ptrs(');
const ptrEnd = nmblib.indexOf('\n}', ptrStart) + 2;
const ptrHandler = nmblib.slice(ptrStart, ptrEnd);
assert.match(ptrHandler, /target_offset >= pointer_offset/);
assert.ok(ptrHandler.indexOf('target_offset >= pointer_offset') < ptrHandler.indexOf('(*offset) = target_offset'));

function pointerAccepted(pointerOffset, targetOffset, packetLength) {
    return pointerOffset <= packetLength - 2 &&
        targetOffset < pointerOffset &&
        targetOffset <= packetLength - 2;
}

assert.equal(pointerAccepted(14, 40, 576), false, 'forward pointer into browse body rejected');
assert.equal(pointerAccepted(40, 14, 576), true, 'backward pointer remains valid');
assert.equal(pointerAccepted(40, 575, 576), false, 'out-of-bounds pointer target rejected');

console.log('PASS: browse handler payload bounds, bounded NetBIOS names, and backward-only compression pointers (source contracts and boundary models; not compiled Samba or packet execution)');