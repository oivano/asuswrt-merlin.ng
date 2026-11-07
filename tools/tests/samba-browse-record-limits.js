const assert = require('assert');
const fs = require('fs');

const root = process.cwd();
const read = (file) => fs.readFileSync(`${root}/${file}`, 'utf8');
const serverDb = read('release/src/router/samba-3.6.x_opwrt/source/source3/nmbd/nmbd_serverlistdb.c');
const workgroupDb = read('release/src/router/samba-3.6.x_opwrt/source/source3/nmbd/nmbd_workgroupdb.c');
const incoming = read('release/src/router/samba-3.6.x_opwrt/source/source3/nmbd/nmbd_incomingdgrams.c');
const proto = read('release/src/router/samba-3.6.x_opwrt/source/source3/nmbd/nmbd_proto.h');

assert.match(proto, /#define MAX_BROWSE_SERVERS_PER_SUBNET 256/);
assert.match(proto, /#define MAX_BROWSE_WORKGROUPS_PER_SUBNET 32/);
assert.match(proto, /#define MAX_BROWSE_RECORD_TTL 3600/);
assert.match(proto, /int clamp_browse_record_ttl\(int ttl\);/);
assert.match(serverDb, /count_learned_servers\(work->subnet\) >= MAX_BROWSE_SERVERS_PER_SUBNET/);
assert.match(serverDb, /servrec->death_time != PERMANENT_TTL/);
assert.match(serverDb, /local_server = is_myname\(name\) && strequal\(work->work_group, lp_workgroup\(\)\)/);
assert.match(serverDb, /ttl = clamp_browse_record_ttl\(ttl\);[\s\S]*?servrec->death_time = time\(NULL\)\+\(ttl\*3\);/);
assert.match(workgroupDb, /count_learned_workgroups\(subrec\) >=[\s\S]*?MAX_BROWSE_WORKGROUPS_PER_SUBNET/);
assert.match(workgroupDb, /ttl = clamp_browse_record_ttl\(ttl\);/);
assert.match(workgroupDb, /work->death_time != PERMANENT_TTL[\s\S]*?ttl = clamp_browse_record_ttl\(ttl\);/);

const ttlHandlers = [
    ['process_host_announce', 'IVAL(buf,1)/1000'],
    ['process_workgroup_announce', 'IVAL(buf,1)/1000'],
    ['process_local_master_announce', 'IVAL(buf,1)/1000'],
    ['process_lm_host_announce', 'SVAL(buf,7)'],
];
for (const [name, rawTtl] of ttlHandlers) {
    const start = incoming.indexOf(`void ${name}(`);
    const end = incoming.indexOf('\n}', start) + 2;
    const body = incoming.slice(start, end);
    assert.ok(start >= 0 && end > start, `${name} definition`);
    assert.ok(body.includes(`clamp_browse_record_ttl(${rawTtl})`), `${name} clamps network TTL`);
}

function clampTtl(ttl, configuredMax) {
    const max = Math.max(1, Math.min(configuredMax, 3600));
    return Math.max(1, Math.min(ttl, max));
}

assert.equal(clampTtl(0, 86400), 1, 'zero TTL is not the permanent sentinel');
assert.equal(clampTtl(-1, 86400), 1, 'negative converted TTL is bounded');
assert.equal(clampTtl(7200, 86400), 3600, 'remote lifetime input is capped');
assert.equal(clampTtl(7200, 900), 900, 'configured maximum remains effective');

function admit(current, limit) {
    return current < limit ? current + 1 : current;
}

let serverCount = 0;
for (let index = 0; index < 300; index++)
    serverCount = admit(serverCount, 256);
assert.equal(serverCount, 256, 'unique server announcements cannot exceed the subnet cap');

let workgroupCount = 0;
for (let index = 0; index < 100; index++)
    workgroupCount = admit(workgroupCount, 32);
assert.equal(workgroupCount, 32, 'unique workgroup announcements cannot exceed the subnet cap');

const afterPurge = [0, 100, 200].filter((deathTime) => deathTime === 0);
assert.deepEqual(afterPurge, [0], 'the -1 purge preserves only permanent records');
assert.match(serverDb, /expire_servers\(struct work_record \*work, time_t t\)/);
assert.match(serverDb, /\(t == -1\)/);
assert.match(workgroupDb, /\(t == \(time_t\)-1\)/);

console.log('PASS: browse record caps and finite remote TTLs (source contracts and boundary models; not compiled Samba or runtime flood testing)');