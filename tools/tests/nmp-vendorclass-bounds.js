const assert = require('assert');
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const repo = path.resolve(__dirname, '../..');
const sourcePath = path.join(repo, 'release/src/router/rc/dhcpc_vc_query.c');
const makePath = path.join(repo, 'release/src/router/rc/Makefile');
const source = fs.readFileSync(sourcePath, 'utf8');
const makefile = fs.readFileSync(makePath, 'utf8');
const maxEntries = Number(source.match(/#define NMP_VC_MAX_ENTRIES (\d+)/)[1]);
const maxBytes = Number(source.match(/#define NMP_VC_MAX_BYTES (\d+)/)[1]);

assert(makefile.includes('ifeq ($(wildcard ./dhcpc_vc_query.c),)'));
assert(makefile.includes('$(OBJS): | PB'), 'objects must wait for prebuild filtering under -j');
assert(makefile.includes('source=$${source%.o}.c;'));
assert(makefile.includes('if [ -f "$$source" ]; then'));
assert(source.startsWith('#define _GNU_SOURCE\n'));
assert(source.includes('json_object_object_del(root, mac)'));
assert(source.includes('json_object_object_length(root) > NMP_VC_MAX_ENTRIES'));
assert(source.includes('nmp_vc_size(root) > NMP_VC_MAX_BYTES'));
assert(source.includes('json_object_to_file(NMP_VC_JSON_FILE, root)'));
assert(source.includes('strcmp(argv[1], "del")'));
assert(source.includes('O_NOFOLLOW'));

const pbStart = makefile.indexOf('\nPB:\n') + 1;
const pbEnd = makefile.indexOf('\n\nifeq', pbStart);
assert(pbStart > 0 && pbEnd > pbStart, 'PB rule should be extractable for a make behavior test');
const pbRule = makefile.slice(pbStart, pbEnd);
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'nmp-vc-make-'));
try {
    fs.mkdirSync(path.join(fixture, 'prebuild'));
    fs.writeFileSync(path.join(fixture, 'prebuild/dhcpc_vc_query.o'), 'stale-prebuilt');
    fs.writeFileSync(path.join(fixture, 'prebuild/opaque.o'), 'source-less-prebuilt');
    fs.writeFileSync(path.join(fixture, 'dhcpc_vc_query.c'), 'source');
    fs.writeFileSync(path.join(fixture, 'Makefile'), [
        pbRule,
        'OBJS := dhcpc_vc_query.o opaque.o',
        '$(OBJS): | PB',
        'rc: $(OBJS)',
        '\t@test "$$(cat dhcpc_vc_query.o)" = source-built',
        '\t@test "$$(cat opaque.o)" = source-less-prebuilt',
        '%.o: %.c',
        '\t@printf source-built > "$@"',
        '',
    ].join('\n'));

    const make = spawnSync('make', ['-j8', '-f', 'Makefile', 'rc'], {
        cwd: fixture,
        encoding: 'utf8',
    });
    assert.strictEqual(make.status, 0, `parallel make fixture failed: ${make.stderr || make.stdout}`);
} finally {
    fs.rmSync(fixture, { recursive: true, force: true });
}

if (process.argv[2]) {
    const binary = spawnSync('strings', [process.argv[2]], { encoding: 'utf8' });
    assert.strictEqual(binary.status, 0, `unable to inspect built rc: ${binary.stderr || binary.stdout}`);
    assert(binary.stdout.includes('json_object_object_length'));
    assert(binary.stdout.includes('json_object_object_del'));
    assert(!binary.stdout.includes('add_entry'));
    assert(!binary.stdout.includes('write_to_memory'));
}

function serializedSize(entries) {
    return Buffer.byteLength(JSON.stringify(Object.fromEntries(entries)), 'utf8');
}

const store = new Map();
let writes = 0;
let maximumWrite = 0;

function lease(action, mac, vendorclass) {
    let changed = false;
    const priorSize = store.size;
    if (action === 'del' || vendorclass === undefined) {
        changed = store.delete(mac);
    } else {
        const current = store.get(mac);
        if (!current || current.vendorclass !== vendorclass) {
            store.delete(mac);
            store.set(mac, { mac, vendorclass });
            changed = true;
        }
    }

    while (store.size > maxEntries || serializedSize(store) > maxBytes) {
        const oldest = [...store.keys()].find((key) => key !== mac);
        assert.notStrictEqual(oldest, undefined);
        store.delete(oldest);
    }
    if (store.size !== priorSize) changed = true;

    if (changed) {
        const bytes = serializedSize(store);
        assert(bytes <= maxBytes);
        writes++;
        maximumWrite = Math.max(maximumWrite, bytes);
    }
}

for (let index = 0; index < 5000; index++) {
    const suffix = index.toString(16).padStart(6, '0').slice(-6).toUpperCase();
    const mac = `02:00:00:${suffix.slice(0, 2)}:${suffix.slice(2, 4)}:${suffix.slice(4)}`;
    lease('add', mac, 'V'.repeat(255));
    assert(store.size <= maxEntries);
    assert(serializedSize(store) <= maxBytes);
}

const priorWrites = writes;
const retained = store.keys().next().value;
lease('old', retained, store.get(retained).vendorclass);
assert.strictEqual(writes, priorWrites, 'unchanged renewals must not rewrite flash');

lease('del', retained);
assert(!store.has(retained), 'released clients must be removed');

for (let index = 0; index < maxEntries + 8; index++) {
    const suffix = (index + 10000).toString(16).padStart(6, '0').slice(-6).toUpperCase();
    const mac = `02:00:00:${suffix.slice(0, 2)}:${suffix.slice(2, 4)}:${suffix.slice(4)}`;
    store.set(mac, { mac, vendorclass: 'legacy' });
}
const activeMac = store.keys().next().value;
lease('old', activeMac, store.get(activeMac).vendorclass);
assert(store.size <= maxEntries, 'legacy databases must be pruned on lease events');
assert(store.has(activeMac), 'the active lease must survive legacy pruning');
assert(maximumWrite <= maxBytes, 'each serialized write must respect the byte ceiling');
assert(writes > 0);

console.log(`ok: 5000 MAC churn events bounded to ${maxEntries} entries / ${maxBytes} serialized bytes`);