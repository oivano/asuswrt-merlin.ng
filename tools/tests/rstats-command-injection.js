const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const rstats = read('release/src/router/rstats/rstats.c');
const cstats = read('release/src/router/cstats/cstats.c');
const web = read('release/src/router/httpd/web.c');

const cursorNormalizer = rstats.slice(
    rstats.indexOf('static void normalize_history_cursor('),
    rstats.indexOf('\nstatic int load_history(', rstats.indexOf('static void normalize_history_cursor('))
);
assert.match(cursorNormalizer, /\*cursor < 0/);
assert.match(cursorNormalizer, /\*cursor >= max/);
assert.match(cursorNormalizer, /\*cursor = 0/);

const loadHistory = rstats.slice(rstats.indexOf('static int load_history('), rstats.indexOf('\n/* Try loading', rstats.indexOf('static int load_history(')));
assert.match(loadHistory, /normalize_history_cursor\(&history\.dailyp, MAX_NDAILY\)/);
assert.match(loadHistory, /normalize_history_cursor\(&history\.monthlyp, MAX_NMONTHLY\)/);
assert.ok(loadHistory.indexOf('normalize_history_cursor') > loadHistory.indexOf('memcpy(&history, &hist'));

const saveData = rstats.slice(rstats.indexOf('static void save_datajs('), rstats.indexOf('\nstatic void save_histjs(', rstats.indexOf('static void save_datajs(')));
assert.match(saveData, /normalize_history_cursor\(&p, max\)/);
assert.ok(saveData.indexOf('normalize_history_cursor') < saveData.indexOf('p = (p + 1) % max'));

const bump = rstats.slice(rstats.indexOf('static void bump('), rstats.indexOf('\n/**', rstats.indexOf('static void bump(')));
assert.match(bump, /if \(max <= 0\) return;/);
assert.match(bump, /normalize_history_cursor\(tail, max\)/);
assert.ok(bump.indexOf('normalize_history_cursor') < bump.indexOf('data[t].xtime'));

const dailySize = Number(rstats.match(/#define MAX_NDAILY\s+(\d+)/)[1]);
const monthlySize = Number(rstats.match(/#define MAX_NMONTHLY\s+(\d+)/)[1]);
const normalizeCursor = (cursor, max) => (max <= 0 || cursor < 0 || cursor >= max) ? 0 : cursor;
for (const max of [dailySize, monthlySize]) {
    for (const cursor of [0, max - 1])
        assert.equal(normalizeCursor(cursor, max), cursor, `keep valid cursor ${cursor}/${max}`);
    for (const cursor of [-5, 0x10000000, 0x7fffffff]) {
        const normalized = normalizeCursor(cursor, max);
        assert.equal(normalized, 0, `normalize invalid cursor ${cursor}/${max}`);
        assert.ok(normalized >= 0 && normalized < max, `index remains inside ring ${normalized}/${max}`);
    }
}

const rstatsDecomp = rstats.slice(rstats.indexOf('static int decomp('), rstats.indexOf('\nstatic ', rstats.indexOf('static int decomp(') + 1));
const cstatsLoad = cstats.slice(cstats.indexOf('static int load_history_to_tree('), cstats.indexOf('\nstatic int load_history(', cstats.indexOf('static int load_history_to_tree(')));
for (const [name, source] of [['rstats', rstatsDecomp], ['cstats', cstatsLoad]]) {
    assert.match(source, /fork\(\)/, `${name} starts gzip without a shell`);
    assert.match(source, /execlp\("gzip", "gzip", "-dc", "--", fname, \(char \*\)NULL\)/,
        `${name} passes the history path as one argument`);
    assert.doesNotMatch(source, /\b(system|popen)\s*\(/, `${name} does not invoke a shell`);
    assert.match(source, /O_CREAT \| O_EXCL/, `${name} creates its temporary output exclusively`);
}

const pathValidator = web.match(/int rstats_path_valid\(const char \*path\)\s*\{([^]*?)\n\}/)?.[1];
assert(pathValidator, 'httpd has a dedicated rstats_path validator');
assert.match(pathValidator, /!\*path/);
assert.match(pathValidator, /!strcmp\(path, "\*nvram"\)/);
assert.match(pathValidator, /strncmp\(path, "\/mnt\/", 5\)/);
assert.match(pathValidator, /component\[1\] == '\.'/);
const nvramCheckStart = web.indexOf('int nvram_check(char');
const nvramCheckEnd = web.indexOf('int nvram_check_and_set_for_prefix(', nvramCheckStart);
assert.match(web.slice(nvramCheckStart, nvramCheckEnd),
    /!strcmp\(name, "rstats_path"\) && !rstats_path_valid\(value\)/);

const validPath = value => {
    if (value === '' || value === '*nvram') return true;
    if (!value.startsWith('/mnt/')) return false;
    const components = value.slice(5).split('/');
    if (components.at(-1) === '') components.pop();
    return components.length > 0 && components.every(component =>
        component !== '' && component !== '.' && component !== '..' && /^[A-Za-z0-9_.-]+$/.test(component));
};
for (const value of ['', '*nvram', '/mnt/sda1/', '/mnt/sda1/traffic-history', '/mnt/USB_1/History-2026.gz'])
    assert.equal(validPath(value), true, value);
for (const value of ['/tmp/history/', '/mnt/', '/mnt/sda1/../tmp/', '/mnt/sda1//history/',
    '/mnt/sda1/a;b/', '/mnt/sda1/two words/', '/mnt/sda1/$(id)/', '/mnt/sda1/a`id`/'])
    assert.equal(validPath(value), false, value);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'rstats-literal-path-'));
try {
    const marker = path.join(temporary, 'pwned');
    const directory = path.join(temporary, 'x;touch pwned;');
    fs.mkdirSync(directory);
    const compressed = path.join(directory, 'history.gz');
    const payload = Buffer.from('history bytes\n');
    const encoded = spawnSync('gzip', ['-c'], { input: payload });
    assert.equal(encoded.status, 0, encoded.stderr.toString());
    fs.writeFileSync(compressed, encoded.stdout);
    const decoded = spawnSync('gzip', ['-dc', '--', compressed]);
    assert.equal(decoded.status, 0, decoded.stderr.toString());
    assert.deepEqual(decoded.stdout, payload);
    assert.equal(fs.existsSync(marker), false, 'shell syntax in the path is not executed');
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}

console.log('rstats/cstats command-injection regressions passed');