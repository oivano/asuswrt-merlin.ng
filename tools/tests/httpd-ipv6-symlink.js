const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const web = read('release/src/router/httpd/web.c');
const header = read('release/src/router/httpd/httpd.h');
const arrays = read('release/src/router/httpd/data_arrays.c');
const broadcom = read('release/src/router/httpd/sysdeps/web-broadcom-am.c');
const body = (source, name) => {
    const match = source.match(new RegExp(`\\b${name}\\([^\\n]*\\)\\n\\{([\\s\\S]*?)\\n\\}`));
    assert(match, name);
    return match[1];
};

assert.match(web, /#define IPV6_CLIENT_INFO\s+"\/tmp\/httpd\/ipv6_client_info"/);
assert.match(header, /#define IPV6_CLIENT_LIST\s+"\/tmp\/httpd\/ipv6_client_list"/);
for (const source of [web, header, broadcom])
    assert.doesNotMatch(source, /\/tmp\/ipv6_(?:neigh|client_info|client_list)/);

const openScratch = body(web, 'open_ipv6_scratch');
for (const contract of [
    'httpd_ensure_temp_dir()', 'O_NOFOLLOW', 'fstat(fd, &st)',
    'S_ISREG(st.st_mode)', 'st.st_uid != 0', 'st.st_nlink != 1',
    'ftruncate(fd, 0)'
])
    assert(openScratch.includes(contract), contract);
assert(openScratch.indexOf('st.st_nlink != 1') < openScratch.indexOf('ftruncate(fd, 0)'));

for (const helper of ['init_file', 'save_file']) {
    const code = body(web, helper);
    assert.match(code, /if \(!?fp\)|if \(\(fp =/);
    assert.match(code, /return -1;/);
}

const clientInfo = body(web, 'get_ipv6_client_info');
assert.match(clientInfo, /popen\(command, "r"\)/);
assert.match(clientInfo, /pclose\(fp\)/);
    assert.doesNotMatch(clientInfo, /doSystem\(|IPV6_CLIENT_NEIGH|\s>\s/);
assert.match(arrays, /httpd_ensure_temp_dir\(\) != 0/);
assert.match(broadcom, /httpd_ensure_temp_dir\(\) == 0/);

console.log('httpd IPv6 scratch-file symlink contracts passed');