const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const clientSource = read('release/src/router/www/client_function.js');
const webSource = read('release/src/router/httpd/web.c');
const servicesSource = read('release/src/router/rc/services.c');
const clientsPage = read('release/src/router/www/device-map/clients.asp');
const callbackSource = clientSource.match(/function clientListItemClick\([^]*?\n\}/);
assert(callbackSource, 'client callback dispatcher exists');

const dropdown = clientSource.slice(clientSource.indexOf('function showDropdownClientList('),
    clientSource.indexOf('function redirectTimeScheduling('));
const itemBuilder = dropdown.match(/var genClientItem = function\(_state\) \{[^]*?\n\t\};/);
assert(itemBuilder, 'dropdown item builder exists');
assert.match(itemBuilder[0], /clientListItemClick\(' \+ i/);
assert.doesNotMatch(itemBuilder[0], /clientName[^\n]*onclick|onclick[^\n]*clientName/);
assert.doesNotMatch(itemBuilder[0], /_callBackFun \+ '\('/);
assert.match(clientSource, /thisClientName = htmlEnDeCode\.htmlEncode\(thisClientName\)/);
assert.match(clientSource, /thisClientNickName = htmlEnDeCode\.htmlEncode\(thisClientNickName\)/);

let alertCalls = 0;
let callbackArgs;
const payload = "');alert(1)//";
const context = {
    clientList: ['00:11:22:33:44:55'],
    window: {},
    htmlEnDeCode: { htmlDecode: value => value.replace(/&#39;/g, "'").replace(/&quot;/g, '"') },
    alert: () => alertCalls++
};
context.clientList[context.clientList[0]] = {
    mac: context.clientList[0], ip: 'offline', name: '&#39;);alert(1)//', nickName: '',
    from: 'nmpClient', isOnline: false
};
context.window.setClientIP = (...args) => { callbackArgs = args; };
vm.createContext(context);
vm.runInContext(callbackSource[0], context);
context.clientListItemClick(0, 'setClientIP', 'name>mac');
assert.deepEqual(callbackArgs, [payload, '00:11:22:33:44:55']);
assert.equal(alertCalls, 0, 'the client name is passed as data, never evaluated');

const filterHelper = webSource.match(/static struct json_object \*filter_client_json_text\([^]*?\n\}/);
assert(filterHelper, 'server-side filter exists');
for (const allowed of ["c >= 'A' && c <= 'Z'", "c >= 'a' && c <= 'z'", "c >= '0' && c <= '9'",
    "c == ' '", "c == '-'", "c == '_'", "c == '('", "c == ')'", "filtered[i] = ' '"])
    assert(filterHelper[0].includes(allowed), `server-side filter includes ${allowed}`);

const databaseStart = webSource.indexOf('ej_get_clientlist_from_json_database(', webSource.indexOf('static struct json_object *filter_client_json_text'));
const databaseEnd = webSource.indexOf('static int\nej_get_all_basic_clientlist', databaseStart);
const databaseHook = webSource.slice(databaseStart, databaseEnd);
for (const field of ['name', 'nickName', 'vendor'])
    assert(databaseHook.includes(`filter_client_json_field(filter_val, "${field}")`));
assert(databaseHook.lastIndexOf('filter_client_json_field(filter_val, "name")') < databaseHook.lastIndexOf('websWrite(wp, "%s", json_object_to_json_string(clients))'));

const basicStart = webSource.indexOf('static int\nej_get_all_basic_clientlist');
const basicHook = webSource.slice(basicStart, webSource.indexOf('#ifdef RTCONFIG_INTERNETCTRL', basicStart));
assert.equal((basicHook.match(/filter_client_json_text\(/g) || []).length, 2,
    'database and custom names are both filtered by the basic client-list hook');

const filterName = value => Array.from(value, character =>
    /[A-Za-z0-9 _()\-]/.test(character) ? character : ' ').join('');
const filtered = filterName(payload);
assert.equal(filtered, ' ) alert(1)  ');
assert.match(filtered, /^[A-Za-z0-9 _()\-]*$/);
assert.doesNotMatch(filtered, /[<'">&]/);

const sharedText = webSource.match(/static void copy_client_json_text\([^]*?\n\}/);
assert(sharedText, 'shared-memory strings use a bounded allowlist copy');
assert(sharedText[0].includes('i < src_size') && sharedText[0].includes('i < dst_size - 1'));
assert(sharedText[0].includes("c == '(' || c == ')' || c == '.' || c == ':'"));

const sharedMemory = webSource.match(/static int get_client_info_shm\([^]*?\n\}/);
assert(sharedMemory, 'httpd validates the client shared-memory permissions');
assert(sharedMemory[0].includes('? 0600 : 0666'));
assert(sharedMemory[0].includes('shmctl(shmid, IPC_SET, &info)'));
assert.doesNotMatch(webSource, /shmget\(\(key_t\)SHMKEY_LAN[^\n]*0666/);

const networkmapStart = servicesSource.slice(servicesSource.indexOf('int start_networkmap(int bootwait)'),
    servicesSource.indexOf('void stop_networkmap(void)'));
assert(networkmapStart.indexOf('secure_networkmap_client_shm()') < networkmapStart.indexOf('_eval(networkmap_argv'));
assert(servicesSource.includes('shmget((key_t)SHMKEY_LAN, sizeof(CLIENT_DETAIL_INFO_TABLE), 0600 | IPC_CREAT)'));
assert(servicesSource.includes('shmctl(shmid, IPC_SET, &info)'));

const detailStart = webSource.indexOf('static int get_client_detail_info(struct json_object *clients, struct json_object *macArray, key_t shmkey){');
const detailEnd = webSource.indexOf('static int ', detailStart + 20);
const clientDetails = webSource.slice(detailStart, detailEnd);
assert(clientDetails.includes('client_count > MAX_NR_CLIENT_LIST'));
for (const field of ['apple_model', 'vendor_name', 'ssid', 'tx_rate', 'rx_rate', 'connect_time', 'ip_method'])
    assert(clientDetails.includes(`copy_client_json_text(${field}`), `${field} is filtered before JSON output`);

assert(clientsPage.includes('htmlEnDeCode.htmlEncode(deviceTitle)'));
assert(clientsPage.includes('htmlEnDeCode.htmlEncode(connectModeTip)'));
const sharedPayload = '"><img src=x onerror=alert(1)>';
const safeSharedPayload = sharedPayload.replace(/[^A-Za-z0-9 _().:-]/g, ' ').slice(0, 127);
assert.doesNotMatch(safeSharedPayload, /[<>"']/);

console.log('PASS: client-list names and networkmap shared-memory fields are bounded/filtered before rendering (source/model checks; not compiled C or hardware)');