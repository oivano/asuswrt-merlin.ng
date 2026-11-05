const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const state = fs.readFileSync(path.join(root, 'release/src/router/www/state.js'), 'utf8');
const showMenuStart = state.indexOf('function show_menu()');
const showMenuEnd = state.indexOf('\nfunction ', showMenuStart + 1);
const rendererStart = state.indexOf('function showMenuTree(');
const rendererEnd = state.indexOf('\nfunction ', rendererStart + 1);
const showMenu = state.slice(showMenuStart, showMenuEnd);
const renderer = state.slice(rendererStart, rendererEnd);

assert.doesNotMatch(state, /\bSession\b|window\.top\.name|JSON\.parse\(win\.name\)/);
assert.match(showMenu, /require\(\['\/require\/modules\/menuTree\.js'\], function \(menuTree\)/);
assert.match(showMenu, /menuList = menuTree\.list/);
assert.match(showMenu, /menus: menuTree\.exclude\.menus\(\)/);
assert.match(showMenu, /showMenuTree\(menuList, menuExclude\)/);

for (const value of ['curMenu.menuName', 'curMenu.index', 'curMenu.tab[firstEntry].url', 'curTab.tabName', 'curTab.url']) {
    const escapedValue = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    assert.match(renderer, new RegExp(`htmlEnDeCode\\.htmlEncode\\(${escapedValue}\\)`));
}
assert.doesNotMatch(renderer, /menu_code \+= curMenu\.(?:menuName|index|tab\[firstEntry\]\.url)/);
assert.doesNotMatch(renderer, /tab_code \+= curTab\.(?:tabName|url)/);

const encoderStart = state.indexOf('\tfunction htmlEncode(value) {');
const encoderEnd = state.indexOf('\n\tfunction htmlDecode(value)', encoderStart);
const encoderSource = state.slice(encoderStart, encoderEnd);
const entities = { '&': '&amp;', '>': '&gt;', '<': '&lt;', '"': '&quot;', "'": '&#39;' };
const htmlEncode = new Function('charToEntity', 'charToEntityRegex',
    `${encoderSource}\nreturn htmlEncode;`)(entities, /([&<>"'])/g);
const payload = '<img src=x onerror=alert(1)>"\'&';
const encoded = htmlEncode(payload);
assert.equal(encoded, '&lt;img src=x onerror=alert(1)&gt;&quot;&#39;&amp;');
assert.doesNotMatch(encoded, /[<>"']/);

console.log('PASS: menu rendering ignores window.name and escapes bundled menu fields before HTML insertion');