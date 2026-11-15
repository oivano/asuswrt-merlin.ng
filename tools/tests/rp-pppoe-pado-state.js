'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const discovery = fs.readFileSync(path.join(root, 'release/src/router/rp-pppoe/src/discovery.c'), 'utf8');
const plugin = fs.readFileSync(path.join(root, 'release/src/router/rp-pppoe/src/plugin.c'), 'utf8');
const header = fs.readFileSync(path.join(root, 'release/src/router/rp-pppoe/src/pppoe.h'), 'utf8');

function functionBody(source, name) {
    const match = new RegExp(`(?:^|\\n)(?:static\\s+)?(?:void|int)\\s+${name}\\s*\\(`).exec(source);
    assert.ok(match, `missing function ${name}`);
    const open = source.indexOf('{', match.index);
    const close = source.indexOf('\n}\n', open);
    assert.ok(close >= 0, `unterminated function ${name}`);
    return source.slice(open + 1, close);
}

const parsePado = functionBody(discovery, 'parsePADOTags');
assert.match(parsePado, /pc->cookie\.type\s*=\s*htons\(type\)/);
assert.match(parsePado, /memcpy\(pc->cookie\.payload,\s*data,\s*len\)/);
assert.match(parsePado, /pc->relayId\.type\s*=\s*htons\(type\)/);
assert.match(parsePado, /memcpy\(pc->relayId\.payload,\s*data,\s*len\)/);
assert.doesNotMatch(parsePado, /conn->(?:cookie|relayId|seenMaxPayload)\s*=/);
assert.match(parsePado, /pc->maxPayload\s*=\s*mru/);

const waitForPado = functionBody(discovery, 'waitForPADO');
const selection = waitForPado.indexOf('if (pc.acNameOK && pc.serviceNameOK)');
const fitCheck = waitForPado.indexOf('padrPayloadFits', selection);
const commit = waitForPado.indexOf('conn->cookie = pc.cookie', selection);
assert.ok(selection >= 0 && fitCheck > selection && commit > fitCheck,
    'candidate tags must pass PADO selection and PADR sizing before commit');
assert.ok(waitForPado.indexOf('if (pc.gotError)') < commit);
assert.ok(waitForPado.indexOf('if (!pc.seenACName)') < commit);
assert.ok(waitForPado.indexOf('if (!pc.seenServiceName)') < commit);

const fits = functionBody(discovery, 'padrPayloadFits');
assert.match(fits, /ntohs\(cookie->length\)/);
assert.match(fits, /ntohs\(relayId->length\)/);
assert.match(fits, /payload\s*<=\s*MAX_PPPOE_PAYLOAD/);
assert.match(fits, /payload\s*\+\s*PPPOE_OVERHEAD\s*>\s*\(unsigned int\)\s*conn->ifMtu/);

const sendPadr = functionBody(discovery, 'sendPADR');
assert.match(sendPadr, /if\s*\(!padrPayloadFits\([\s\S]*?\)\)\s*\{[\s\S]*?return -1;/);
assert.match(sendPadr, /sendPacket\([\s\S]*?\)\s*<\s*0/);
assert.doesNotMatch(sendPadr, /CHECK_ROOM/);

const discoveryBody = functionBody(discovery, 'discovery');
assert.ok(discoveryBody.indexOf('resetPADORound(conn)') < discoveryBody.indexOf('sendPADI(conn)'));
assert.match(discoveryBody, /if\s*\(sendPADR\(conn\)\s*<\s*0\)\s*\{\s*clearPADOTags\(conn\);[\s\S]*?goto SEND_PADI;/);
assert.match(discovery, /void\s+clearPADOTags\(PPPoEConnection \*conn\)[\s\S]*?memset\(&conn->cookie,\s*0,[\s\S]*?memset\(&conn->relayId,\s*0,/);
assert.match(header, /int ifMtu;/);
assert.match(plugin, /conn->ifMtu\s*=\s*ifr\.ifr_mtu/);

const disconnect = functionBody(plugin, 'PPPOEDisconnectDevice');
assert.ok(disconnect.indexOf('sendPADT(conn, NULL)') < disconnect.indexOf('clearPADOTags(conn)'));

console.log('PPPoE PADO state and PADR bounds contracts passed');
