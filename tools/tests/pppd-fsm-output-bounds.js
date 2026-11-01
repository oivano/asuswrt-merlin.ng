#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const header = fs.readFileSync(path.join(root, 'release/src/router/pppd/pppd/pppd.h'), 'utf8');
const fsm = fs.readFileSync(path.join(root, 'release/src/router/pppd/pppd/fsm.c'), 'utf8');

assert.match(header, /outpacket_buf\[PPP_MRU\s*\+\s*PPP_HDRLEN\]/);
assert.match(fsm, /maxdatalen\s*=\s*sizeof\(outpacket_buf\)\s*-\s*PPP_HDRLEN\s*-\s*HEADERLEN/);
assert.match(fsm, /if\s*\(datalen\s*>\s*maxdatalen\)\s*datalen\s*=\s*maxdatalen/);
assert.match(fsm, /if\s*\(datalen\s*>\s*peer_mru\[f->unit\]\s*-\s*HEADERLEN\)/);

const pppMru = 1500;
const pppHeaderLength = 4;
const controlHeaderLength = 4;
const bufferSize = pppMru + pppHeaderLength;
const maxDataLength = bufferSize - pppHeaderLength - controlHeaderLength;
const peerMru = 65535;
const clamp = (length) => Math.min(length, peerMru - controlHeaderLength, maxDataLength);

for (const inputLength of [1502, 1500]) {
  const outputLength = clamp(inputLength) + pppHeaderLength + controlHeaderLength;
  assert.strictEqual(outputLength, bufferSize);
  assert(outputLength <= bufferSize);
}

console.log('pppd FSM output-buffer bounds passed');