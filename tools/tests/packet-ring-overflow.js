#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const sourcePath = path.join(__dirname, '../../release/src-rt-6.x.4708/linux/linux-2.6.36/net/packet/af_packet.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const slabPath = path.join(__dirname, '../../release/src-rt-6.x.4708/linux/linux-2.6.36/include/linux/slab.h');
const slabSource = fs.readFileSync(slabPath, 'utf8');
const allocStart = source.indexOf('static char **alloc_pg_vec(');
const ringStart = source.indexOf('static int packet_set_ring(', allocStart);
const ringEnd = source.indexOf('\nstatic ', ringStart + 1);
const allocPgVec = source.slice(allocStart, ringStart);
const packetSetRing = source.slice(ringStart, ringEnd);

assert(allocStart >= 0 && ringStart > allocStart && ringEnd > ringStart,
    'could not locate AF_PACKET ring allocation functions');
assert.match(allocPgVec, /kcalloc\(block_nr,\s*sizeof\(char \*\),\s*GFP_KERNEL\)/,
    'pg_vec pointer array must use overflow-checked kcalloc');
assert(!/kzalloc\(block_nr\s*\*\s*sizeof\(char \*\)/.test(allocPgVec),
    'pg_vec pointer array must not use unchecked multiplication');
assert.match(slabSource, /if \(size != 0 && n > ULONG_MAX \/ size\)\s*return NULL;/,
    'kernel kcalloc must reject element-count multiplication overflow');

const totalSizeGuard = /req->tp_block_size\s*>\s*UINT_MAX\s*\/\s*req->tp_block_nr/;
assert(totalSizeGuard.test(packetSetRing), 'ring total-size overflow guard is missing');
assert(packetSetRing.indexOf('UINT_MAX / req->tp_block_nr') < packetSetRing.indexOf('rb->frames_per_block * req->tp_block_nr'),
    'ring total-size overflow must be checked before the frame-count product');
assert(packetSetRing.indexOf('UINT_MAX / req->tp_block_nr') < packetSetRing.indexOf('alloc_pg_vec(req, order)'),
    'ring total-size overflow must be checked before allocation');
assert.match(source, /case PACKET_RX_RING:\s*case PACKET_TX_RING:/,
    'RX and TX ring options must continue sharing packet_set_ring');

const uintMax = 0xffffffff;
function ringSizeFits(blockSize, blockCount) {
    return blockCount === 0 || blockSize <= Math.floor(uintMax / blockCount);
}
function pointerArraySizeFits(blockCount, pointerSize) {
    return blockCount <= Math.floor(uintMax / pointerSize);
}

assert(!ringSizeFits(4096, 0x40000000), '0x40000000 blocks must be rejected');
assert(!ringSizeFits(4096, 0x40000001), '0x40000001 blocks must be rejected');
assert(!pointerArraySizeFits(0x40000000, 4), 'pointer-array byte size must reject 0x40000000 entries');
assert(!pointerArraySizeFits(0x40000001, 4), 'pointer-array byte size must reject 0x40000001 entries');
assert(ringSizeFits(4096, 8), 'ordinary mmap ring must remain valid');

console.log('AF_PACKET ring overflow checks passed');