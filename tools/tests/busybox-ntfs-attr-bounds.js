#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');

const source = fs.readFileSync(
    'release/src/router/busybox/util-linux/volume_id/ntfs.c',
    'utf8'
);
const diskInitial = fs.readFileSync(
    'release/src/router/libdisk/disk_initial.c',
    'utf8'
);
const walkStart = source.indexOf('while (1) {', source.indexOf('volume_id_probe_ntfs'));
const walkEnd = source.indexOf('\n\t}\n', walkStart);
assert(walkStart >= 0 && walkEnd > walkStart, 'NTFS attribute walk must exist');
const walk = source.slice(walkStart, walkEnd);

const recordGuard = walk.indexOf('mft_record_size - attr_off < sizeof(*attr)');
const attrRead = walk.indexOf('attr = (struct file_attribute*) &buf[attr_off]');
const lengthGuard = walk.indexOf('attr_len < sizeof(*attr)');
const advance = walk.indexOf('attr_off += attr_len');
assert(recordGuard >= 0 && recordGuard < attrRead,
    'validate the record offset before dereferencing an attribute');
assert(lengthGuard >= 0 && lengthGuard < advance,
    'validate the attribute length before advancing');
assert(walk.includes('attr_len > mft_record_size - attr_off'),
    'attribute length must fit in the remaining record');
assert(walk.includes('val_len > attr_len - val_off'),
    'label value must fit in its attribute');
assert(/if \(\*nvram_value\)\s*goto ret;/.test(diskInitial),
    'a cached label must bypass another device probe');
assert(/if \(ret == 0\)\s*strcpy\(nvram_value, " "\);\s*nvram_set\(nvram_label, nvram_value\);/.test(diskInitial),
    'an unlabeled device result must be cached');

const HEADER_SIZE = 22;
const ATTR_END = 0xffffffff;
const ATTR_VOLUME_NAME = 0x60;

function walkAttributes(recordSize, startOffset, attributes) {
    const labels = [];
    let offset = startOffset;
    let iterations = 0;
    while (true) {
        if (offset > recordSize || recordSize - offset < HEADER_SIZE)
            break;

        const attr = attributes.get(offset);
        if (!attr || attr.type === ATTR_END)
            break;
        if (attr.length < HEADER_SIZE || attr.length > recordSize - offset)
            break;

        if (attr.type === ATTR_VOLUME_NAME) {
            if (attr.valueOffset >= HEADER_SIZE
                && attr.valueOffset <= attr.length
                && attr.valueLength <= attr.length - attr.valueOffset)
                labels.push(attr.valueLength);
        }

        offset += attr.length;
        iterations++;
        assert(iterations <= Math.floor(recordSize / HEADER_SIZE),
            'valid attributes must make bounded forward progress');
    }
    return labels;
}

const wrappingAttributes = new Map([
    [0x40, { type: 0x80, length: 0x20 }],
    [0x60, { type: 0x80, length: 0xffffffe0 }]
]);
assert.deepStrictEqual(walkAttributes(1024, 0x40, wrappingAttributes), [],
    'wrapping attribute lengths must terminate without a label');

assert.deepStrictEqual(walkAttributes(1024, 1016, new Map()), [],
    'an incomplete attribute header must terminate');
assert.deepStrictEqual(walkAttributes(1024, 0x40, new Map([
    [0x40, { type: 0x80, length: 8 }]
])), [], 'an undersized attribute must terminate');
assert.deepStrictEqual(walkAttributes(1024, 0x40, new Map([
    [0x40, {
        type: ATTR_VOLUME_NAME,
        length: 0x20,
        valueOffset: 0x18,
        valueLength: 0x20
    }]
])), [], 'an out-of-attribute label value must be rejected');
assert.deepStrictEqual(walkAttributes(1024, 0x40, new Map([
    [0x40, {
        type: ATTR_VOLUME_NAME,
        length: 0x20,
        valueOffset: 0x18,
        valueLength: 8
    }]
])), [8], 'a valid bounded label value must remain discoverable');

console.log('NTFS attribute bounds checks passed');
