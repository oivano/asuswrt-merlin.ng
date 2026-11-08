#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');

const source = fs.readFileSync(
    'release/src/router/busybox/util-linux/volume_id/ntfs.c',
    'utf8'
);
const utilSource = fs.readFileSync(
    'release/src/router/busybox/util-linux/volume_id/util.c',
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

assert(source.includes('mft_record_shift < 9 || mft_record_shift > 16'),
    'negative MFT record exponents must be within the supported range');
assert(source.includes('mft_record_size > SEEK_BUFFER_SIZE'),
    'the complete MFT record must fit in the seek buffer');
assert(source.includes('mft_cluster > (uint64_t)-1 / cluster_size'),
    'the MFT cluster multiplication must not overflow');
assert(source.includes('mft_off > (uint64_t)-1 - mft_record_extent'),
    'the requested MFT record extent must not overflow');
assert(utilSource.includes('off <= SB_BUFFER_SIZE')
    && utilSource.includes('len <= SB_BUFFER_SIZE - off'),
    'the superblock cache range must be checked without addition overflow');
assert(utilSource.includes('off - id->seekbuf_off <= id->seekbuf_len')
    && utilSource.includes('len <= id->seekbuf_len - (size_t)(off - id->seekbuf_off)'),
    'the seek cache range must be checked without addition overflow');

const HEADER_SIZE = 22;
const ATTR_END = 0xffffffff;
const ATTR_VOLUME_NAME = 0x60;
const SB_BUFFER_SIZE = 0x11000;
const SEEK_BUFFER_SIZE = 0x10000;
const UINT64_MAX = (1n << 64n) - 1n;

function requestedBuffer(off, len) {
    if (off <= BigInt(SB_BUFFER_SIZE)
        && BigInt(len) <= BigInt(SB_BUFFER_SIZE) - off)
        return 'superblock';
    if (len > SEEK_BUFFER_SIZE)
        return null;
    return 'seek';
}

function ntfsRecordOffset(cluster, clusterSize, recordSize) {
    const clusterValue = BigInt(cluster);
    const size = BigInt(clusterSize);
    const extent = 11n * BigInt(recordSize);
    if (!size || clusterValue > UINT64_MAX / size)
        return null;
    const offset = clusterValue * size;
    if (offset > UINT64_MAX - extent)
        return null;
    return offset + 3n * BigInt(recordSize);
}

const nearEndCluster = UINT64_MAX / 4096n;
assert.strictEqual(ntfsRecordOffset(nearEndCluster, 4096, 1024), null,
    'a near-2^64 MFT location with a wrapping record extent must be rejected');
assert.strictEqual(ntfsRecordOffset(nearEndCluster + 1n, 4096, 1024), null,
    'an overflowing MFT cluster multiplication must be rejected');
assert.strictEqual(requestedBuffer(UINT64_MAX - 8n, 16), 'seek',
    'a wrapped superblock request must not be treated as an in-buffer offset');
assert.strictEqual(requestedBuffer(BigInt(SB_BUFFER_SIZE + 1), SEEK_BUFFER_SIZE + 1), null,
    'oversized seek-buffer reads must remain rejected');
assert.strictEqual(ntfsRecordOffset(1024n, 4096, 1024),
    1024n * 4096n + 3n * 1024n,
    'a valid MFT record location remains addressable');

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
