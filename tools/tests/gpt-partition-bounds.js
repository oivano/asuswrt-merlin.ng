const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const kernel = 'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/partitions/';
const source = fs.readFileSync(path.join(root, kernel, 'efi.c'), 'utf8');
const header = fs.readFileSync(path.join(root, kernel, 'efi.h'), 'utf8');
const body = (text, start, end) => {
    const offset = text.indexOf(start);
    assert.ok(offset >= 0, `missing ${start}`);
    const limit = text.indexOf(end, offset + start.length);
    assert.ok(limit > offset, `missing ${end}`);
    return text.slice(offset, limit);
};

const headerStruct = body(header, 'typedef struct _gpt_header {', '} __attribute__ ((packed)) gpt_header;');
const entryStruct = body(header, 'typedef struct _gpt_entry {', '} __attribute__ ((packed)) gpt_entry;');
assert.match(headerStruct, /__le32 partition_entry_array_crc32;/);
assert.match(entryStruct, /efi_char16_t partition_name\[72 \/ sizeof \(efi_char16_t\)\];/);

const headerRead = body(source, 'static gpt_header *alloc_read_gpt_header(', 'static int is_gpt_valid(');
assert.match(headerRead, /if \(ssz < sizeof\(\*gpt\)\)\s*return NULL;/,
    'do not allocate a block too small for the fixed GPT header');

const valid = body(source, 'static int is_gpt_valid(', 'static inline int\nis_pte_valid(');
const headerGuard = valid.match(/if \((header_size < sizeof\(gpt_header\) \|\|\s*header_size > block_size)\)\s*goto fail;/);
assert.ok(headerGuard, 'bound header_size by the fixed header and logical block size');
assert.ok(valid.indexOf(headerGuard[0]) < valid.indexOf('/* Check the GUID Partition Table signature */'));
assert.ok(valid.indexOf(headerGuard[0]) < valid.indexOf('efi_crc32((const unsigned char *) (*gpt), header_size)'));
const rejectHeader = new Function('header_size', 'block_size',
    `return Boolean(${headerGuard[1].replace(/sizeof\(gpt_header\)/g, '92')});`);
for (const size of [0, 91, 513, 0xffffffff])
    assert.equal(rejectHeader(size, 512), true, `reject invalid header_size ${size}`);
assert.equal(rejectHeader(92, 512), false, 'accept the fixed-size GPT v1 header');
assert.equal(rejectHeader(512, 512), false, 'header may occupy the complete logical block');

const sizing = body(source, 'static int gpt_entry_array_size(', 'static gpt_entry *alloc_read_gpt_entries(');
const entryGuard = sizing.match(/if \((entry_size != sizeof\(gpt_entry\) \|\| !num_entries \|\|\s*num_entries > \(size_t\)-1 \/ sizeof\(gpt_entry\))\)\s*return 0;/);
assert.ok(entryGuard, 'require fixed-size entries and guard multiplication overflow');
const rejectEntries = new Function('entry_size', 'num_entries', 'entry_sizeof', 'size_max',
    `return Boolean(${entryGuard[1]
        .replace(/sizeof\(gpt_entry\)/g, 'entry_sizeof')
        .replace(/\(size_t\)-1/g, 'size_max')});`);
const maxSize = 0xffffffff;
assert.equal(rejectEntries(1, 255, 128, maxSize), true, 'reject undersized entries');
assert.equal(rejectEntries(128, 0xffffffff, 128, maxSize), true, 'reject overflowing entry-array size');
assert.equal(rejectEntries(128, 0, 128, maxSize), true, 'reject empty entry arrays');
assert.equal(rejectEntries(128, 255, 128, maxSize), false, 'accept 255 correctly-sized entries');
assert.match(sizing, /\*count = \(size_t\)num_entries \* sizeof\(gpt_entry\);/);

const allocate = body(source, 'static gpt_entry *alloc_read_gpt_entries(', 'static gpt_header *alloc_read_gpt_header(');
assert.match(allocate, /gpt_entry_array_size\(gpt, &count\)/);
assert.match(allocate, /read_lba\(state, le64_to_cpu\(gpt->partition_entry_lba\),\s*\(u8 \*\) pte,\s*count\)/);
assert.match(valid, /gpt_entry_array_size\(\*gpt, &count\)/);
assert.match(valid, /efi_crc32\(\(const unsigned char \*\) \(\*ptes\), count\)/);
assert.match(source, /ptes\[i\]\.starting_lba/,
    'entry indexing remains protected by fixed-size array allocation');

console.log('PASS: GPT header and entry bounds source contracts/models (not kernel execution)');
