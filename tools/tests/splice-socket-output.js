#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const sourcePath = path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/fs/splice.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const helperStart = source.indexOf('static ssize_t BCMFASTPATH_HOST do_splice_from_socket');
const helperEnd = source.indexOf('#endif /* CONFIG_BCM_RECVFILE */', helperStart);

assert(helperStart !== -1, 'socket receive helper exists');
assert(helperEnd !== -1, 'socket receive helper has a closing config guard');

const helper = source.slice(helperStart, helperEnd);
const validation = helper.indexOf('if (!mapping || !mapping->a_ops || !mapping->a_ops->write_begin ||');
const writeBegin = helper.indexOf('mapping->a_ops->write_begin(');
const writeEnd = helper.indexOf('mapping->a_ops->write_end(');

assert(validation !== -1, 'helper rejects absent page-cache write operations');
assert(validation < writeBegin, 'validation precedes write_begin');
assert(validation < writeEnd, 'validation precedes write_end');
assert(helper.includes('!mapping->a_ops->write_end'), 'write_end is required too');

console.log('splice socket output guard checks passed');