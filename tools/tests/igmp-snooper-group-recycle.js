'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const sourcePath = path.join(__dirname, '../../release/src/router/snooper/cache.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const match = source.match(/static struct group_entry \*get_group\([\s\S]*?\n}\n\nstatic int isempty_port/);

assert(match, 'get_group() must be present');

const getGroup = match[0];
assert.match(getGroup, /switch_clr_portmap\(group->ea\);\s*memset\(group, 0, sizeof\(\*group\)\);/,
    'recycling must clear the group entry, not the local pointer');
assert.doesNotMatch(getGroup, /memset\s*\(\s*&group\s*,/,
    'recycling must not zero the local group pointer');
assert.match(getGroup, /memset\(group, 0, sizeof\(\*group\)\);\s*}\s*\n\s*init_group\(group\);/,
    'recycled entries must be initialized before reuse');

console.log('IGMP snooper group recycle regression passed');
