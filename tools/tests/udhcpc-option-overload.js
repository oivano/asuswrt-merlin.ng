const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const udhcpDir = path.resolve(__dirname, '../../release/src/router/busybox/networking/udhcp');
const scannerSource = fs.readFileSync(path.join(udhcpDir, 'common.c'), 'utf8');
const headerSource = fs.readFileSync(path.join(udhcpDir, 'common.h'), 'utf8');
const configSource = fs.readFileSync(
    path.resolve(udhcpDir, '../../include/autoconf.h'),
    'utf8'
);
const scanner = scannerSource.match(
    /uint8_t\* FAST_FUNC udhcp_scan_options\([\s\S]*?\n\}/
)?.[0];
assert(scanner, 'DHCP option scanner is present');

const overloadAdvance = scanner.match(
    /if \(scan_state->optionptr\[OPT_CODE\] == DHCP_OPTION_OVERLOAD\) \{[\s\S]*?\n\t\t\} else \{[\s\S]*?\n\t\t\}\n((?:\t\tscan_state->optionptr \+= len;\n)+)/
);
assert(overloadAdvance, 'overload options advance the scanner after processing');
const overloadAdvanceCount = (overloadAdvance[1].match(/optionptr \+= len;/g) || []).length;
assert.equal(overloadAdvanceCount, 1,
    'overload option pointer advances exactly as many bytes as rem consumes');

const optionsSize = Number(headerSource.match(/#define DHCP_OPTIONS_BUFSIZE\s+(\d+)/)?.[1]) +
    Number(configSource.match(/#define CONFIG_UDHCPC_SLACK_FOR_BUGGY_SERVERS\s+(\d+)/)?.[1]);
assert(Number.isInteger(optionsSize) && optionsSize > 0, 'configured options buffer size is known');

function scanOptions(options, overloadAdvances) {
    let pointer = 0;
    let remaining = options.length;
    const returnedCodes = [];

    while (remaining > 0) {
        if (pointer < 0 || pointer >= options.length)
            return { result: 'out-of-bounds', pointer, remaining, returnedCodes };

        const code = options[pointer];
        if (code === 0) {
            pointer++;
            remaining--;
            continue;
        }
        if (code === 255)
            return { result: 'end', pointer, remaining, returnedCodes };
        if (remaining <= 1)
            return { result: 'malformed', pointer, remaining, returnedCodes };

        const length = options[pointer + 1] + 2;
        remaining -= length;
        if (remaining < 0)
            return { result: 'malformed', pointer, remaining, returnedCodes };

        if (code === 52) {
            pointer += overloadAdvances * length;
        } else {
            returnedCodes.push(code);
            pointer += length;
            return { result: 'option', pointer, remaining, returnedCodes };
        }

        if (pointer !== options.length - remaining)
            return { result: 'misaligned', pointer, remaining, returnedCodes };
    }

    return { result: 'malformed', pointer, remaining, returnedCodes };
}

const validOptions = Buffer.alloc(optionsSize, 0);
validOptions.set([52, 1, 3, 54, 4, 192, 0, 2, 1, 255]);
const validResult = scanOptions(validOptions, overloadAdvanceCount);
assert.equal(validResult.result, 'option');
assert.deepEqual(validResult.returnedCodes, [54]);
assert.equal(validResult.pointer, 9);
assert.equal(validResult.remaining, optionsSize - 9);

const malformedOptions = Buffer.alloc(optionsSize, 0x7e);
for (let offset = 0; offset + 2 < optionsSize; offset += 257)
    malformedOptions.set([52, 255, 255], offset);

const malformedResult = scanOptions(malformedOptions, overloadAdvanceCount);
assert.equal(malformedResult.result, 'malformed',
    'oversized overload options stop at the end of the options field');
assert(malformedResult.pointer < optionsSize,
    'malformed overload sequence never reads beyond the options field');
assert.deepEqual(malformedResult.returnedCodes, [],
    'malformed bytes are not returned as DHCP options');

console.log('udhcpc option overload bounds: ok');