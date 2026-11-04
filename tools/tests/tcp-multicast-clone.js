const assert = require('assert');
const fs = require('fs');
const path = require('path');

const sourcePath = path.join(__dirname, '../../release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/inet_connection_sock.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const functionStart = source.indexOf('struct sock *inet_csk_clone(');
const functionEnd = source.indexOf('\nEXPORT_SYMBOL_GPL(inet_csk_clone);', functionStart);

assert(functionStart >= 0 && functionEnd > functionStart, 'inet_csk_clone definition must exist');

const cloneFunction = source.slice(functionStart, functionEnd);
const listReset = cloneFunction.indexOf('inet_sk(newsk)->mc_list = NULL;');
const securityHook = cloneFunction.indexOf('security_inet_csk_clone(newsk, req);');

assert(listReset >= 0, 'cloned connection sockets must not inherit the listener multicast list');
assert(securityHook > listReset, 'multicast-list ownership must be cleared before clone security hooks');
assert(/if \(newsk != NULL\) \{[\s\S]*inet_sk\(newsk\)->mc_list = NULL;/.test(cloneFunction),
  'only initialize the multicast list after a successful clone');

console.log('TCP/DCCP cloned sockets start with an empty IPv4 multicast list');
