/** Every library in the comparison, in the order the tables list them. */
const casl = require('./casl.js');

const ADAPTERS = [
  require('./kerberos.js'),
  casl.prebuilt,
  casl.perRequest,
  require('./casbin.js'),
  require('./accesscontrol.js'),
  require('./easy-rbac.js'),
  require('./rbac.js'),
  require('./opa-wasm.js'),
  require('./opa-server.js'),
  require('./cerbos.js'),
];

function getAdapter(id) {
  const adapter = ADAPTERS.find((candidate) => candidate.id === id);
  if (!adapter) throw new Error(`unknown adapter "${id}" (known: ${ADAPTERS.map((a) => a.id).join(', ')})`);
  return adapter;
}

module.exports = { ADAPTERS, getAdapter };
