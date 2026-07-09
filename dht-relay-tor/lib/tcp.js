const { isBare } = require('which-runtime')

// Pick the runtime's TCP implementation: bare-tcp on Bare, net on Node.
// These are required lazily via the ternary — bare-tcp won't load under Node
// (it needs Bare's native addon loader) and net isn't present on Bare, so we
// must never require both eagerly.
module.exports = isBare ? require('bare-tcp') : require('net')
