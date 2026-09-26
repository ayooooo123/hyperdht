'use strict'

// Module-private protocol between the link bootstrap session and its UDX
// owner. Neither symbol is re-exported from the package entry point.
const LINK_BOOTSTRAP_BIND_OWNERSHIP = Symbol('link-bootstrap-bind-ownership')
const LINK_BOOTSTRAP_CONSUME_OWNERSHIP = Symbol('link-bootstrap-consume-ownership')
const LINK_BOOTSTRAP_REGISTER_ESTABLISHED = Symbol('link-bootstrap-register-established')

module.exports = {
  LINK_BOOTSTRAP_BIND_OWNERSHIP,
  LINK_BOOTSTRAP_CONSUME_OWNERSHIP,
  LINK_BOOTSTRAP_REGISTER_ESTABLISHED
}
