const { EventEmitter } = require('events')
const TrustList = require('./trust-list')

// Routes each outbound connection over the direct transport (fast, holepunched,
// exposes your IP) or the masked transport (Tor/relay, hides your IP, slower),
// according to a TrustList.
//
// Both transports only have to look like hyperdht: a `.connect(publicKey, opts)`
// that returns an encrypted stream. `direct` is normally a HyperDHT instance;
// `masked` is normally a relayed DHT (e.g. `new RelayedDHT(await TorStream
// .connect({ onion }))` from dht-relay-tor), but it can be any overlay — the
// router doesn't care which, so Nym/I2P drop in unchanged.
//
// Default policy: trusted peers go direct, everyone else is masked. Flip it with
// `defaultMode`/`trustedMode` (e.g. direct-by-default, mask only listed peers).

const MODES = ['direct', 'masked']

class TransportRouter extends EventEmitter {
  constructor(opts = {}) {
    super()

    const {
      direct,
      masked = null,
      trust = new TrustList(),
      defaultMode = 'masked',
      trustedMode = 'direct',
      strict = true
    } = opts

    if (!direct || typeof direct.connect !== 'function') {
      throw new Error('a direct transport with .connect() is required')
    }
    if (!MODES.includes(defaultMode) || !MODES.includes(trustedMode)) {
      throw new Error("modes must be 'direct' or 'masked'")
    }

    this.direct = direct
    this.trust = trust
    this.defaultMode = defaultMode
    this.trustedMode = trustedMode
    this.strict = strict

    // masked may be a ready object, an async factory (lazy), or null.
    this._masked = typeof masked === 'function' ? null : masked
    this._maskedFactory = typeof masked === 'function' ? masked : null
    this._ownsMasked = false
  }

  // The policy decision for a key, without connecting. Pure and UI-friendly.
  mode(publicKey) {
    return this.trust.has(publicKey) ? this.trustedMode : this.defaultMode
  }

  // Everything a UI needs to show why a peer will route the way it will.
  describe(publicKey) {
    const { id } = TrustList.key(publicKey)
    return {
      id,
      mode: this.mode(publicKey),
      trusted: this.trust.has(publicKey),
      entry: this.trust.get(publicKey)
    }
  }

  // Resolve a lazy masked factory up front. Safe to call more than once; a no-op
  // when masked is already a ready object or not configured.
  async ready() {
    if (this._masked || !this._maskedFactory) return
    this._masked = await this._maskedFactory()
    this._ownsMasked = true
  }

  connect(publicKey, options = {}) {
    const mode = this.mode(publicKey)
    return mode === 'masked'
      ? this.connectMasked(publicKey, options)
      : this.connectDirect(publicKey, options)
  }

  connectDirect(publicKey, options = {}) {
    return this._emit('direct', publicKey, this.direct.connect(publicKey, options))
  }

  connectMasked(publicKey, options = {}) {
    if (!this._masked) {
      if (this._maskedFactory) {
        throw new Error('masked transport not ready — call await router.ready() first')
      }
      if (this.strict)
        throw new Error('no masked transport configured (refusing to expose IP in strict mode)')
      return this.connectDirect(publicKey, options) // explicit opt-out of privacy
    }
    return this._emit('masked', publicKey, this._masked.connect(publicKey, options))
  }

  _emit(mode, publicKey, connection) {
    const { id } = TrustList.key(publicKey)
    this.emit('connection', { id, mode, publicKey: TrustList.key(publicKey).publicKey, connection })
    return connection
  }

  async destroy() {
    if (this._ownsMasked && this._masked && typeof this._masked.destroy === 'function') {
      await this._masked.destroy()
    }
  }
}

module.exports = TransportRouter
