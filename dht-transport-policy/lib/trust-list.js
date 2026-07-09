const { EventEmitter } = require('events')
const b4a = require('b4a')
const id = require('hypercore-id-encoding')

// A whitelist of trusted peers, keyed by public key.
//
// "Trusted" here means: peers you are willing to reach over the fast/direct
// transport (which exposes your IP to them). Everything not on the list falls
// back to the masked transport. The router (lib/router.js) reads this to decide,
// per connection, whether to holepunch directly or route over Tor/relay.
//
// It is UI-driven: keys go in as hex, z-base-32, or raw buffers; it emits
// 'update' on every change so a front-end can re-render; and toJSON/fromJSON let
// a UI persist and re-import the list (localStorage, a file, a Hyperbee, etc.).

class TrustList extends EventEmitter {
  constructor(entries = []) {
    super()
    this._byId = new Map() // z32 id -> { publicKey, id, alias, note }
    if (entries.length) this.import(entries, { silent: true })
  }

  get size() {
    return this._byId.size
  }

  // Normalise any accepted key form to { publicKey: Buffer, id: z32 string }.
  static key(key) {
    const publicKey = b4a.isBuffer(key) ? id.decode(id.encode(key)) : id.decode(key)
    return { publicKey, id: id.encode(publicKey) }
  }

  has(key) {
    try {
      return this._byId.has(TrustList.key(key).id)
    } catch {
      return false
    }
  }

  get(key) {
    const entry = this._byId.get(TrustList.key(key).id)
    return entry ? { ...entry } : null
  }

  // add(key) or add(key, { alias, note }). Re-adding updates metadata.
  add(key, meta = {}) {
    const { publicKey, id: pid } = TrustList.key(key)
    const prev = this._byId.get(pid)
    const entry = {
      publicKey,
      id: pid,
      alias: meta.alias ?? (prev ? prev.alias : null),
      note: meta.note ?? (prev ? prev.note : null)
    }
    this._byId.set(pid, entry)
    if (!meta.silent) this.emit('update', { type: prev ? 'change' : 'add', entry: { ...entry } })
    return { ...entry }
  }

  remove(key) {
    let pid
    try {
      pid = TrustList.key(key).id
    } catch {
      return false
    }
    const entry = this._byId.get(pid)
    if (!entry) return false
    this._byId.delete(pid)
    this.emit('update', { type: 'remove', entry: { ...entry } })
    return true
  }

  // Bulk import from a UI or a persisted list. Accepts an array of keys or of
  // { publicKey|id|key, alias, note } objects. Emits a single 'update'.
  import(entries, { silent = false } = {}) {
    const added = []
    for (const item of entries) {
      const key =
        typeof item === 'string' || b4a.isBuffer(item)
          ? item
          : (item.publicKey ?? item.id ?? item.key)
      const meta = typeof item === 'object' && !b4a.isBuffer(item) ? item : {}
      added.push(this.add(key, { ...meta, silent: true }))
    }
    if (!silent) this.emit('update', { type: 'import', entries: added })
    return added
  }

  clear() {
    if (this._byId.size === 0) return
    this._byId.clear()
    this.emit('update', { type: 'clear' })
  }

  list() {
    return [...this._byId.values()].map((e) => ({ ...e }))
  }

  // Serialisable form for a UI to persist (public keys as z32 ids).
  toJSON() {
    return this.list().map(({ id, alias, note }) => ({ id, alias, note }))
  }

  static fromJSON(json) {
    return new TrustList(Array.isArray(json) ? json : [])
  }
}

module.exports = TrustList
