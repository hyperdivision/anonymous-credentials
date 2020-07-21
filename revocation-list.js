const hyperswarm = require('hyperswarm')
const hypercore = require('hypercore')
const pump = require('pump')
const path = require('path')
const keys = require('./lib/keygen')
const EventEmitter = require('events')

module.exports = class RevocationList extends EventEmitter {
  constructor (storage, certId, opts) {
    super()

    this.certId = typeof certId === 'string' ? Buffer.from(certId, 'hex') : certId
    this.storage =  storage

    this.key = opts ? opts.key : null
    this.feed = null
    this.swarm = null
    this.revokedKeys = []

    // this.ready = thunky(this._ready.bind(this))
  }

  _ready (cb) {

  }

  create (cb) {
    const self = this

    const feed = hypercore(path.join(this.storage, this.certId.toString('hex')), null, {
      valueEncoding: 'binary'
    })

    this.key = feed.key

    const swarm = hyperswarm()

    swarm.join(self.certId, {
      lookup: true,
      announce: true
    })

    feed.on('ready', () => {
      swarm.on('connection', function (socket, info) {
        pump(socket, feed.replicate(true, { live: true }), socket)
      })

      self.feed = feed
      self.swarm = swarm

      cb()
    })
  }

  init (cb) {
    const self = this

    const feed = hypercore(path.join(this.storage, this.certId.toString('hex')), this.key, {
      valueEncoding: 'binary'
    })

    if (this.key === null) this.key = feed.key

    const swarm = hyperswarm()
    swarm.join(self.certId, {
      lookup: true,
      announce: true
    })

    feed.on('ready', () => {
      swarm.on('connection', function (socket, info) {
        pump(socket, feed.replicate(false, { live: true }), socket)
        cb()
      })

      self.feed = feed
      self.swarm = swarm
    })

    feed.on('download', function (i, root) {
      // TODO: remove hardcoded depth
      for (let key of keys.keysFromRoot(root, 256)) {
        self.revokedKeys.push(key.pk)
      }
    })
  }

  serialize (buf, offset) {
    if (!buf) buf = Buffer.alloc(4 + this.revokedKeys.length * 32)
    if (!offset) offset = 0

    buf.writeUInt32LE(this.revokedKeys.length, offset)
    offset += 4

    for (let key of revokedKeys) {
      buf.set(key, offset)
      offset += 32
    }

    this.serialize.bytes = offset - startIndex
    return buf
  }

  add (key, cb) {
    this.feed.append(key, cb)
  }

  // TODO: specify time since last sync / live sync then check
  has (key, opts, cb) {
    for (let revoked of this.revokedKeys) {
      if (Buffer.compare(key, revoked) === 0) return true
    }

    return false
  }
}
