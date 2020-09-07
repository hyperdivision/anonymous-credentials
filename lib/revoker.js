const curve = require('./curve')
const hash = require('./challenge')
const assert = require('nanoassert')
const Identifier = require('./identifier')
const { verifyWitness } = require('./verify')
const Accumulator = require('./accumulator')
const { AccumulatorPublicKey, WitnessProof } = require('../wire')

const { F, F12, G1, G2 } = curve

module.exports = class Revoker {
  constructor (opts = { secrets: {} }) {
    this.acc = opts.acc || new Accumulator()
    this.users = opts.users || []
    this.revoked = opts.revoked || []
    
    this.secrets = {}
    this.secrets.alpha = this.acc.alpha
    this.secrets.xi1 = opts.secrets.xi1 || curve.randomScalar()
    this.secrets.xi2 = opts.secrets.xi2 || curve.randomScalar()

    this.pubkey = new AccumulatorPublicKey({
      g1: this.acc.g1,
      g2: this.acc.g2,
      secrets: this.secrets,
      current: this.acc.current
    })

    this.history = [[ this.acc.current, Date.now() ]]
  }

  issueIdentifier (k) {
    if (k === undefined) return this.issueIdentifier(curve.randomScalar())

    const id = this.acc.new(k)

    const identifier = new Identifier(id, this.pubkey)
    this.users.push(id)

    return identifier
  }

  open (identifier) {
    const { witness, challenge } = identifier

    const acc = this.history.find((_, i, arr) => witness.timestamp < arr[i + 1])
    const pubkey = acc === undefined
      ? this.pubkey
      : new AccumulatorPublicKey({
        g1: this.g1,
        g2: this.g2,
        secrets: this.secrets,
        current: acc[0]
      })

    assert(verifyWitness(witness, this.pubkey, challenge), 'opening failed: invalid signature')

    const { C, C1, C2 } = witness

    const C1xi1 = G1.mulScalar(C1, this.secrets.xi1)
    const C2xi2 = G1.mulScalar(C2, this.secrets.xi2)

    return G1.sub(C, G1.add(C1xi1, C2xi2))
  }

  revoke (y) {
    const acc = this.acc.current

    this.acc.add(y)

    this.history.push([ this.acc.current, Date.now() ])

    this.pubkey.acc = this.acc.current
    this.pubkey.e.vg = curve.pairing(this.acc.current, this.pubkey.g2)

    return {
      acc,
      y
    }
  }

  getPubkey () {
    return this.pubkey
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    this.acc.encode(buf, offset)
    offset += this.acc.encode.bytes

    encodeUserArray(this.users, buf, offset)
    offset += encodeUserArray.bytes

    encodeUserArray(this.revoked, buf, offset)
    offset += encodeUserArray.bytes

    curve.encodeG1(this.pubkey.u, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeScalar(this.secrets.xi1, buf, offset)
    offset += curve.encodeScalar.bytes

    curve.encodeScalar(this.secrets.xi2, buf, offset)
    offset += curve.encodeScalar.bytes 

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const opts = {}
    opts.secrets = {}

    opts.acc = Accumulator.decode(buf, offset)
    offset += Accumulator.decode.bytes

    opts.users = decodeUserArray(buf, offset)
    offset += decodeUserArray.bytes

    opts.revoked = decodeUserArray(buf, offset)
    offset += decodeUserArray.bytes

    opts.u = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    opts.secrets.xi1 = curve.decodeScalar(buf, offset)
    offset += curve.decodeScalar.bytes

    opts.secrets.xi2 = curve.decodeScalar(buf, offset)
    offset += curve.decodeScalar.bytes 

    this.encode.bytes = offset - startIndex
    return new Revoker(opts)
  }

  encodingLength () {
    let len = 0

    len += this.acc.encodingLength()
    len += 8
    for (let user of this.users) len += user.encodingLength()
    for (let user of this.revoked) len += user.encodingLength()
    len += 160

    return len
  }
}

function encodeUserArray (arr, buf, offset) {
  if (!buf) throw new Error()
  if (!offset) offset = 0
  const startIndex = offset

  buf.writeUInt32LE(arr.length, offset)
  offset += 4

  for (let item of arr) {
    item.encode(buf, offset)
    offset += item.encode.bytes
  }

  encodeUserArray.bytes = offset - startIndex
  return buf
}

function decodeUserArray (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  const arr = []
  const len = buf.readUInt32LE(offset)
  offset += 4

  for (let i = 0; i < len; i++) {
    arr.push(User.decode(buf, offset))
    offset += User.decode.bytes
  }

  decodeUserArray.bytes = offset - startIndex
  return arr
}