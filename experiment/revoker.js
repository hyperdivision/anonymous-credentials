const curve = require('../lib/curve')
const sha512 = require('sha512-wasm')
const assert = require('nanoassert')
const { AccumulatorPublicKey, WitnessProof } = require('../wire')

const { F, F12, G1, G2 } = curve

module.exports = {
  verify
}

let R2

module.exports.Revoker = class Revoker {
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

  issueIdentifier () {
    const id = this.acc.new()

    const identifier = new Identifier(id, this.pubkey)
    this.users.push(id)

    return identifier
  }

  open (showing) {
    console.log(showing)
    const acc = this.history.find((_, i, arr) => showing.timestamp < arr[i + 1])
    const pubkey = acc === undefined
      ? this.pubkey
      : new AccumulatorPublicKey({
        g1: this.g1,
        g2: this.g2,
        secrets: this.secrets,
        current: acc[0]
      })

    assert(verify(showing, pubkey), 'opening failed: invalid signature')

    const { T } = showing
    const c = G1.sub(T[2], G1.add(G1.mulScalar(T[0], this.secrets.xi1), G1.mulScalar(T[1], this.secrets.xi2)))
    return c
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

const Identifier = module.exports.Identifier = class Identifier {
  constructor (id = {}, pk) {
    this.y = id.y
    this.w = id.witness || {}
    this.pk = pk
  }

  show () {
    const alpha = curve.randomScalar()
    const beta = curve.randomScalar()
    const gamma = curve.randomScalar()
    const delta = curve.randomScalar()

    const T = []
    T[0] = G1.affine(G1.mulScalar(this.pk.u, alpha))
    T[1] = G1.affine(G1.mulScalar(this.pk.v, beta))
    T[2] = G1.affine(G1.add(this.w.c, G1.mulScalar(this.pk.h, F.add(alpha, beta))))
    T[3] = G1.affine(G1.mulScalar(this.pk.u, gamma))
    T[4] = G1.affine(G1.mulScalar(this.pk.v, delta))
    T[5] = G1.affine(G1.add(G1.mulScalar(this.pk.g1, F.div(this.w.d, F.add(gamma, delta))), this.pk.h))

    const delta1 = F.mul(this.y, alpha)
    const delta2 = F.mul(this.y, beta)

    const blinds = []

    for (let i = 0; i < 7; i++) blinds.push(curve.randomScalar())

    const precomp_r1 = F.neg(F.add(blinds[0], blinds[1]))
    const precomp_r2 = F.add(blinds[5], blinds[6])
    const precomp_r1y_r2 = F.neg(F.add(F.add(blinds[3], blinds[4]), precomp_r2))
    const precomp = F12.mul(F12.exp(this.pk.e.ha, precomp_r1), F12.exp(this.pk.e.hg, precomp_r1y_r2))

    const pairingT2 = curve.pairing(G1.mulScalar(T[2], blinds[2]), this.pk.g2)
    const pairingT5 = curve.pairing(G1.mulScalar(T[5], F.neg(precomp_r2)), this.pk.g2)

    const R = []
    R[0] = G1.affine(G1.mulScalar(this.pk.u, blinds[0]))
    R[1] = G1.affine(G1.mulScalar(this.pk.v, blinds[1]))
    R[2] = F12.div(F12.mul(pairingT2, precomp), pairingT5)
    R[3] = G1.affine(G1.sub(G1.mulScalar(T[0], blinds[2]), G1.mulScalar(this.pk.u, blinds[3])))
    R[4] = G1.affine(G1.sub(G1.mulScalar(T[1], blinds[2]), G1.mulScalar(this.pk.v, blinds[4])))
    R[5] = G1.affine(G1.mulScalar(this.pk.u, blinds[5]))
    R[6] = G1.affine(G1.mulScalar(this.pk.v, blinds[6]))

    // console.log(R)
    const challenge = hash(...T, ...R)
    R2 = R

    const cBlinds = [alpha, beta, this.y, delta1, delta2, gamma, delta].map((scalar, i) => {
      return F.add(blinds[i], F.mul(challenge, scalar))
    })
    console.log('--------------')
    console.log(verify({ T, challenge, cBlinds }, this.pk))
    return new WitnessProof({ T, challenge, cBlinds })
  }

  update (info) {
    const diff = F.sub(info.y, this.y)
    this.w.c = G1.affine(G1.add(info.acc, G1.mulScalar(this.w.c, diff)))
    this.w.d = F.mul(this.w.d, diff)
  }

  encode (buf, offset) {
    console.log(this)
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    curve.encodeScalar(this.y, buf, offset)
    offset += curve.encodeScalar.bytes

    curve.encodeG1(this.w.c, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeScalar(this.w.d, buf, offset)
    offset += curve.encodeScalar.bytes

    this.pk.encode(buf, offset)
    offset += this.pk.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const id = new Identifier()

    id.y = curve.decodeScalar(buf, offset)
    offset += curve.decodeScalar.bytes

    id.w.c = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    id.w.d = curve.decodeScalar(buf, offset)
    offset += curve.decodeScalar.bytes

    id.pk = AccumulatorPublicKey.decode(buf, offset)
    offset += AccumulatorPublicKey.decode.bytes

    Identifier.decode.bytes = offset - startIndex
    return id
  }

  encodingLength () {
    return 160 + this.pk.encodingLength()
  }
}

function verify (showing, pk) {
  console.log(showing)
  // console.log(pk)
  // for (let i of Object.values(pk.e)) console.log(i)
  const { T, R, challenge, cBlinds } = showing

  const pairingT5 = curve.pairing(T[5], pk.g2)
  if (F12.eq(pairingT5, pk.e.hg)) return false

  const precomp_r1 = F.neg(F.add(cBlinds[0], cBlinds[1]))
  const precomp_r2 = F.add(cBlinds[5], cBlinds[6])
  const precomp_r1y = F.neg(F.add(cBlinds[3], cBlinds[4]))
  const precomp_vg_c = F12.exp(pk.e.vg, F.neg(challenge))
  const precomp = F12.mul(F12.exp(pk.e.ha, precomp_r1), F12.exp(pk.e.hg, F.add(precomp_r1y, F.neg(precomp_r2))))

  const pairingT2 = curve.pairing(T[2], G2.add(G2.mulScalar(pk.a, challenge), G2.mulScalar(pk.g2, cBlinds[2])))
  const pairingT5_r2 = F12.exp(pairingT5, precomp_r2)

  const R_ = []
  R_[0] = G1.affine(G1.sub(G1.mulScalar(pk.u, cBlinds[0]), G1.mulScalar(T[0], challenge)))
  R_[1] = G1.affine(G1.sub(G1.mulScalar(pk.v, cBlinds[1]), G1.mulScalar(T[1], challenge)))
  R_[2] = F12.mul(F12.mul(F12.mul(pairingT2, pairingT5_r2), precomp_vg_c), precomp)
  R_[3] = G1.affine(G1.sub(G1.mulScalar(T[0], cBlinds[2]), G1.mulScalar(pk.u, cBlinds[3])))
  R_[4] = G1.affine(G1.sub(G1.mulScalar(T[1], cBlinds[2]), G1.mulScalar(pk.v, cBlinds[4])))
  R_[5] = G1.affine(G1.sub(G1.mulScalar(pk.u, cBlinds[5]), G1.mulScalar(T[3], challenge)))
  R_[6] = G1.affine(G1.sub(G1.mulScalar(pk.v, cBlinds[6]), G1.mulScalar(T[4], challenge)))

  // console.log(R_)

  for (let i = 0; i < 7; i++) {
    try {
      if (!G1.eq(R2[i], R_[i])) console.log(i)
    } catch {
      if (!F12.eq(R2[i], R_[i])) console.log(i)
    }
  }

  const check = hash(...T, ...R_)
  return F.eq(challenge, check)
}

function hash (...elements) {
  const data = Buffer.alloc(63 * 32)
  let offset = 0

  const strings = elements.flatMap((a, i) => {
    try {
      return a.flatMap(b => b.flatMap(c => c.map(n => n.toString(16).padStart('0', 32))))
    } catch {
      return a.map(n => n.toString(16).padStart('0', 32))
    }
  })

  for (let n of strings) {
    data.write(n, offset, 'hex')
    offset += 32
  }

  const digest = sha512().update(data).digest()
  return curve.scalarFrom(digest)
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

class Accumulator {
  constructor ({ g1, g2, product, alpha } = {}) {
    this.alpha = alpha || curve.randomScalar()

    this.g1 = g1 || curve.randomPointG1()
    this.g2 = g2 || curve.randomPointG2()
    this.e = curve.pairing(this.g1, this.g2)

    this.product = product || F.one
    this.current = G1.mulScalar(this.g1, this.product)

    this.add(curve.randomScalar())
    this.add(curve.randomScalar())
  }

  new () {
    const y = curve.randomScalar()
    const witness = this.genWitness(y)

    return {
      y,
      witness
    }
  }

  genWitness (y_) {
    const y_plusa = F.add(this.alpha, y_)

    const witness = {}

    witness.d = F.mod(this.product, y_plusa)
    assert(!F.eq(witness.d, 0n), 'cannot generate non-membership witness for a member')

    this.y_a = y_plusa
    const exponent = F.div(F.sub(this.product, witness.d), y_plusa)

    witness.c = G1.mulScalar(this.g1, exponent)

    return witness
  }

  add (y) {
    const yplusa = F.add(this.alpha, y)
    this.product = F.mul(this.product, yplusa)
    this.current = G1.mulScalar(this.current, yplusa)

    return y
  }

  verifyWitness (w, y) {
    const g_yg_a = G2.mulScalar(this.g2, F.add(y, this.alpha))

    const pair1 =  curve.pairing(w.c, g_yg_a)
    const pair_d = F12.exp(this.e, w.d)
    
    const lhs = F12.mul(pair1, pair_d)
    const rhs = curve.pairing(this.current, this.g2)

    return F12.eq(lhs, rhs)
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    curve.encodeScalar(this.alpha, buf, offset)
    offset += curve.encodeScalar.bytes

    curve.encodeG1(this.g1, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG2(this.g2, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeScalar(this.product, buf, offset)
    offset += curve.encodeScalar.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const opts = {}

    opts.alpha = curve.decodeScalar(buf, offset)
    offset += curve.decodeScalar.bytes

    opts.g1 = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    opts.g2 = curve.decodeG2(buf, offset)
    offset += curve.decodeG1.bytes

    opts.product = curve.decodeScalar(buf, offset)
    offset += curve.decodeScalar.bytes

    Accumulator.decode.bytes = offset - startIndex
    return new Accumulator(opts)
  }

  encodingLength () {
    return 352
  }
}
