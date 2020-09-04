const curve = require('../lib/curve')
const hash = require('./challenge')
const assert = require('nanoassert')
const schnorr = require('../lib/schnorr-proof')
const { verifyWitness } = require('../lib/verify')
const { AccumulatorPublicKey, WitnessProof } = require('../wire')

const { F, F12, G1, G2 } = curve

const optsG1 = {
  add: (a, b) => G1.add(a, b),
  mul: (a, b) => G1.mulScalar(a, b),
  eq: (a, b) => G1.eq(a, b)
}

const optsF12 = {
  add: (a, b) => F12.mul(a, b),
  mul: (a, b) => F12.exp(a, b),
  eq: (a, b) => F12.eq(a, b)
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

const Identifier = module.exports.Identifier = class Identifier {
  constructor (id = {}, pk) {
    this.y = id.y
    this.w = id.witness || {}
    this.pk = pk
  }

  prover () {
    const self = this

    const [g0, g1, g2, g3, g4] = this.pk.basepoints

    const blind = [null, null].map(curve.randomScalar)
    const blindSum = F.add(blind[0], blind[1])

    const C1 = G1.affine(G1.mulScalar(this.pk.u, blind[0]))
    const C2 = G1.affine(G1.mulScalar(this.pk.v, blind[1]))
    const C = G1.affine(G1.add(G1.mulScalar(g0, this.y), G1.mulScalar(g1, blindSum)))

    const beta = []
    for (let i = 0; i < 4; i++) beta.push(curve.randomScalar())

    const delta = beta.map(n => F.mul(n, this.y))
    delta[2] = F.mul(this.w.d, beta[2])
    delta[3] = F.mul(this.w.d, beta[3])

    const U = []
    U[0] = G1.affine(G1.add(G1.mulScalar(g0, beta[0]), G1.mulScalar(g1, beta[1])))
    U[1] = G1.affine(G1.add(this.w.c, G1.mulScalar(g1, beta[0])))
    U[2] = G1.affine(G1.add(G1.mulScalar(g2, beta[2]), G1.mulScalar(g3, beta[3])))
    U[3] = G1.affine(G1.mulScalar(g4, F.mul(beta[2], this.w.d)))

    const allSecrets = [F.neg(this.w.d), this.y, blindSum].concat(beta, delta, blind)
    const allScalars = allSecrets.map(curve.randomScalar)

    return {
      U,
      C, C1, C2,
      prove
    }

    function prove (k, challenge) {
      const proofs = []
    
      allSecrets[1] = k
      const blinds = allScalars.map((s, i) => F.add(s, F.mul(challenge, allSecrets[i])))

      const generatorsF12 = [
        self.pk.e.gg,
        curve.pairing(g1, self.pk.a),
        curve.pairing(g1, self.pk.g2),
        F12.inv(curve.pairing(U[1], self.pk.g2))
      ]

      proofs.push(genProof([g0, g1], [3, 4]))
      proofs.push(genProof([self.pk.u], [11]))
      proofs.push(genProof([self.pk.v], [12]))
      proofs.push(genProof([G1.neg(U[0]), g0, g1], [1, 7, 8]))
      proofs.push(genProof([g2, g3], [5, 6]))
      proofs.push(genProof([U[2], g2, g3], [0, 9, 10]))
      proofs.push(genProof([g4], [9]))
      proofs.push(genProof([g0, g1], [1, 2]))
      proofs.push(genProof(generatorsF12, [0, 3, 7, 1], optsF12))

      return {
        U,
        C, C1, C2,
        proofs,
        blinds
      }  
    }
    
    function genProof (generators, indices, { add, mul } = optsG1) {
      const scalars = indices.map(i => allScalars[i])
      const secrets = indices.map(i => allSecrets[i])

      const products = generators.map((g, i) => mul(g, scalars[i]))
      const P_ = products.reduce((acc, el) => add(acc, el))

      return {
        P_, indices
      }
    }
  }

  update (info) {
    const diff = F.sub(info.y, this.y)
    this.w.c = G1.affine(G1.add(info.acc, G1.mulScalar(this.w.c, diff)))
    this.w.d = F.mul(this.w.d, diff)
  }

  encode (buf, offset) {
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

  new (y) {
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
