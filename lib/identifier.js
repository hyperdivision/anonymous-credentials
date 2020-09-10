const sodium = require('sodium-native')
const curve = require('./curve')
const util = require('util')

const { G1, G2, F, F12 } = curve

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

module.exports = class Identifier {
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

      return new WitnessProof(U, C, C1, C2, proofs, blinds)
    }
    
    function genProof (generators, indices, { add, mul, enc } = optsG1) {
      const scalars = indices.map(i => allScalars[i])
      const secrets = indices.map(i => allSecrets[i])

      const products = generators.map((g, i) => mul(g, scalars[i]))
      const P_ = products.reduce((acc, el) => add(acc, el))

      return SimpleProof(P_, indices)
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

class SimpleProof {
  constructor (P_, indices, enc) {
    this.P_ = P_
    this.indices = indices
  }

  encode (buf, offset, encoder = curve.encodeG1) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    encoder(this.P_, buf, offset)
    offset += encoder.bytes

    buf.writeUInt8(this.indices.length, offset++)
    for (let i of this.indices) buf.writeUInt8(i, offset++)

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset, decoder = curve.decodeG1) {
    if (!offset) offset = 0
    const startIndex = offset

    const P_ = decoder(buf, offset)
    offset += decoder.bytes

    const indexLen = buf.readUInt8(offset++)

    const indices = []
    for (let i = 0; i < indexLen; i++) {
      proof.indices.push(buf.readUInt8(offset++))
    }

    SimpleProof.decode.bytes = offset - startIndex
    return new SimpleProof(P_, indices)
  }

  encodingLength () {
    return (this.P_.length === 3 ? 96 : 384) + this.indices.length + 1
  }
}

class WitnessProof {
  constructor (U, C, C1, C2, proofs, blinds) {
    this.U =U
    this.C =C
    this.C1 = C1
    this.C2 = C2

    this.proofs = proofs
    this.blinds = blinds
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    curve.encodeG1(this.U, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG1(this.C, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG1(this.C1, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG1(this.C2, buf, offset)
    offset += curve.encodeG1.bytes

    for (let i = 0; i < this.proofs.length - 1; i++) {
      this.proofs[i].encode(buf, offset)
      offset += this.proofs[i].encode.bytes
    }

    this.proofs[8].encode(buf, offset, curve.encodeF12)
    offset += this.proofs[8].encode.bytes

    curve.encodeScalars(this.blinds)
    offset += curve.encodeScalars.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    const witProof = new WitnessProof()

    const U = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    const C = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    const C1 = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    const C2 = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    const proofs = new Array(9)
    for (let i = 0; i < 8; i++) {
      proofs[i] = SimpleProof.decode(buf, offset)
      offset += SimpleProof.decode.bytes
    }

    proofs[9] = SimpleProof.decode(buf, offset, curve.decodeF12)
    offset += SimpleProof.decode.bytes

    const blinds = curve.decodeScalars(this.blinds)
    offset += curve.decodeScalars.bytes

    WitnessProof.decode.bytes = offset - startIndex
    return new WitnessProof(U, C, C1, C2, proofs, blinds)
  }

  encodingLength () {
    return 13 * 32 + 4 * 96 + this.proofs.reduce((acc, p) => acc + p.encodingLength())
  }
}
