const sha512 = require('sha512-wasm')
const curve = require('./curve')

const F = curve.F
const G1 = curve.G1
const rand = curve.randomScalar

module.exports = {
  prover,
  encode,
  decode,
  encodingLength
}

// randomOracle should return a hex string
function prover (generators, randomOracle) {
  if (!randomOracle) randomOracle = oracle
  if (randomOracle instanceof Uint8Array) return prover(generators, () => randomOracle)

  function genProof (secrets) {
    const scalars = generators.map(rand)

    const products = generators.map((g, i) => G1.mulScalar(g, scalars[i]))
    const P_ = products.reduce((acc, el) => G1.add(acc, el))

    var t = curve.scalarFrom(randomOracle(P_[0].toString(16)))

    const blinds = scalars.map((s, i) => F.add(s, F.mul(t, secrets[i])))

    return {
      P_, blinds, t
    }
  }

  function verify (P, proof) {
    const t = curve.scalarFrom(randomOracle(proof.P_[0].toString(16)))

    const products = generators.map((g, i) => G1.mulScalar(g, proof.blinds[i]))
    var lhs = products.reduce((acc, el) => G1.add(acc, el))

    var tP = G1.mulScalar(P, t)
    var rhs = G1.add(proof.P_, tP)

    return G1.eq(lhs, rhs)
  }

  return {
    genProof,
    verify
  }
}

function oracle (data) {
  return sha512().update(Buffer.from(data)).digest('hex')
}

function encode (proof, buf, offset) {
  if (!buf) buf = Buffer.alloc(encodingLength(proof))
  if (!offset) offset = 0
  const startIndex = offset

  curve.encodeG1(proof.P_, buf, offset)
  offset += curve.encodeG1.bytes

  buf.writeUInt32LE(proof.blinds.length, offset)
  offset += 4

  for (let k of proof.blinds) {
    curve.encodeScalar(k, buf, offset)
    offset += curve.encodeScalar.bytes
  }

  curve.encodeScalar(proof.t, buf, offset)
  offset += curve.encodeScalar.bytes

  encode.bytes = offset - startIndex
  return buf
}

function decode (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  const proof = {}

  proof.P_ = curve.decodeG1(buf, offset)
  offset += curve.decodeG1.bytes

  const blindLen = buf.readUInt32LE(offset)
  offset += 4

  proof.blinds = []
  for (let i = 0; i < blindLen; i++) {
    proof.blinds.push(curve.decodeScalar(buf, offset))
    offset += curve.decodeScalar.bytes
  }

  proof.t = curve.decodeScalar(buf, offset)
  offset += curve.decodeScalar.bytes

  decode.bytes = offset - startIndex
  return proof
}

function encodingLength (proof) {
  let len = 0

  len += 96
  len += 4
  len += 32 * (proof.blinds.length + 1)

  return len
}
