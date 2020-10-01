const curve = require('./curve')

const { F, F12, G1 } = curve
const rand = curve.randomScalar

module.exports = {
  prove,
  verify,
  encode,
  decode,
  encodingLength
}

const ops = {}
ops.G1 = {
  add: (a, b) => G1.add(a, b),
  mul: (a, b) => G1.mulScalar(a, b),
  eq: (a, b) => G1.eq(a, b)
}

ops.F12 = {
  add: (a, b) => F12.mul(a, b),
  mul: (a, b) => F12.exp(a, b),
  eq: (a, b) => F12.eq(a, b)
}

// randomOracle should return a hex string
function prove (generators, secrets, t, field = 'G1') {
  const { add, mul } = ops[field]

  const scalars = generators.map(rand)

  const products = generators.map((g, i) => mul(g, scalars[i]))
  const P_ = products.reduce((acc, el) => add(acc, el))

  const blinds = scalars.map((s, i) => F.add(s, F.mul(t, secrets[i])))

  return {
    P_,
    blinds
  }
}

function verify (g, P, proof, blinds, t, field = 'G1') {
  const { add, mul, eq } = ops[field]

  const products = g.map((g, i) => mul(g, blinds[i]))
  var lhs = products.reduce((acc, el) => add(acc, el))

  var tP = mul(P, t)
  var rhs = add(proof.P_, tP)

  return eq(lhs, rhs)
}

function encode (proof, buf, offset) {
  if (!buf) buf = Buffer.alloc(encodingLength(proof))
  if (!offset) offset = 0
  const startIndex = offset

  curve.encodeG1(proof.P_, buf, offset)
  offset += curve.encodeG1.bytes

  buf.writeUInt32LE(proof.blinds.length, offset)
  offset += 4

  for (const k of proof.blinds) {
    curve.encodeScalar(k, buf, offset)
    offset += curve.encodeScalar.bytes
  }

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
