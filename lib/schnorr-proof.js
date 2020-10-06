const curve = require('./curve')

const rand = curve.Fr.random

module.exports = {
  prove,
  verify
}

// randomOracle should return a hex string
function prove (g, secrets, t, P) {
  if (g[0] instanceof curve.math.Fq12) return proveF12(g, secrets, t, P)

  const scalars = g.map(() => rand())
  const products = g.map((g, i) => g.multiply(scalars[i]))
  const P_ = products.reduce((acc, el) => acc.add(el))

  const blinds = scalars.map((s, i) => s.add(secrets[i].multiply(t)))

  return new SchnorrProof({
    P_,
    blinds
  })
}

function verify (g, P, proof, t) {
  if (g[0] instanceof curve.math.Fq12) return verifyF12(g, P, proof, t)

  const products = g.map((g, i) => g.multiply(proof.blinds[i]))
  var lhs = products.reduce((acc, el) => acc.add(el))

  var tP = P.multiply(t)
  var rhs = proof.P_.add(tP)

  return lhs.equals(rhs)
}

function verifyF12 (g, P, proof, t) {
  const products = g.map((g, i) => g.pow(proof.blinds[i].value))
  var lhs = products.reduce((acc, el) => acc.multiply(el))

  var tP = P.pow(t.value)
  var rhs = proof.P_.multiply(tP)

  return lhs.equals(rhs)
}

class SchnorrProof {
  constructor (opts) {
    this.P_ = opts.P_
    this.blinds = opts.blinds
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    this.P_.encode(buf, offset)
    offset += this.P_.encode.bytes

    curve.encodeScalars(this.blinds, buf, offset)
    offset += curve.encodeScalars.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const proof = {}

    proof.P_ = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    proof.blinds = curve.decodeScalars(buf, offset)
    offset += curve.decodeScalars.bytes

    SchnorrProof.decode.bytes = offset - startIndex
    return proof
  }

  encodingLength () {
    let len = 0

    len += 96
    len += 4
    len += 33 * (this.blinds.length + 1)

    return len
  }
}

module.exports.SchnorrProof = SchnorrProof
