const sha512 = require('sha512-wasm')
const curve = require('./curve')

const F = curve.F
const G1 = curve.G1
const rand = curve.randomScalar

module.exports = prover

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
