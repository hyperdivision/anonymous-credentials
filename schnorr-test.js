const curve = require('./curve')
const schnorr = require('./schnorr-proof')
const crypto = require('crypto')

const rand = curve.randomScalar

const generators = []
const secrets = []
for (let i = 0; i < 10; i++) {
  generators.push(curve.randomPointG1())
  secrets.push(rand())
}

generators[1] = generators[0]
var products = generators.map((g, i) => curve.G1.mulScalar(g, secrets[i]))
var P = products.reduce((acc, el) => curve.G1.add(acc, el))

const challenge = crypto.randomBytes(32)
const prover = schnorr(generators, challenge)
const proof = prover.genProof(secrets)
console.log(proof)

// console.log(d224.curve_mul(d224.element_pow_wind_G1(P, proof.t), proof.P_))
console.log(prover.verify(P, proof))
