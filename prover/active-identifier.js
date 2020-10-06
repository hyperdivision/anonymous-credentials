const curve = require('../lib/curve')
const { Identifier, SimpleProof, WitnessProof } = require('../lib/wire')
const schnorr = require('../lib/schnorr-proof')

const { G1, F, F12 } = curve

const optsG1 = {
  add: (a, b) => a.add(b),
  mul: (a, b) => a.multiply(b),
}

const optsF12 = {
  add: (a, b) => a.multiply(b),
  mul: (a, b) => a.pow(b.value),
}

module.exports = class ActiveIdentifier extends Identifier {
  prover () {
    const self = this

    const [g0, g1, g2, g3, g4] = this.pk.basepoints

    const blind = [null, null].map(curve.Fr.random)
    const blindSum = blind[0].add(blind[1])

    const C1 = this.pk.u.multiply(blind[0]).normalize()
    const C2 = this.pk.v.multiply(blind[1]).normalize()
    const C = g0.multiply(this.y).add(g1.multiply(blindSum)).normalize()

    const beta = []
    for (let i = 0; i < 4; i++) beta.push(curve.Fr.random())

    const delta = beta.map(n => n.multiply(this.y))
    delta[2] = this.w.d.multiply(beta[2])
    delta[3] = this.w.d.multiply(beta[3])

    const U = []
    U[0] = g0.multiply(beta[0]).add(g1.multiply(beta[1])).normalize()
    U[1] = this.w.c.add(g1.multiply(beta[0])).normalize()
    U[2] = g2.multiply(beta[2]).add(g3.multiply(beta[3])).normalize()
    U[3] = this.w.d.equals(curve.Fr.zero()) 
      ? g4
      : g4.multiply(beta[2].multiply(this.w.d)).normalize()

    const allSecrets = [this.w.d.negate(), this.y, blindSum].concat(beta, delta, blind)
    const allScalars = allSecrets.map(curve.Fr.random)

    return {
      U,
      C,
      C1,
      C2,
      prove
    }

    function prove (k, challenge) {
      const proofs = []

      allSecrets[1] = k
      const blinds = allScalars.map((s, i) => s.add(challenge.multiply(allSecrets[i])))

      const pairingU2 = curve.pairing(U[1], self.pk.a).div(self.pk.e.vg)

      const generatorsF12 = [
        self.pk.e.gg,
        self.pk.e.g1a,
        self.pk.e.g1g2,
        curve.pairing(U[1].negate(), self.pk.g2)
      ]

      proofs.push(genProof([g0, g1], [3, 4]))
      proofs.push(genProof([self.pk.u], [11]))
      proofs.push(genProof([self.pk.v], [12]))
      proofs.push(genProof([U[0].negate(), g0, g1], [1, 7, 8]))
      proofs.push(genProof([g2, g3], [5, 6]))
      proofs.push(genProof([U[2], g2, g3], [0, 9, 10]))
      proofs.push(genProof([g4], [9]))
      proofs.push(genProof([g0, g1], [1, 2]))
      proofs.push(genProof(generatorsF12, [0, 3, 7, 1], optsF12))

      return new WitnessProof({ U, C, C1, C2, proofs, blinds })
    }

    function genProof (generators, indices, { add, mul, enc } = optsG1) {
      const scalars = indices.map(i => allScalars[i])

      const products = generators.map((g, i) => mul(g, scalars[i]))
      const P_ = products.reduce((acc, el) => add(acc, el))

      return new SimpleProof(P_, indices)
    }
  }

  update (info) {
    const diff = info.y.subtract(this.y)
    if (!diff.equals(curve.Fr.zero())) {
      this.w.c = info.acc.add(this.w.c.multiply(diff.value)).normalize()
    }
    this.w.d = this.w.d.multiply(diff)
  }
}
