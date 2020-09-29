const curve = require('../lib/curve')
const { Identifier, SimpleProof, WitnessProof } = require('../lib/wire')

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

module.exports = class ActiveIdentifier extends Identifier {
  constructor (identity, pk) {
    super(identity, pk)
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

      return new WitnessProof({ U, C, C1, C2, proofs, blinds })
    }
    
    function genProof (generators, indices, { add, mul, enc } = optsG1) {
      const scalars = indices.map(i => allScalars[i])
      const secrets = indices.map(i => allSecrets[i])

      const products = generators.map((g, i) => mul(g, scalars[i]))
      const P_ = products.reduce((acc, el) => add(acc, el))

      return new SimpleProof(P_, indices)
    }
  }

  update (info) {
    const diff = F.sub(info.y, this.y)
    this.w.c = G1.affine(G1.add(info.acc, G1.mulScalar(this.w.c, diff)))
    this.w.d = F.mul(this.w.d, diff)
  }
}
