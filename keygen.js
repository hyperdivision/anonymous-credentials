const curve = require('./curve')

const G2 = curve.G2
const rand = curve.randomScalar

module.exports = function (n) {
  const a = rand()
  const z = rand()

  const _a = []
  for (let i = 0; i < n; i++) _a[i] = rand()

  const q = rand()
  const Q = curve.mulGenG2(q)

  const A = G2.mulScalar(Q, a)
  const Z = G2.mulScalar(Q, z)

  const _A = _a.map(k => G2.mulScalar(Q, k))

  return {
    sk: {
      a, _a, z
    },
    pk: {
      Q, A, _A, Z
    }
  }
}
