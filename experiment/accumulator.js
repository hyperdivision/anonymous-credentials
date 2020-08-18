const assert = require('nanoassert')
const curve = require('../lib/curve')
const { F, F12, G1, G2 } = curve

module.exports = class Accumulator {
  constructor () {
    this.alpha = curve.randomScalar()
    this.acc = G1.g
    this.e = curve.pairing
    this.g1 = curve.randomPointG1()
    this.g2 = curve.randomPointG2()
    this.init = curve.scalarFrom(1)
    this.product = F.one + this.alpha
    this.e = curve.pairing(this.g1, this.g2)

    this.add(1n)
    this.add(curve.randomScalar())
    this.add(curve.randomScalar())
  }

  new () {
    const y = curve.randomScalar()
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
    this.acc = G1.mulScalar(this.g1, this.product)

    return y
  }

  verifyWitness (w, y) {
    const g_yg_a = G2.mulScalar(this.g2, F.add(y, this.alpha))

    const pair1 =  curve.pairing(w.c, g_yg_a)
    const pair_d = F12.exp(this.e, w.d)
    
    const lhs = F12.mul(pair1, pair_d)
    const rhs = curve.pairing(this.acc, this.g2)

    return F12.eq(lhs, rhs)
  }
}
