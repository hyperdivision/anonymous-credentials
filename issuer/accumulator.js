const assert = require('nanoassert')
const curve = require('../lib/curve')
const { F, F12, G1, G2 } = curve

module.exports = class Accumulator {
  constructor ({ g1, g2, product, alpha, init = true } = {}) {
    this.alpha = alpha || curve.Fr.random()

    this.g1 = g1 || curve.PointG1.random()
    this.g2 = g2 || curve.PointG2.random()
    this.e = curve.pairing(this.g1, this.g2)

    this.product = product || curve.Fr.one()
    this.current = this.g1.multiply(this.product)

    if (init) {
      this.add(curve.Fr.random())
      this.add(curve.Fr.random())
    }
  }

  new (y) {
    const witness = this.genWitness(y)

    return {
      y,
      witness
    }
  }

  genWitness (y_) {
    const y_plusa = this.alpha.add(y_)

    const witness = {}

    witness.d = curve.Fr.from(curve.math.mod(this.product, y_plusa))
    assert(!witness.d.equals(curve.math.Fr.ZERO), 'cannot generate non-membership witness for a member')

    this.y_a = y_plusa
    const exponent = this.product.subtract(witness.d).div(y_plusa)

    witness.c = this.g1.multiply(exponent)

    return witness
  }

  add (y) {
    const yplusa = this.alpha.add(y)
    this.product = this.product.multiply(yplusa)
    this.current = this.current.multiply(yplusa)

    return y
  }

  verifyWitness (w, y) {
    const g_yg_a = this.g2.multiply(y.add(this.alpha))

    const pair1 = curve.pairing(w.c, g_yg_a)
    const pair_d = this.e.pow(w.d)

    const lhs = pair1.multiply(pair_d)
    const rhs = curve.pairing(this.current, this.g2)

    return lhs.equals(rhs)
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    this.alpha.encode(buf, offset)
    offset += this.alpha.encode.bytes

    this.g1.encode(buf, offset)
    offset += this.g1.encode.bytes

    this.g2.encode(buf, offset)
    offset += this.g2.encode.bytes

    this.product.encode(buf, offset)
    offset += this.product.encode.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const opts = {}

    opts.alpha = curve.Fr.decode(buf, offset)
    offset += curve.Fr.decode.bytes

    opts.g1 = curve.PointG1.decode(buf, offset)
    offset += curve.PointG1.decode.bytes

    opts.g2 = curve.PointG2.decode(buf, offset)
    offset += curve.PointG2.decode.bytes

    opts.product = curve.Fr.decode(buf, offset)
    offset += curve.Fr.decode.bytes

    opts.init = false

    Accumulator.decode.bytes = offset - startIndex
    return new Accumulator(opts)
  }

  encodingLength () {
    let len = 0

    len += this.alpha.encodingLength()
    len += this.g1.encodingLength()
    len += this.g2.encodingLength()
    len += this.product.encodingLength()
    
    return len
  }
}
