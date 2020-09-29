const assert = require('nanoassert')
const curve = require('../lib/curve')
const { F, F12, G1, G2 } = curve

module.exports = class Accumulator {
  constructor ({ g1, g2, product, alpha } = {}) {
    this.alpha = alpha || curve.randomScalar()

    this.g1 = g1 || curve.randomPointG1()
    this.g2 = g2 || curve.randomPointG2()
    this.e = curve.pairing(this.g1, this.g2)

    this.product = product || F.one
    this.current = G1.mulScalar(this.g1, this.product)

    this.add(curve.randomScalar())
    this.add(curve.randomScalar())
  }

  new (y) {
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
    this.current = G1.mulScalar(this.current, yplusa)

    return y
  }

  verifyWitness (w, y) {
    const g_yg_a = G2.mulScalar(this.g2, F.add(y, this.alpha))

    const pair1 =  curve.pairing(w.c, g_yg_a)
    const pair_d = F12.exp(this.e, w.d)
    
    const lhs = F12.mul(pair1, pair_d)
    const rhs = curve.pairing(this.current, this.g2)

    return F12.eq(lhs, rhs)
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    curve.encodeScalar(this.alpha, buf, offset)
    offset += curve.encodeScalar.bytes

    curve.encodeG1(this.g1, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeG2(this.g2, buf, offset)
    offset += curve.encodeG1.bytes

    curve.encodeScalar(this.product, buf, offset)
    offset += curve.encodeScalar.bytes

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    const startIndex = offset

    const opts = {}

    opts.alpha = curve.decodeScalar(buf, offset)
    offset += curve.decodeScalar.bytes

    opts.g1 = curve.decodeG1(buf, offset)
    offset += curve.decodeG1.bytes

    opts.g2 = curve.decodeG2(buf, offset)
    offset += curve.decodeG1.bytes

    opts.product = curve.decodeScalar(buf, offset)
    offset += curve.decodeScalar.bytes

    Accumulator.decode.bytes = offset - startIndex
    return new Accumulator(opts)
  }

  encodingLength () {
    return 352
  }
}
