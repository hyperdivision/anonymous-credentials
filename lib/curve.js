const bls = require('noble-bls12-381')
const math = require('noble-bls12-381/math')
const crypto = require('crypto')

const bn128 = require('ffjavascript').bn128
const ZqField = require('ffjavascript').ZqField
const Scalar = require('ffjavascript').Scalar
const utils = require('ffjavascript').utils

const G1 = bn128.G1
const G2 = bn128.G2
const F = new ZqField(bn128.r)

const order = bn128.r
const fieldOrder = bn128.q
const F1 = bn128.F1
const F2 = bn128.F2
const F12 = bn128.F12

class Fq extends math.Fq {
  static random () {
    return new this(arrToBigInt(crypto.randomBytes(48)))
  }

  static from (val) {
    if (typeof val === 'number' || typeof val === 'bigint') return new this((BigInt(val)))

    if (val instanceof Uint8Array) {
      return Fq.from(arrToBigInt(val))
    }

    if (typeof val === 'string') {
      if (val[1] !== 'x') return Fq.from(BigInt('0x' + val))
      return Fq.from(BigInt(val))
    }

    return new Error('unrecoganised format: expect number / bigint / string / Uint8Array')
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.write(this.value.toString(16).padStart(96, '0'), offset, 'hex')
    offset += 48

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    return this.constructor.encodingLength()
  }

  static encodingLength () {
    return 48
  }

  static decode (buf, offset) {
    if (!offset) offset = 0

    Fr.decode.bytes = 48
    return new this(BigInt('0x' + buf.subarray(offset, offset + 48).toString('hex')))
  }
}

class Fr extends math.Fr {
  static random () {
    return new Fr(arrToBigInt(crypto.randomBytes(32)))
  }

  static from (val) {
    if (typeof val === 'number' || typeof val === 'bigint') return new this((BigInt(val)))

    if (val instanceof Uint8Array) {
      return Fr.from(arrToBigInt(val))
    }

    if (typeof val === 'string') {
      if (val[1] !== 'x') return Fr.from(BigInt('0x' + val))
      return Fr.from(BigInt(val))
    }

    return new Error('unrecoganised format: expect number / bigint / string / Uint8Array')
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(this.encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.write(this.value.toString(16).padStart(64, '0'), offset, 'hex')
    offset += 32

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    return this.constructor.encodingLength()
  }

  static encodingLength () {
    return 32
  }

  static decode (buf, offset) {
    if (!offset) offset = 0

    Fr.decode.bytes = 32
    return new this(BigInt('0x' + buf.subarray(offset, offset + 32).toString('hex')))
  }

  static one () {
    return this.from(math.Fr.ONE.value)
  }

  static zero () {
    return this.from(math.Fr.ZERO.value)
  }
}

class PointG1 extends bls.PointG1 {
  static random () {
    const p = this.fromPrivateKey(crypto.randomBytes(48))
    return new this(p.x, p.y, p.z)
  }

  static _fromPoint (p) {
    return new this(p.x, p.y, p.z)
  }

  static mulGen (k) {
    return this._fromPoint(bls.PointG2.BASE.multiply(k))
  }

  normalize () {
    return new this.constructor().fromAffineTuple(this.toAffine())
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(48)
    if (!offset) offset = 0
    var startIndex = offset

    buf.set(this.toCompressedHex(), offset)
    offset += 48

    this.encode.bytes = offset - startIndex
    return buf
  }

  encodingLength () {
    return this.constructor.encodingLength()
  }

  static encodingLength () {
    return 48
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    var startIndex = offset

    const p = super.fromCompressedHex(buf.subarray(offset, offset + 48))
    offset += 48

    PointG1.decode.bytes = offset - startIndex
    return PointG1._fromPoint(p)
  }
}

class PointG2 extends bls.PointG2 {
  static random () {
    const p = this.hashToCurve(crypto.randomBytes(96))
    return new this(p.x, p.y, p.z)
  }

  static _fromPoint (p) {
    return new this(p.x, p.y, p.z)
  }

  static mulGen (k) {
    return this._fromPoint(bls.PointG2.BASE.multiply(k))
  }

  normalize () {
    return new this.constructor().fromAffineTuple(this.toAffine())
  }

  encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(192)
    if (!offset) offset = 0
    var startIndex = offset

    for (let i of this.toAffine()) {
      for (let j of i.c) {
        buf.write(j.value.toString(16).padStart(96, '0'), offset, 'hex')
        offset += 48
      }
    }

    this.encode.bytes = offset - startIndex
    return buf
  }

  static decode (buf, offset) {
    if (!offset) offset = 0
    var startIndex = offset
    
    const p = []
    for (let i = 0; i < 2; i++) {
      const coeffs = []
      for (let j = 0; j < 2; j++) {
        coeffs.push(BigInt('0x' + buf.subarray(offset, offset + 48).toString('hex')))
        offset += 48
      }

      p.push(new math.Fq2(coeffs))
    }

    PointG2.decode.bytes = offset - startIndex
    return new this().fromAffineTuple(p)
  }

  encodingLength () {
    return this.constructor.encodingLength()
  }

  static encodingLength () {
    return 96
  }
}

// TODO: implement random choice properly, should fail above group order

function genG1 () {
  return PointG1.BASE
}

function genG2 () {
  return PointG2.BASE
}

function mulGenG1 (k) {
  return PointG1.BASE.multiply(k)
}

function mulGenG2 (k) {
  return PointG2.BASE.multiply(k)
}

function pairing (a, b) {
  return bls.pairing(a, b)
}

function verifyPairEq ([a, b], [c, d]) {
  var ab = pairing(a, b)
  var cd = pairing(c, d)

  return ab.equals(cd)
}

function encodeF12 (p, buf, offset) {
  // console.log(require('util').inspect(p, false, null, true))
  if (!buf) buf = Buffer.alloc(encodingLengthF12())
  if (!offset) offset = 0
  var startIndex = offset

  for (const m of p.c) {
    for (const l of m.c) {
      for (const i of l.c) {
        buf.write(i.value.toString(16).padStart(96, '0'), offset, 'hex')
        offset += 48
      }
    }
  }

  encodeF12.bytes = offset - startIndex
  return buf
}

function decodeF12 (buf, offset) {
  if (!offset) offset = 0
  var startIndex = offset

  const Fq12 = []
  for (let i = 0; i < 2; i++) {
    const Fq6 = []
    for (let j = 0; j < 3; j++) {
      const Fq2 = []
      for (let k = 0; k < 2; k++) {
        Fq2.push(arrToBigInt(buf.subarray(offset, offset + 48)))
        offset += 48
      }
      Fq6.push(new math.Fq2(Fq2))
    }
    Fq12.push(new math.Fq6(Fq6))
  }

  decodeF12.bytes = offset - startIndex
  return new math.Fq12(Fq12)
}

function encodingLengthF12 () {
  return 12 * 48
}

function encodeScalars (arr, buf, offset) {
  if (!buf) buf = Buffer.alloc(4 + arr.length * 49)
  if (!offset) offset = 0
  const startIndex = offset

  buf.writeUInt32LE(arr.length, offset)
  offset += 4

  for (const k of arr) {
    if (k instanceof Fr) {
      buf.writeUInt8(1, offset++)
    } else if (k instanceof Fq) {
      buf.writeUInt8(2, offset++)
    } else {
      console.log(k instanceof math.Fr)
      throw new Error('unrecognised type: expect Fr or Fq')
    }
    k.encode(buf, offset)
    offset += k.encode.bytes
  }

  encodeScalars.bytes = offset - startIndex
  return buf
}

function decodeScalars (buf, offset, field = 'Fq') {
  if (!offset) offset = 0
  const startIndex = offset

  const len = buf.readUInt32LE(offset)
  offset += 4

  const scalars = []
  for (let i = 0; i < len; i++) {
    let flag = buf.readUInt8(offset++)

    if (flag !== 1 && flag !== 2) throw new Error('unrecognised type: expect Fr or Fq')

    const type = flag === 1 ? Fr : Fq  
    scalars.push(type.decode(buf, offset))
    offset += type.decode.bytes
  }

  decodeScalars.bytes = offset - startIndex
  return scalars
}

function arrToBigInt (arr) {
  let str = ''
  for (let i = 0; i < arr.length; i++) str += arr[i] >> 4 ? arr[i].toString(16) : '0' + arr[i].toString(16)
  return BigInt('0x' + str)
}

module.exports = {
  math,
  bls,
  G1,
  G2,
  F,
  F1,
  F2,
  F12,
  Fq,
  Fr,
  PointG1,
  PointG2,
  bn128,
  genG1,
  genG2,
  mulGenG1,
  mulGenG2,
  order,
  fieldOrder,
  pairing,
  verifyPairEq,
  encodeF12,
  decodeF12,
  encodingLengthF12,
  encodeScalars,
  decodeScalars
}
