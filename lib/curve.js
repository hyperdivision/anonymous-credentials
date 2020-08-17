const bn128 = require('ffjavascript').bn128
const ZqField = require("ffjavascript").ZqField
const Scalar = require("ffjavascript").Scalar
const utils = require("ffjavascript").utils

const G1 = bn128.G1
const G2 = bn128.G2
const F = new ZqField(bn128.r)

const order = bn128.r
const fieldOrder = bn128.q
const F1 = bn128.F1
const F2 = bn128.F2
const F12 = bn128.F12

function scalarFrom (arr) {
  if (typeof arr === 'number') return scalarFrom(arr.toString(16))

  if (arr instanceof Uint8Array) {
    return F.normalize(Scalar.fromArray(arr, 16))
  } else {
    if (arr[2] !== 'x') return F.normalize(Scalar.fromString('0x' + arr, 16))
    return F.normalize(Scalar.fromString(arr), 16)
  }
}

function randomPointG1 () {
  return G1.mulScalar(G1.g, F.random())
}

function randomPointG2 () {
  return G2.mulScalar(G2.g, F.random())
}

function randomScalar () {
  return F.random()
}

function genG1 () {
  return G1.g
}

function genG2 () {
  return G2.g
}

function modOrder () {
  return G2.g
}

function inverseF1 (a) {
  return F.inv(a)
}

function mulGenG1 (k) {
  return G1.mulScalar(G1.g, k)
}

function mulGenG2 (k) {
  return G2.mulScalar(G2.g, k)
}

function pairing (a, b) {
  return bn128.pairing(a, b)
}

function verifyPairEq ([a, b], [c, d]) {
  var ab = pairing(a, b)
  var cd = pairing(c, d)

  return F12.eq(ab, cd)
}

function encodeG1 (p, buf, offset) {
  if (!buf) buf = Buffer.alloc(96)
  if (!offset) offset = 0
  var startIndex = offset

  for (let i of p) {
    buf.set(utils.beInt2Buff(i, 32), offset)
    offset += 32
  }

  encodeG1.bytes = offset - startIndex
  return buf
}

function decodeG1 (buf, offset) {
  if (!offset) offset = 0
  var startIndex = offset
  const p = []

  for (let i = 0; i < 3; i++) {
    p[i] = utils.beBuff2int(buf.subarray(offset, offset + 32))
    offset += 32
  }

  decodeG1.bytes = offset - startIndex
  return p
}

function encodeG2 (p, buf, offset) {
  if (!buf) buf = Buffer.alloc(192)
  if (!offset) offset = 0
  var startIndex = offset

  for (let i of p) {
    for (let j of i) {
      buf.set(utils.beInt2Buff(j, 32), offset)
      offset += 32
    } 
  }

  encodeG2.bytes = offset - startIndex
  return buf
}

function decodeG2 (buf, offset) {
  if (!offset) offset = 0
  var startIndex = offset
  const p = [[], [], []]

  for (let i = 0; i < 3; i++) {
    for (let j = 0; j < 2; j++) {
      p[i][j] = utils.beBuff2int(buf.subarray(offset, offset + 32))
      offset += 32
    }
  }

  decodeG2.bytes = offset - startIndex
  return p
}

function encodeScalar (k, buf, offset) {
  if (!buf) buf = Buffer.alloc(32)
  if (!offset) offset = 0
  let startIndex = offset

  buf.set(utils.beInt2Buff(k, 32), offset)
  offset += 32

  encodeScalar.bytes = offset - startIndex
  return buf
}

function decodeScalar (buf, offset) {
  if (!offset) offset = 0
  
  decodeScalar.bytes = 32
  return utils.beBuff2int(buf.subarray(offset, offset + 32))
}

function encodeScalars (arr, buf, offset) {
  if (!buf) buf = Buffer.alloc(4 + arr.length * 32)
  if (!offset) offset = 0
  let startIndex = offset
  
  buf.writeUInt32LE(arr.length, offset)
  offset += 4

  for (let k of arr) {
    encodeScalar(k, buf, offset)
    offset += encodeScalar.bytes
  }

  encodeScalars.bytes = offset - startIndex
  return buf
}

function decodeScalars (buf, offset) {
  if (!offset) offset = 0
  let startIndex = offset
  
  let len = buf.readUInt32LE(offset)
  offset += 4

  const scalars = []
  for (let i = 0; i < len; i++) {
    scalars.push(decodeScalar(buf, offset))
    offset += decodeScalar.bytes
  }

  decodeScalars.bytes = offset - startIndex
  return scalars
}

module.exports = {
  G1,
  G2,
  F,
  F1,
  F2,
  F12,
  bn128,
  randomPointG1,
  randomPointG2,
  randomScalar,
  scalarFrom,
  genG1,
  genG2,
  mulGenG1,
  mulGenG2,
  order,
  fieldOrder,
  pairing,
  verifyPairEq,
  encodeG1,
  decodeG1,
  encodeG2,
  decodeG2,
  encodeScalar,
  decodeScalar,
  encodeScalars,
  decodeScalars
}
