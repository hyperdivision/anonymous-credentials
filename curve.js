const bn128 = require('ffjavascript').bn128
const ZqField = require("ffjavascript").ZqField
const Scalar = require("ffjavascript").Scalar

const G1 = bn128.G1
const G2 = bn128.G2
const F = new ZqField(bn128.r)

const order = G1.r
const fieldOrder = G1.q
const F1 = bn128.F1
const F2 = bn128.F2
const F12 = bn128.F12

function scalarFrom (arr) {
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

module.exports = {
  G1,
  G2,
  F,
  F1,
  F2,
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
  verifyPairEq
}
