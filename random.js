const BigInteger = require('./lib/BigInteger')
const curve = require('./curve')
const hash = require('sha512-wasm')

var src = Buffer.alloc(64)
hash().update((Math.random() * 10 ** 8).toString(16)).digest(src)

module.exports = function () {
  var ret
  do {
    hash().update(src).digest(src)
    ret = new BigInteger(src.toString('hex'), 16).mod(curve.order)
  } while (ret > curve.order)

  return ret
}
