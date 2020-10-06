const sha512 = require('sha512-wasm')
const curve = require('./curve')

module.exports = function (...elements) {
  let data = ''
  for (let el of elements) {
    if (!(el instanceof curve.PointG1 || el instanceof curve.PointG2)) {
      throw new Error(el)
    }
    data += el.toAffine()[0].toString(16)
  }

  const digest = sha512().update(data, 'hex').digest()
  return curve.Fr.from(digest)
}
