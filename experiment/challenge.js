const sha512 = require('sha512-wasm')
const curve = require('../lib/curve')

module.exports = function (...elements) {
  const data = Buffer.alloc(63 * 32)
  let offset = 0

  const strings = elements.flatMap((a, i) => {
    try {
      return a.flatMap(b => b.flatMap(c => c.map(n => n.toString(16).padStart('0', 32))))
    } catch {
      return a.map(n => n.toString(16).padStart('0', 32))
    }
  })

  for (let n of strings) {
    data.write(n, offset, 'hex')
    offset += 32
  }

  const digest = sha512().update(data).digest()
  return curve.scalarFrom(digest)
}
