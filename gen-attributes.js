const curve = require('./curve')

// module.exports = function (attr) {
//   return attr.map(a => curve.scalarFrom(Buffer.from(a).toString('hex'), 16))
// }

function format (attrs) {
  const k = attrs.map(encode)

  const ret = {}
  for (let i = 0; i < attrs.length; i++) ret[attrs[i]] = k[i]
  return ret
}

function encode (attr) {
  return curve.scalarFrom(Buffer.from(attr).toString('hex'), 16)
}

function decode (k) {
  return Buffer.from(k.toString(16), 'hex').toString()
}

module.exports = {
  format,
  encode,
  decode
}
