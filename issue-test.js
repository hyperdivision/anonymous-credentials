const issuer = require('./issuer')
const User = require('./user')
const verify = require('./verifier')
const attributes = require('./gen-attributes')
const bn128 = require('ffjavascript').bn128
const curve = require('./curve')

const attr = attributes.map(['age: 66', 'nationality: holland', 'residence: denmark', 'drivers licence', 'employed', 'gender: female'])
const attr1 = attributes.map(['age', 'nationality', 'residence', 'drivers licence', 'employed', 'gender'])

const alice = issuer(attr)
const bob = new User(attr)

const init = alice.one()
const res = bob.issuance(init)
const final = alice.two(res)

bob.store(final)

const disclosed = attributes.map(['age: 66', 'residence: denmark', 'gender: female'])
const attrs = disclosed.map(k => [k, attr.indexOf(k) + 1])

const sig = bob.show(disclosed)

const success = verify(sig, alice.getPk(), attrs)
console.log(success)

// console.log(JSON.stringify(bob.credential, function (key, value) {
//   if (typeof value === 'bigint') return value.toString(16)
//   if (Array.isArray(value)) return value.reduce((s, n) => s + n.length, 0)
//   return value
// }))
