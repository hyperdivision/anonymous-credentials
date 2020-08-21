const curve = require('../lib/curve')
const { Revoker, verify } = require('./revoker')

const org = new Revoker()
// console.log('org pk: ', org.getPubkey())

const id = org.issueIdentifier()
// console.log('id: ', id)

const show = id.show()
// console.log('show: ', show)

console.time('verify')
console.log('initial showing:', verify(show, org.getPubkey()))
console.timeEnd('verify')

console.time('revoke')
const revInfo = org.revoke({ y: curve.randomScalar() })
console.timeEnd('revoke')

console.time('update')
id.update(revInfo)
console.timeEnd('update')

console.time('show')
const show2 = id.show()
console.timeEnd('show')
console.log('second showing:', verify(show2, org.getPubkey()))

const revid = org.open(show2)
const rev = org.revoke(revid)

const revokeShow = id.show()
console.log('revoked show:', verify(revokeShow, org.getPubkey()))

id.update(rev)
const revokeShow2 = id.show()
console.log('revoked show 2:', verify(revokeShow2, org.getPubkey()))
