const revoker = require('./revoker')

const org = revoker.Issuer()
// console.log('org pk: ', org.getPubkey())

const id = org.issue()
// console.log('id: ', id)

const show = revoker.show(id, org.getPubkey())
console.log('show: ', show)

console.log(revoker.verify(show, org.getPubkey()))

const revid = org.open(show)
console.log('user id: ', revid)

