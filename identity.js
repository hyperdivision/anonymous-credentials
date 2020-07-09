const sodium = require('sodium-native')
const keygen = require('./keygen')
const Credential = require('./credential')

module.exports = class {
  constructor (attrs) {
    this.credential = new Credential(Object.keys(attrs).length)
    this.root = null
    this.pseudonym = null
    this.attributes = attrs
  }

  finalize ({ identity, info }) {
    this.root = identity.root
    this.pseudonym = Pseudonym(this.root, identity.sigs)
    this.credential.finalize(info)
  }
}

function Pseudonym (root, sigs) {
  let count = 0
  let keys = {}
  let seed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)

  function update () {
    seed = keygen.genIdentifier(root, count++)
    sodium.crypto_sign_seed_keypair(keys.pk, keys.sk, seed)
  }

  function getSubIdentity (prefix, depth) {
    return keygen.genIdentifier(root, prefix, depth)
  }

  function sign (msg) {
    const pk = keys.pk
    const cert = sigs[count]

    const sig = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign(sig, msg, keys.sk)

    return {
      sig,
      pk,
      cert
    }
  }

  return {
    update,
    sign
  }
}
