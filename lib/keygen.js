const sodium = require('sodium-native')
const curve = require('./curve')

const G2 = curve.G2
const rand = curve.randomScalar

module.exports = {
  issuingKeys,
  signingKeys,
  userIds,
  findRoot,
  genIdentifiers,
  idToKeys,
  keysFromRoot,
  genIdentifier
}

function issuingKeys (n) {
  const a = rand()
  const z = rand()

  const _a = []
  for (let i = 0; i < n; i++) _a[i] = rand()

  const q = rand()
  const Q = curve.mulGenG2(q)

  const A = G2.mulScalar(Q, a)
  const Z = G2.mulScalar(Q, z)

  const _A = _a.map(k => G2.mulScalar(Q, k))

  return {
    sk: {
      a, _a, z
    },
    pk: {
      Q, A, _A, Z
    }
  }
}

function signingKeys () {
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_keypair(pk, sk)

  return {
    pk, sk
  }
}

function idToKeys (id) {
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_seed_keypair(pk, sk, id)

  return {
    pk, sk
  }
}

function userIds (signingKeys, number) {
  const root = genUserRoot()
  const keys = genIdentifiers(root, number).map(idToKeys)

  const sigs = keys.map(keys => {
    const sig = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(sig, keys.pk, signingKeys.sk)

    return sig
  })

  return {
    root,
    sigs,
    certKey: signingKeys.pk
  }
}

function genUserRoot () {
  const root = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
  sodium.randombytes_buf(root)

  return root
}

function genIdentifier (root, index, bits) {
  const buf = Buffer.alloc(sodium.crypto_sign_SEEDBYTES, root)

  for (let i = 0; i < bits; i++) {
    sodium.crypto_generichash(buf, Buffer.alloc(1, index & 1), buf)
    index >>= 1
  }

  return buf
}

function genIdentifiers (root, len) {
  const range = new Array(len).fill(0)
  const bits = Math.ceil(Math.log2(len))

  const identifiers = range.map((_, i) => genIdentifier(root, i, bits))
  return identifiers
}

function keysFromRoot (root, len) {
  return genIdentifiers(root, len).map(idToKeys)
}

function findRoot (revokeKey, len) {
  return (root) => {
    const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

    const identifiers = genIdentifiers(root, len)

    for (const id of identifiers) {
      sodium.crypto_sign_seed_keypair(pk, sk, id)
      if (Buffer.compare(pk, revokeKey)) return true
    }

    return false
  }
}
