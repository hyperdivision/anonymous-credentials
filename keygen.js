const sodium = require('sodium-native')
const curve = require('./curve')

const G2 = curve.G2
const rand = curve.randomScalar

module.exports = {
  issuingKeys,
  signingKeys,
  userIds,
  findRoot
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

function userIds (signingKey) {
  const root = genUserRoot()
  const identifiers = genIdentifiers(root)

  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  const sig = Buffer.alloc(sodium.crypto_sign_BYTES)


  const sigs = identifiers.map(id => {
    sodium.crypto_sign_seed_keypair(pk, sk, id)
    sodium.crypto_sign_detached(sig, pk, signingKey)
    return sig.slice()
  })

  return {
    root,
    sigs
  }
}

function genUserRoot () {
  const root = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
  sodium.randombytes_buf(root)

  return root
}

function genIdentifiers (root, len) {
  const range = new Array(len)
  const bits = Math.ceil(Math.log2(len))

  const identifiers = range.map((_, i) => genIdentifier(root, i, bits))
  return identifiers
}

function genIdentifier (root, index, bits) {
  const buf = Buffer.alloc(sodium.crypto_sign_SEEDBYTES, root)

  for (let i = 0; i < bits; i++) {
    sodium.crypto_generichash(buf, Buffer.alloc(1, index & 1), buf)
    index >>= 1
  }

  return buf
}

function findRoot (revokeKey) {
  return (root) => {
    const id = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
    const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

    sodium.crypto_generichash(id, root)

    for (let i = 0; i < 128; i++) {
      sodium.crypto_sign_seed_keypair(pk, sk, id)
      if (Buffer.compare(pk, revokeKey)) return true

      sodium.crypto_generichash(id, id)
    }

    return false
  }
}
