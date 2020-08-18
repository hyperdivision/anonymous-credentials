const sodium = require('sodium-native')
const curve = require('./curve')

const G2 = curve.G2
const rand = curve.randomScalar

module.exports = {
  issuingKeys: {
    generate: issuingKeys,
    encode: encodeIssuingKeys,
    decode: decodeIssuingKeys
  },
  signingKeys: {
    generate: signingKeys,
    encode: encodeSigningKeys,
    decode: decodeSigningKeys
  },
  encodeCertKeys,
  decodeCertKeys,
  certKeysEncodingLength,
  userIds,
  decodeUserIds,
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

function encodeCertKeys (keys, buf, offset) {
  if (!buf) buf = Buffer.alloc(certKeysEncodingLength(keys))
  if (!offset) offset = 0
  const startIndex = offset

  buf.set(keys.org, buf, offset)
  offset += 32

  encodeCredentialKey(keys.credential, buf, offset)
  offset += encodeCredentialKey.bytes

  encodeCertKeys.bytes = offset - startIndex
  return buf
}

function decodeCertKeys (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset
  const keys = {}

  keys.org = buf.subarray(offset, offset + 32)
  offset += 32

  keys.credential = decodeCredentialKey(buf, offset)
  offset += decodeCredentialKey.bytes

  decodeCertKeys.bytes = offset - startIndex
  return keys
}

function certKeysEncodingLength (keys) {
  let len = 32
  len += credentialKeysEncodingLength(keys.credential)

  return len
}

function encodeCredentialKey (keys, buf, offset) {
  if (!buf) buf = Buffer.alloc(192 * (3 + keys._A.length) + 4)
  if (!offset) offset = 0
  const startIndex = offset

  curve.encodeG2(keys.A, buf, offset)
  offset += curve.encodeG2.bytes

  buf.writeUInt32LE(keys._A.length, offset)
  offset += 4

  for (const k of keys._A) {
    curve.encodeG2(k, buf, offset)
    offset += curve.encodeG2.bytes
  }

  curve.encodeG2(keys.Z, buf, offset)
  offset += curve.encodeG2.bytes

  curve.encodeG2(keys.Q, buf, offset)
  offset += curve.encodeG2.bytes

  encodeCredentialKey.bytes = offset - startIndex
  return buf
}

function decodeCredentialKey (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  const keys = {}

  keys.A = curve.decodeG2(buf, offset)
  offset += curve.decodeG2.bytes

  const aLen = buf.readUInt32LE(offset)
  offset += 4

  keys._A = new Array(aLen)
  for (let i = 0; i < aLen; i++) {
    keys._A[i] = curve.decodeG2(buf, offset)
    offset += curve.decodeG2.bytes
  }

  keys.Z = curve.decodeG2(buf, offset)
  offset += curve.decodeG2.bytes

  keys.Q = curve.decodeG2(buf, offset)
  offset += curve.decodeG2.bytes

  decodeCredentialKey.bytes = offset - startIndex
  return keys
}

function credentialKeysEncodingLength (keys) {
  return 192 * (3 + keys._A.length) + 4
}

function encodeIssuingKeys (keys, buf, offset) {
  if (!buf) buf = Buffer.alloc(issuingKeysEncodingLength(keys))
  if (!offset) offset = 0
  const startIndex = offset

  curve.encodeScalar(keys.sk.a, buf, offset)
  offset += curve.encodeScalar.bytes

  buf.writeUInt32LE(keys.sk._a.length, offset)
  offset += 4

  for (const k of keys.sk._a) {
    curve.encodeScalar(k, buf, offset)
    offset += curve.encodeScalar.bytes
  }

  curve.encodeScalar(keys.sk.z, buf, offset)
  offset += curve.encodeScalar.bytes

  curve.encodeG2(keys.pk.Q, buf, offset)
  offset += curve.encodeG2.bytes

  encodeIssuingKeys.bytes = offset - startIndex
  return buf
}

function decodeIssuingKeys (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  const keys = {}
  keys.sk = {}
  keys.pk = {}

  keys.sk.a = curve.decodeScalar(buf, offset)
  offset += curve.decodeScalar.bytes

  const aLen = buf.readUInt32LE(offset)
  offset += 4

  keys.sk._a = new Array(aLen)
  for (let i = 0; i < aLen; i++) {
    keys.sk._a[i] = curve.decodeScalar(buf, offset)
    offset += curve.decodeScalar.bytes
  }

  keys.sk.z = curve.decodeScalar(buf, offset)
  offset += curve.decodeScalar.bytes

  keys.pk.Q = curve.decodeG2(buf, offset)
  offset += curve.encodeG2.bytes

  keys.pk.A = G2.mulScalar(keys.pk.Q, keys.sk.a)
  keys.pk.Z = G2.mulScalar(keys.pk.Q, keys.sk.z)
  keys.pk._A = keys.sk._a.map(k => G2.mulScalar(keys.pk.Q, k))

  decodeIssuingKeys.bytes = offset - startIndex
  return keys
}

function issuingKeysEncodingLength (keys) {
  return 192 + 4 + 32 * (2 + keys.sk._a.length)
}

function encodeSigningKeys (keys, buf, offset) {
  if (!buf) buf = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  buf.set(keys.sk, offset)

  encodeSigningKeys.bytes = 64
  return buf
}

function decodeSigningKeys (keys, buf, offset) {
  if (!buf) buf = Buffer.alloc(32)

  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)

  sk.set(buf.subarray(offset, offset + 64))
  sodium.crypto_sign_ed25519_sk_to_pk(pk, sk)

  decodeSigningKeys.bytes = 64
  return {
    pk, sk
  }
}

function signingKeysEncodingLength (keys) {
  return sodium.crypto_sign_SECRETKEYBYTES
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

  const sigs = keys.map((keys, i) => {
    const sig = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(sig, keys.pk, signingKeys.sk)

    return sig
  })

  function encode (buf, offset) {
    if (!buf) buf = Buffer.alloc(encodingLength())
    if (!offset) offset = 0
    const startIndex = offset

    buf.set(root, offset)
    offset += root.byteLength

    buf.writeUInt32LE(sigs.length, offset)
    offset += 4

    for (let sig of sigs) {
      buf.set(sig, offset)
      offset += sig.byteLength
    }

    buf.set(signingKeys.pk, offset)
    offset += signingKeys.pk.byteLength

    encode.bytes = offset - startIndex
    return buf
  }

  function encodingLength () {
    return 4 + sodium.crypto_sign_SEEDBYTES + sodium.crypto_sign_BYTES * sigs.length + sodium.crypto_sign_PUBLICKEYBYTES
  }

  return {
    root,
    sigs,
    certKey: signingKeys.pk,
    encode,
    encodingLength
  }
}

function decodeUserIds (buf, offset) {
  if (!offset) offset = 0
  const startIndex = offset

  const id = {}

  id.root = buf.subarray(offset, offset + sodium.crypto_sign_SEEDBYTES)
  offset += sodium.crypto_sign_SEEDBYTES

  const len = buf.readUInt32LE(offset)
  offset += 4

  id.sigs = []
  for (let i = 0; i < len; i++) {
    id.sigs.push(buf.subarray(offset, offset + sodium.crypto_sign_BYTES))
    offset += sodium.crypto_sign_BYTES
  }

  id.certKey = buf.subarray(offset, offset + sodium.crypto_sign_PUBLICKEYBYTES)
  offset += sodium.crypto_sign_PUBLICKEYBYTES

  decodeUserIds.bytes = offset - startIndex
  return id
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
