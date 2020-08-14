const assert = require('nanoassert')
const sodium = require('sodium-native')
const keygen = require('./lib/keygen')
const { Credential, serializeShowing, showingEncodingLength } = require('./credential')
const attributes = require('./lib/gen-attributes')

module.exports = class Identity {
  constructor (attrs, certId) {
    this.credential = new Credential(Object.keys(attrs).length)
    this.pseudonym = null
    this.attributes = attrs
    this.certId = certId
  }

  finalize ({ identity, info }) {
    this.pseudonym = Pseudonym(identity)
    this.credential.finalize(info)
  }

  present (disclosure) {
    const disclosed = {}
    for (let item of disclosure) disclosed[item] = this.attributes[item]

    // TODO: validate against credential
    const encoded = Object.values(disclosed).map(v =>
      attributes.encode(v.toString()))

    const showing = this.credential.show(encoded)
    const toSign = serializeShowing(showing)

    const sig = this.pseudonym.sign(Buffer.from(toSign, 'hex'))
    this.pseudonym.update()

    const presentation = {
      disclosed,
      showing,
      sig,
      certId: this.certId
    }

    return encodePresent(presentation)
  }
}

function Pseudonym ({ root, sigs, certKey }) {
  let count = 0
  let seed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
  let maxDepth = Math.ceil(Math.log2(sigs.length))

  const keys = {
    pk: Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES),
    sk: Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES),
    certSig: null
  }

  validate()
  loadIdentity(0, keys)

  function update () {
    loadIdentity(++count, keys)
    return this
  }

  function getSubIdentity (prefix, depth) {
    return keygen.genIdentifier(root, prefix, depth)
  }

  function loadIdentity (counter, keypair) {
    const seed = keygen.genIdentifier(root, counter, maxDepth)
    sodium.crypto_sign_seed_keypair(keypair.pk, keypair.sk, seed)
    keys.certSig = sigs[count]

    return keypair
  }

  function sign (msg) {
    const sig = Buffer.alloc(sodium.crypto_sign_BYTES)
    const pk = keys.pk.toString('hex')
    const certSig = keys.certSig.toString('hex')

    sodium.crypto_sign_detached(sig, msg, keys.sk)

    assert(sodium.crypto_sign_verify_detached(sig, msg, keys.pk))

    function encode (buf, offset) {
      if (!buf) buf = Buffer.alloc(encodingLength())
      if (!offset) offset = 0
      const startIndex = offset

      buf.set(sig, offset)
      offset += sig.byteLength

      buf.write(pk, offset, 'hex')
      offset += keys.pk.byteLength

      buf.write(certSig, offset, 'hex')
      offset += keys.certSig.byteLength

      encode.bytes = offset - startIndex
      return buf
    }

    function encodingLength () {
      return 2 * sodium.crypto_sign_BYTES + sodium.crypto_sign_PUBLICKEYBYTES
    }

    return {
      signature: sig,
      pk: Buffer.from(keys.pk),
      certSig: Buffer.from(keys.certSig),
      encode,
      encodingLength
    }
  }

  function validate () {
    for (let i = 0; i < sigs.length; i++) {
      const { pk } = loadIdentity(i, keys)
      assert(sodium.crypto_sign_verify_detached(sigs[i], pk, certKey))
    }
  }

  return {
    update,
    sign,
    loadIdentity
  }
}

function serialize (obj) {
  let result = ''

  if (obj.buffer) result += obj.buffer.toString('hex')
  else if (Array.isArray(obj)) {
    for (let entry of obj) result += serialize(entry)
  } else if (typeof obj === 'object') {
    for (let item of Object.values(obj)) {
      result += serialize(item)
    }
  } else {
    try {
      result += obj.toString(16)
    } catch {
      result += obj.toString('hex')
    }
  }

  return result
}

function encodePresent (present, buf, offset) {
  if (!buf) buf = Buffer.alloc(presentEncodingLength(present))
  if (!offset) offset = 0
  const startIndex = offset

  buf.writeUInt32LE(Object.values(present.disclosed).length, offset)
  offset += 4

  for (let e of Object.entries(present.disclosed)) {
    const [k, v] = e.map(a => a.toString())

    buf.writeUInt8(k.length, offset)
    offset++

    buf.write(k, offset)
    offset += k.length

    buf.writeUInt8(v.length, offset)
    offset++

    buf.write(v, offset)
    offset += v.length
  }

  const show = serializeShowing(present.showing, buf, offset)
  offset += serializeShowing.bytes

  present.sig.encode(buf, offset)
  offset += present.sig.encode.bytes

  buf.write(present.certId, offset, 'hex')
  offset += present.certId.byteLength

  encodePresent.bytes = offset - startIndex
  return buf
}

function presentEncodingLength (present) {
  let len = 0

  len += 4

  for (let e of Object.entries(present.disclosed)) {
    const [k, v] = e.map(a => a.toString())

    len += 2
    len += k.length
    len += v.length
  }

  len += showingEncodingLength(present.showing)
  len += present.sig.encodingLength()
  len += 32

  return len
}
