const curve = require('../lib/curve')
const Accumulator = require('./accumulator')
const sha256 = require('sha512-wasm')
const assert = require('nanoassert')

const { F, F12, G1, G2 } = curve

module.exports = {
  verify
}

module.exports.Revoker = class Revoker {
  constructor () {
    this.acc = new Accumulator
    this.users = []
    this.revoked = []

    this.secrets = {}
    this.secrets.alpha = this.acc.alpha
    this.secrets.xi1 = curve.randomScalar()
    this.secrets.xi2 = curve.randomScalar()

    this.pubkey = {}
    this.pubkey.g1 = this.acc.g1
    this.pubkey.u = curve.randomPointG1()
    this.pubkey.h = G1.mulScalar(this.pubkey.u, this.secrets.xi1)
    this.pubkey.v = G1.mulScalar(this.pubkey.h, F.inv(this.secrets.xi2))

    this.pubkey.g2 = this.acc.g2
    this.pubkey.a = G2.mulScalar(this.pubkey.g2, this.secrets.alpha)
    this.pubkey.acc = this.acc.acc
    
    this.pubkey.e = {}
    this.pubkey.e.gg = curve.pairing(this.pubkey.g1, this.pubkey.g2)
    this.pubkey.e.vg = curve.pairing(this.acc.acc, this.pubkey.g2)
    this.pubkey.e.hg = curve.pairing(this.pubkey.h, this.pubkey.g2)
    this.pubkey.e.ha = curve.pairing(this.pubkey.h, this.pubkey.a)
  }

  issue () {
    const id = this.acc.new()
    this.users.push(id)

    const identifier = new Identifier(id, this.pubkey)
    return identifier
  }

  open (showing, r) {
    assert(verify(showing, this.pubkey), 'opening failed: invalid signature')

    const { T } = showing
    const c = G1.sub(T[2], G1.add(G1.mulScalar(T[0], this.secrets.xi1), G1.mulScalar(T[1], this.secrets.xi2)))

    const user = this.users.find(u => G1.eq(u.witness.c, c))
    return user
  }

  revoke (user) {
    const acc = this.acc.acc
    this.acc.add(user.y)
    this.revoked.push(user)

    this.pubkey.acc = this.acc.acc
    this.pubkey.e.vg = curve.pairing(this.acc.acc, this.pubkey.g2)

    return {
      acc,
      y: user.y
    }
  }

  getPubkey () {
    return this.pubkey
  }
}

class Identifier {
  constructor (id, pk) {
    this.y = id.y
    this.w = id.witness
    this.pk = pk
  }

  show () {
    const alpha = curve.randomScalar()
    const beta = curve.randomScalar()
    const gamma = curve.randomScalar()
    const delta = curve.randomScalar()

    const T = []
    T[0] = G1.affine(G1.mulScalar(this.pk.u, alpha))
    T[1] = G1.affine(G1.mulScalar(this.pk.v, beta))
    T[2] = G1.affine(G1.add(this.w.c, G1.mulScalar(this.pk.h, F.add(alpha, beta))))
    T[3] = G1.affine(G1.mulScalar(this.pk.u, gamma))
    T[4] = G1.affine(G1.mulScalar(this.pk.v, delta))
    T[5] = G1.affine(G1.add(G1.mulScalar(this.pk.g1, F.mul(this.w.d, F.inv(F.add(gamma, delta)))), this.pk.h))

    const delta1 = F.mul(this.y, alpha)
    const delta2 = F.mul(this.y, beta)

    const blinds = []

    for (let i = 0; i < 7; i++) blinds.push(curve.randomScalar())

    const precomp_r1 = F.neg(F.add(blinds[0], blinds[1]))
    const precomp_r1y_r2 = F.neg(F.add(F.add(blinds[3], blinds[4]), F.add(blinds[5], blinds[6])))
    const precomp = F12.mul(F12.exp(this.pk.e.ha, precomp_r1), F12.exp(this.pk.e.hg, precomp_r1y_r2))

    const pairingT2 = curve.pairing(G1.mulScalar(T[2], blinds[2]), this.pk.g2)
    const pairingT5 = curve.pairing(G1.mulScalar(T[5], F.neg(F.add(blinds[5], blinds[6]))), this.pk.g2)

    const R = []
    R[0] = G1.affine(G1.mulScalar(this.pk.u, blinds[0]))
    R[1] = G1.affine(G1.mulScalar(this.pk.v, blinds[1]))
    R[2] = F12.div(F12.mul(pairingT2, precomp), pairingT5)
    R[3] = G1.affine(G1.sub(G1.mulScalar(T[0], blinds[2]), G1.mulScalar(this.pk.u, blinds[3])))
    R[4] = G1.affine(G1.sub(G1.mulScalar(T[1], blinds[2]), G1.mulScalar(this.pk.v, blinds[4])))
    R[5] = G1.affine(G1.mulScalar(this.pk.u, blinds[5]))
    R[6] = G1.affine(G1.mulScalar(this.pk.v, blinds[6]))

    const c = hash(...T, ...R)

    const cBlinds = [alpha, beta, this.y, delta1, delta2, gamma, delta].map((scalar, i) => {
      return F.add(blinds[i], F.mul(c, scalar))
    })

    return {
      T,
      c,
      cBlinds,
    }
  }

  update (info) {
    const diff = F.sub(info.y, this.y)
    this.w.c = G1.affine(G1.add(info.acc, G1.mulScalar(this.w.c, diff)))
    this.w.d = F.mul(this.w.d, diff)
  }
}

function verify (showing, pk) {
  const { T, R, c, cBlinds } = showing

  if (F12.eq(curve.pairing(T[5], pk.g2), pk.e.hg)) return false

  const precomp_r1 = F.neg(F.add(cBlinds[0], cBlinds[1]))
  const precomp_r2 = F.add(cBlinds[5], cBlinds[6])
  const precomp_r1y = F.neg(F.add(cBlinds[3], cBlinds[4]))
  const precomp_vg_c = F12.exp(pk.e.vg, F.neg(c))
  const precomp = F12.mul(F12.mul(F12.exp(pk.e.ha, precomp_r1), F12.exp(pk.e.hg, precomp_r1y)), F12.exp(pk.e.hg, F.neg(precomp_r2)))

  const pairingT2 = curve.pairing(T[2], G2.add(G2.mulScalar(pk.a, c), G2.mulScalar(pk.g2, cBlinds[2])))
  const pairingT5 = curve.pairing(G1.mulScalar(T[5], precomp_r2), pk.g2)

  const R_ = []
  R_[0] = G1.affine(G1.sub(G1.mulScalar(pk.u, cBlinds[0]), G1.mulScalar(T[0], c)))
  R_[1] = G1.affine(G1.sub(G1.mulScalar(pk.v, cBlinds[1]), G1.mulScalar(T[1], c)))
  R_[2] = F12.mul(F12.mul(F12.mul(pairingT2, pairingT5), precomp_vg_c), precomp)
  R_[3] = G1.affine(G1.sub(G1.mulScalar(T[0], cBlinds[2]), G1.mulScalar(pk.u, cBlinds[3])))
  R_[4] = G1.affine(G1.sub(G1.mulScalar(T[1], cBlinds[2]), G1.mulScalar(pk.v, cBlinds[4])))
  R_[5] = G1.affine(G1.sub(G1.mulScalar(pk.u, cBlinds[5]), G1.mulScalar(T[3], c)))
  R_[6] = G1.affine(G1.sub(G1.mulScalar(pk.v, cBlinds[6]), G1.mulScalar(T[4], c)))

  // for (let i = 0; i < 7; i++) {
  //   try {
  //     if (!G1.eq(R[i], R_[i])) console.log(i)
  //   } catch {
  //     if (!F12.eq(R[i], R_[i])) console.log(i)
  //   }
  // }

  const check = hash(...T, ...R_)
  return F.eq(c, check)
}

function hash (...elements) {
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

  const digest = sha256().update(data).digest()
  return curve.scalarFrom(digest)
}
