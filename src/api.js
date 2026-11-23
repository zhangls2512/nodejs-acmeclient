const axios = require('axios')
const nodecrypto = require('crypto')
const net = require('net')
const crypto = require('./crypto')
const pkg = require('../package.json')
function hexbase64url(data) {
  return Buffer.from(data, 'hex').toString('base64url')
}
async function getRequest(url) {
  try {
    const res = await axios.get(url, {
      headers: {
        'User-Agent': pkg.name + '/' + pkg.version
      }
    })
    return res.data
  } catch (err) {
    if (err.response) {
      const error = err.response.data
      if (err.response.headers['retry-after']) {
        error.retryAfter = err.response.headers['retry-after']
      }
      throw error
    }
    throw err
  }
}
async function apiRequest({ apiUrl, apiName, directoryUrl, privateKey, payload, jwk = false }) {
  try {
    let alg = ''
    let sigalg
    const keyinfo = crypto.getKeyInfo(privateKey)
    if (keyinfo.keyType == 'RSA') {
      alg = 'RS256'
      sigalg = 'sha256'
    }
    if (keyinfo.keyType == 'ECDSA') {
      if (keyinfo.curveName == 'prime256v1') {
        alg = 'ES256'
        sigalg = 'sha256'
      }
      if (keyinfo.curveName == 'secp384r1') {
        alg = 'ES384'
        sigalg = 'sha384'
      }
      if (keyinfo.curveName == 'secp521r1') {
        alg = 'ES512'
        sigalg = 'sha512'
      }
    }
    if (keyinfo.keyType == 'MLDSA') {
      alg = 'ML-DSA-' + keyinfo.dimension
    }
    const directoryres = await getRequest(directoryUrl)
    let apiurl
    if (apiUrl) {
      apiurl = apiUrl
    } else {
      apiurl = directoryres[apiName]
    }
    const nonceres = await axios.head(directoryres.newNonce)
    const protected = {
      alg: alg,
      nonce: nonceres.headers['replay-nonce'],
      url: apiurl
    }
    if (jwk) {
      protected.jwk = nodecrypto.createPublicKey(privateKey).export({
        format: 'jwk'
      })
    } else {
      const accounturl = await getAccountUrl({
        directoryUrl: directoryUrl,
        accountKey: privateKey
      })
      protected.kid = accounturl
    }
    const encodedprotected = Buffer.from(JSON.stringify(protected)).toString('base64url')
    const encodedpayload = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const response = await axios.post(apiurl, {
      protected: encodedprotected,
      payload: encodedpayload,
      signature: nodecrypto.sign(sigalg, Buffer.from(encodedprotected + '.' + encodedpayload), {
        key: privateKey,
        dsaEncoding: 'ieee-p1363'
      }).toString('base64url')
    }, {
      headers: {
        'Content-Type': 'application/jose+json',
        'User-Agent': pkg.name + '/' + pkg.version
      }
    })
    const res = {
      data: response.data
    }
    if (response.headers['retry-after']) {
      res.retryAfter = response.headers['retry-after']
    }
    if (response.headers.location) {
      res.locationUrl = response.headers.location
    }
    return res
  } catch (err) {
    if (err.response) {
      const error = err.response.data
      if (err.response.headers['retry-after']) {
        error.retryAfter = err.response.headers['retry-after']
      }
      throw error
    }
    throw err
  }
}
async function getDirectoryMeta(directoryUrl) {
  try {
    const directoryres = await getRequest(directoryUrl)
    return directoryres.meta
  } catch (err) {
    throw err
  }
}
async function newAccount({ directoryUrl, accountKey, contact, eabMacKey, eabKeyId }) {
  try {
    const payload = {
      termsOfServiceAgreed: true
    }
    if (contact) {
      payload.contact = contact
    }
    if (eabMacKey && eabKeyId) {
      const directoryres = await getRequest(directoryUrl)
      const encodedprotected = Buffer.from(JSON.stringify({
        alg: 'HS256',
        kid: eabKeyId,
        url: directoryres.newAccount
      })).toString('base64url')
      const jwk = nodecrypto.createPublicKey(accountKey).export({
        format: 'jwk'
      })
      const encodedpayload = Buffer.from(JSON.stringify(jwk)).toString('base64url')
      payload.externalAccountBinding = {
        protected: encodedprotected,
        payload: encodedpayload,
        signature: nodecrypto.createHmac('sha256', Buffer.from(eabMacKey, 'base64')).update(encodedprotected + '.' + encodedpayload).digest('base64url')
      }
    }
    const res = await apiRequest({
      apiName: 'newAccount',
      directoryUrl: directoryUrl,
      privateKey: accountKey,
      payload: payload,
      jwk: true
    })
    return {
      accountUrl: res.locationUrl,
      accountInfo: res.data
    }
  } catch (err) {
    throw err
  }
}
async function getAccountUrl({ directoryUrl, accountKey }) {
  try {
    const res = await apiRequest({
      apiName: 'newAccount',
      directoryUrl: directoryUrl,
      privateKey: accountKey,
      payload: {
        onlyReturnExisting: true
      },
      jwk: true
    })
    return res.locationUrl
  } catch (err) {
    throw err
  }
}
async function getAccountInfo({ directoryUrl, accountKey }) {
  try {
    const res = await apiRequest({
      apiName: 'newAccount',
      directoryUrl: directoryUrl,
      privateKey: accountKey,
      payload: {
        onlyReturnExisting: true
      },
      jwk: true
    })
    return res.data
  } catch (err) {
    throw err
  }
}
async function updateAccountKey({ directoryUrl, accountKey, newAccountKey }) {
  try {
    let alg = ''
    let sigalg
    const keyinfo = crypto.getKeyInfo(newAccountKey)
    if (keyinfo.keyType == 'RSA') {
      alg = 'RS256'
      sigalg = 'sha256'
    }
    if (keyinfo.keyType == 'ECDSA') {
      if (keyinfo.curveName == 'prime256v1') {
        alg = 'ES256'
        sigalg = 'sha256'
      }
      if (keyinfo.curveName == 'secp384r1') {
        alg = 'ES384'
        sigalg = 'sha384'
      }
      if (keyinfo.curveName == 'secp521r1') {
        alg = 'ES512'
        sigalg = 'sha512'
      }
    }
    const oldjwk = nodecrypto.createPublicKey(accountKey).export({
      format: 'jwk'
    })
    const newjwk = nodecrypto.createPublicKey(newAccountKey).export({
      format: 'jwk'
    })
    const directoryres = await getRequest(directoryUrl)
    const protected = Buffer.from(JSON.stringify({
      alg: alg,
      jwk: newjwk,
      url: directoryres.keyChange
    })).toString('base64url')
    const accounturl = await getAccountUrl({
      directoryUrl: directoryUrl,
      accountKey: accountKey
    })
    const payload = Buffer.from(JSON.stringify({
      account: accounturl,
      oldKey: oldjwk
    })).toString('base64url')
    await apiRequest({
      apiName: 'keyChange',
      directoryUrl: directoryUrl,
      privateKey: accountKey,
      payload: {
        protected: protected,
        payload: payload,
        signature: nodecrypto.sign(sigalg, Buffer.from(protected + '.' + payload), {
          key: newAccountKey,
          dsaEncoding: 'ieee-p1363'
        }).toString('base64url')
      }
    })
    return 'success'
  } catch (err) {
    throw err
  }
}
async function updateAccountContact({ directoryUrl, accountKey, contact }) {
  try {
    const accounturl = await getAccountUrl({
      directoryUrl: directoryUrl,
      accountKey: accountKey
    })
    await apiRequest({
      apiUrl: accounturl,
      directoryUrl: directoryUrl,
      privateKey: accountKey,
      payload: {
        contact: contact
      }
    })
    return 'success'
  } catch (err) {
    throw err
  }
}
async function deactivateAccount({ directoryUrl, accountKey }) {
  try {
    const accounturl = await getAccountUrl({
      directoryUrl: directoryUrl,
      accountKey: accountKey
    })
    await apiRequest({
      apiUrl: accounturl,
      directoryUrl: directoryUrl,
      privateKey: accountKey,
      payload: {
        status: 'deactivated'
      }
    })
    return 'success'
  } catch (err) {
    throw err
  }
}
async function newOrder({ directoryUrl, accountKey, domains, profile, notBefore, notAfter, replaceCertificate }) {
  try {
    const identifiers = domains.map(item => {
      if (net.isIP(item)) {
        return {
          type: 'ip',
          value: item
        }
      }
      return {
        type: 'dns',
        value: item
      }
    })
    const payload = {
      identifiers: identifiers
    }
    if (profile) {
      payload.profile = profile
    }
    if (notBefore) {
      payload.notBefore = notBefore
    }
    if (notAfter) {
      payload.notAfter = notAfter
    }
    if (replaceCertificate) {
      const replacecertificateinfo = crypto.getCertificateInfo(replaceCertificate)[0]
      const replacecertificateidentifier = hexbase64url(replacecertificateinfo.authorityKeyIdentifier) + '.' + hexbase64url(replacecertificateinfo.serialNumber)
      payload.replaces = replacecertificateidentifier
    }
    const res = await apiRequest({
      apiName: 'newOrder',
      directoryUrl: directoryUrl,
      privateKey: accountKey,
      payload: payload
    })
    return {
      orderUrl: res.locationUrl,
      orderInfo: res.data
    }
  } catch (err) {
    throw err
  }
}
async function getOrderInfo(orderUrl) {
  try {
    return await getRequest(orderUrl)
  } catch (err) {
    throw err
  }
}
async function getOrderAuthorization(orderUrl) {
  try {
    const orderres = await getRequest(orderUrl)
    const promises = orderres.authorizations.map(async (item) => {
      return await getRequest(item)
    })
    return await Promise.all(promises)
  } catch (err) {
    throw err
  }
}
async function finalizeOrder({ directoryUrl, accountKey, orderUrl, csr }) {
  try {
    const csrout = csr.replace(/-----BEGIN CERTIFICATE REQUEST-----/g, '').replace(/-----END CERTIFICATE REQUEST-----/g, '').replace(/\s/g, '')
    const orderres = await getOrderInfo(orderUrl)
    const res = await apiRequest({
      apiUrl: orderres.finalize,
      directoryUrl: directoryUrl,
      privateKey: accountKey,
      payload: {
        csr: Buffer.from(csrout, 'base64').toString('base64url')
      }
    })
    const result = {
      status: 'success'
    }
    if (res.retryAfter) {
      result.retryAfter = res.retryAfter
    }
    return result
  } catch (err) {
    throw err
  }
}
async function getOrderCertificate(orderUrl) {
  try {
    const res = await getOrderCertificateEx(orderUrl)
    return res.certificates.map(item.value)
  } catch (err) {
    throw err
  }
}
async function getOrderCertificateEx(orderUrl) {
  try {
    const orderres = await getOrderInfo(orderUrl)
    const res = await axios.get(orderres.certificate, {
      headers: {
        'Accept': 'application/pem-certificate-chain-with-properties',
        'User-Agent': pkg.name + '/' + pkg.version
      }
    })
    const certificates = []
    let allready = true
    if (res.status == 200) {
      certificates.push({
        rel: 'index',
        value: res.data
      })
    }
    if (res.status == 202) {
      allready = false
    }
    const rels = ['rel="alternate"', 'rel="acme-optional-alternate"']
    const alternates = res.headers.link.split(',')
    const promises = alternates.map(async (item) => {
      for (let i = 0; i < rels.length; i++) {
        const rel = rels[i]
        if (item.includes(rel)) {
          const link = item.split('<')[1].split('>')[0]
          const res = await axios.get(link, {
            headers: {
              'Accept': 'application/pem-certificate-chain-with-properties',
              'User-Agent': pkg.name + '/' + pkg.version
            }
          })
          if (res.status == 200) {
            certificates.push({
              rel: rel.split('"')[1].split('"')[0],
              value: res.data
            })
          }
          if (res.status == 202) {
            allready = false
          }
          return
        }
      }
    })
    await Promise.all(promises)
    return {
      certificates: certificates,
      allReady: allready
    }
  } catch (err) {
    throw err
  }
}
async function deactivateAuthorization({ directoryUrl, accountKey, authorizationUrl }) {
  try {
    await apiRequest({
      apiUrl: authorizationUrl,
      directoryUrl: directoryUrl,
      privateKey: accountKey,
      payload: {
        status: 'deactivated'
      }
    })
    return 'success'
  } catch (err) {
    throw err
  }
}
function getChallengeKeyAuthorization({ challenge, accountKey }) {
  const jwk = nodecrypto.createPublicKey(accountKey).export({
    format: 'jwk'
  })
  const res = Object.keys(jwk).sort().reduce((result, k) => {
    result[k] = jwk[k]
    return result
  }, {})
  const thumbprint = nodecrypto.createHash('sha256').update(JSON.stringify(res)).digest('base64url')
  const keyauthorization = challenge.token + '.' + thumbprint
  if (challenge.type == 'http-01') {
    return keyauthorization
  }
  return nodecrypto.createHash('sha256').update(keyauthorization).digest('base64url')
}
async function getChallengeKeyAuthorizationEx({ directoryUrl, accountKey, authorization, type }) {
  const challenge = authorization.challenges.find(challenge => challenge.type == type)
  if (type != 'dns-persist-01') {
    const jwk = nodecrypto.createPublicKey(accountKey).export({
      format: 'jwk'
    })
    const res = Object.keys(jwk).sort().reduce((result, k) => {
      result[k] = jwk[k]
      return result
    }, {})
    const thumbprint = nodecrypto.createHash('sha256').update(JSON.stringify(res)).digest('base64url')
    const keyauthorization = challenge.token + '.' + thumbprint
    if (type == 'http-01') {
      return keyauthorization
    }
    return nodecrypto.createHash('sha256').update(keyauthorization).digest('base64url')
  }
  if (type == 'dns-persist-01') {
    const arr = []
    arr.push(challenge['issuer-domain-names'][0])
    const accounturl = await getAccountUrl({
      directoryUrl: directoryUrl,
      accountKey: accountKey
    })
    arr.push('accounturi=' + accounturl)
    if (authorization.wildcard) {
      arr.push('policy=wildcard')
    }
    return arr.join(';')
  }
}
async function respondChallenge({ directoryUrl, accountKey, challengeUrl }) {
  try {
    const res = await apiRequest({
      apiUrl: challengeUrl,
      directoryUrl: directoryUrl,
      privateKey: accountKey,
      payload: {}
    })
    const result = {
      status: 'success'
    }
    if (res.retryAfter) {
      result.retryAfter = res.retryAfter
    }
    return result
  } catch (err) {
    throw err
  }
}
async function getCertificateRenewalInfo({ directoryUrl, certificate }) {
  try {
    const directoryres = await getRequest(directoryUrl)
    const certificateinfo = crypto.getCertificateInfo(certificate)[0]
    return await getRequest(directoryres.renewalInfo + '/' + hexbase64url(certificateinfo.authorityKeyIdentifier) + '.' + hexbase64url(certificateinfo.serialNumber))
  } catch (err) {
    throw err
  }
}
async function revokeCertificate({ directoryUrl, accountKey, certificateKey, certificate, reason }) {
  try {
    const certificateout = crypto.extractCertificates(certificate)[0].replace(/-----BEGIN CERTIFICATE-----/g, '').replace(/-----END CERTIFICATE-----/g, '').replace(/\s/g, '')
    const payload = {
      certificate: Buffer.from(certificateout, 'base64').toString('base64url')
    }
    if (reason !== undefined) {
      payload.reason = reason
    }
    if (accountKey) {
      await apiRequest({
        apiName: 'revokeCert',
        directoryUrl: directoryUrl,
        privateKey: accountKey,
        payload: payload
      })
      return 'success'
    }
    if (certificateKey) {
      await apiRequest({
        apiName: 'revokeCert',
        directoryUrl: directoryUrl,
        privateKey: certificateKey,
        payload: payload,
        jwk: true
      })
      return 'success'
    }
  } catch (err) {
    throw err
  }
}
module.exports = {
  getDirectoryMeta,
  newAccount,
  getAccountUrl,
  getAccountInfo,
  updateAccountKey,
  updateAccountContact,
  deactivateAccount,
  newOrder,
  getOrderInfo,
  getOrderAuthorization,
  finalizeOrder,
  getOrderCertificate,
  getOrderCertificateEx,
  deactivateAuthorization,
  getChallengeKeyAuthorization,
  getChallengeKeyAuthorizationEx,
  respondChallenge,
  getCertificateRenewalInfo,
  revokeCertificate
}