const axios = require('axios')
const nodecrypto = require('crypto')
const net = require('net')
const jose = require('node-jose')
const crypto = require('./crypto')
const pkg = require('../package.json')
function base64url(data) {
  return Buffer.from(data).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}
function hexbase64url(data) {
  return Buffer.from(data, 'hex').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
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
    let alg = 'RS256'
    let sigalg = 'sha256'
    const keyinfo = crypto.getKeyInfo(privateKey)
    if (keyinfo.keyType == 'ECDSA') {
      if (keyinfo.curveName == 'secp256r1') {
        alg = 'ES256'
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
    const jwkout = await jose.JWK.asKey(privateKey, 'pem', {
      alg: alg
    })
    const directoryres = await getRequest(directoryUrl)
    let apiurl
    if (apiUrl) {
      apiurl = apiUrl
    } else {
      apiurl = directoryres[apiName]
    }
    const nonceres = await axios.head(directoryres.newNonce)
    const nonce = nonceres.headers['replay-nonce']
    const protected = {
      alg: alg,
      nonce: nonce,
      url: apiurl
    }
    if (jwk) {
      protected.jwk = jwkout
    } else {
      const accounturl = await getAccountUrl({
        directoryUrl: directoryUrl,
        accountKey: privateKey
      })
      protected.kid = accounturl
    }
    const encodedprotected = base64url(JSON.stringify(protected))
    const encodedpayload = base64url(JSON.stringify(payload))
    const signature = nodecrypto.createSign(sigalg).update(encodedprotected + '.' + encodedpayload).sign({
      key: privateKey,
      dsaEncoding: 'ieee-p1363'
    }, 'base64url')
    const jws = {
      protected: encodedprotected,
      payload: encodedpayload,
      signature: signature
    }
    const resp = await axios.post(apiurl, jws, {
      headers: {
        'Content-Type': 'application/jose+json',
        'User-Agent': pkg.name + '/' + pkg.version
      }
    })
    const res = {
      data: resp.data
    }
    if (resp.headers['retry-after']) {
      res.retryAfter = resp.headers['retry-after']
    }
    if (resp.headers.location) {
      res.locationUrl = resp.headers.location
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
  if (!directoryUrl) {
    throw 'Invalid input: directoryUrl is required.'
  }
  try {
    const directoryres = await getRequest(directoryUrl)
    return directoryres.meta
  } catch (err) {
    throw err
  }
}
async function newAccount({ directoryUrl, accountKey, contact, eabMacKey, eabKeyId }) {
  if (!directoryUrl || !accountKey) {
    throw 'Invalid input: directoryUrl and accountKey are required.'
  }
  try {
    const payload = {
      termsOfServiceAgreed: true
    }
    if (contact) {
      payload.contact = contact
    }
    if (eabMacKey && eabKeyId) {
      const jwk = await jose.JWK.asKey(accountKey, 'pem')
      const directoryres = await getRequest(directoryUrl)
      const apiurl = directoryres.newAccount
      const protected = {
        alg: 'HS256',
        kid: eabKeyId,
        url: apiurl
      }
      const encodedprotected = base64url(JSON.stringify(protected))
      const encodedpayload = base64url(JSON.stringify(jwk))
      const signature = nodecrypto.createHmac('sha256', Buffer.from(eabMacKey, 'base64')).update(encodedprotected + '.' + encodedpayload).digest('base64url')
      payload.externalAccountBinding = {
        protected: encodedprotected,
        payload: encodedpayload,
        signature: signature
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
  if (!directoryUrl || !accountKey) {
    throw 'Invalid input: directoryUrl and accountKey are required.'
  }
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
  if (!directoryUrl || !accountKey) {
    throw 'Invalid input: directoryUrl and accountKey are required.'
  }
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
  if (!directoryUrl || !accountKey || !newAccountKey) {
    throw 'Invalid input: directoryUrl, accountKey and newAccountKey are required.'
  }
  try {
    let alg = 'RS256'
    let sigalg = 'sha256'
    const keyinfo = crypto.getKeyInfo(newAccountKey)
    if (keyinfo.keyType == 'ECDSA') {
      if (keyinfo.curveName == 'secp256r1') {
        alg = 'ES256'
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
    const oldjwk = await jose.JWK.asKey(accountKey, 'pem')
    const newjwk = await jose.JWK.asKey(newAccountKey, 'pem', {
      alg: alg
    })
    const directoryres = await getRequest(directoryUrl)
    const protected = base64url(JSON.stringify({
      alg: alg,
      jwk: newjwk,
      url: directoryres.keyChange
    }))
    const accounturl = await getAccountUrl({
      directoryUrl: directoryUrl,
      accountKey: accountKey
    })
    const payload = base64url(JSON.stringify({
      account: accounturl,
      oldKey: oldjwk
    }))
    const signature = nodecrypto.createSign(sigalg).update(protected + '.' + payload).sign({
      key: newAccountKey,
      dsaEncoding: 'ieee-p1363'
    }, 'base64url')
    await apiRequest({
      apiName: 'keyChange',
      directoryUrl: directoryUrl,
      privateKey: accountKey,
      payload: {
        protected: protected,
        payload: payload,
        signature: signature
      }
    })
    return 'success'
  } catch (err) {
    throw err
  }
}
async function updateAccountContact({ directoryUrl, accountKey, contact }) {
  if (!directoryUrl || !accountKey || !contact) {
    throw 'Invalid input: directoryUrl, accountKey and contact are required.'
  }
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
  if (!directoryUrl || !accountKey) {
    throw 'Invalid input: directoryUrl and accountKey are required.'
  }
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
  if (!directoryUrl || !accountKey || !domains || !(Array.isArray(domains) && domains.length > 0)) {
    throw 'Invalid input: directoryUrl, accountKey and domains are required.'
  }
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
  if (!orderUrl) {
    throw 'Invalid input: orderUrl is required.'
  }
  try {
    return await getRequest(orderUrl)
  } catch (err) {
    throw err
  }
}
async function getOrderAuthorization(orderUrl) {
  if (!orderUrl) {
    throw 'Invalid input: orderUrl is required.'
  }
  try {
    const orderres = await getRequest(orderUrl)
    const authorizationsurl = orderres.authorizations
    const promises = authorizationsurl.map(async (item) => {
      return await getRequest(item)
    })
    return await Promise.all(promises)
  } catch (err) {
    throw err
  }
}
async function finalizeOrder({ directoryUrl, accountKey, orderUrl, csr }) {
  if (!directoryUrl || !accountKey || !orderUrl || !csr) {
    throw 'Invalid input: directoryUrl, accountKey, orderUrl and csr are required.'
  }
  try {
    const csrout = csr.replace(/-----BEGIN CERTIFICATE REQUEST-----/g, '').replace(/-----END CERTIFICATE REQUEST-----/g, '').replace(/\s/g, '')
    const dercsr = base64url(Buffer.from(csrout, 'base64'))
    const orderres = await getOrderInfo(orderUrl)
    const res = await apiRequest({
      apiUrl: orderres.finalize,
      directoryUrl: directoryUrl,
      privateKey: accountKey,
      payload: {
        csr: dercsr
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
  if (!orderUrl) {
    throw 'Invalid input: orderUrl is required.'
  }
  try {
    const orderres = await getOrderInfo(orderUrl)
    const certificateurl = orderres.certificate
    const res = await axios.get(certificateurl, {
      headers: {
        'User-Agent': pkg.name + '/' + pkg.version
      }
    })
    const certificates = [res.data]
    const regex = /<([^>]+)>;rel="alternate"/g
    let match
    const alternates = []
    while ((match = regex.exec(res.headers.link))) {
      alternates.push(match[1])
    }
    const promises = alternates.map(async (item) => {
      const alternateres = await getRequest(item)
      certificates.push(alternateres)
    })
    await Promise.all(promises)
    return certificates
  } catch (err) {
    throw err
  }
}
async function deactivateAuthorization({ directoryUrl, accountKey, authorizationUrl }) {
  if (!directoryUrl || !accountKey || !authorizationUrl) {
    throw 'Invalid input: directoryUrl, accountKey and authorizationUrl are required.'
  }
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
  if (!challenge || !accountKey) {
    throw 'Invalid input: challenge and accountKey are required.'
  }
  const jwk = nodecrypto.createPublicKey(accountKey).export({
    format: 'jwk'
  })
  const res = Object.keys(jwk).sort().reduce((result, k) => {
    result[k] = jwk[k]
    return result
  }, {})
  const token = challenge.token
  const thumbprint = nodecrypto.createHash('sha256').update(JSON.stringify(res)).digest('base64url')
  const keyauthorization = token + '.' + thumbprint
  if (challenge.type == 'http-01') {
    return keyauthorization
  }
  return nodecrypto.createHash('sha256').update(keyauthorization).digest('base64url')
}
async function respondChallenge({ directoryUrl, accountKey, challengeUrl }) {
  if (!directoryUrl || !accountKey || !challengeUrl) {
    throw 'Invalid input: directoryUrl, accountKey and challengeUrl are required.'
  }
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
  if (!directoryUrl || !certificate) {
    throw 'Invalid input: directoryUrl and certificate are required.'
  }
  try {
    const directoryres = await getRequest(directoryUrl)
    if (!directoryres.renewalInfo) {
      throw 'RenewalInfo is not supported.'
    }
    const certificateinfo = crypto.getCertificateInfo(certificate)[0]
    const url = directoryres.renewalInfo + '/' + hexbase64url(certificateinfo.authorityKeyIdentifier) + '.' + hexbase64url(certificateinfo.serialNumber)
    return await getRequest(url)
  } catch (err) {
    throw err
  }
}
async function revokeCertificate({ directoryUrl, accountKey, certificateKey, certificate, reason }) {
  if (!directoryUrl || !certificate) {
    throw 'Invalid input: directoryUrl and certificate are required.'
  }
  if (!accountKey && !certificateKey) {
    throw 'Invalid input: accountKey or certificateKey is required.'
  }
  try {
    const leafcertificate = crypto.extractCertificates(certificate)[0]
    const certificateout = leafcertificate.replace(/-----BEGIN CERTIFICATE-----/g, '').replace(/-----END CERTIFICATE-----/g, '').replace(/\s/g, '')
    const dercertificate = base64url(Buffer.from(certificateout, 'base64'))
    const payload = {
      certificate: dercertificate
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
  deactivateAuthorization,
  getChallengeKeyAuthorization,
  respondChallenge,
  getCertificateRenewalInfo,
  revokeCertificate
}