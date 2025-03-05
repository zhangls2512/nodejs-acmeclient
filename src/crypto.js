const crypto = require('crypto')
const { KJUR, KEYUTIL, X509 } = require('jsrsasign')
const net = require('net')
function generateRSAKeyPair(keybits = 2048) {
  if (![2048, 3072, 4096].includes(keybits)) {
    throw 'Invalid keybits. Please provide a valid keysize (2048, 3072, or 4096).'
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: keybits,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  })
  return {
    privateKey: privateKey,
    publicKey: publicKey
  }
}
function generateECDSAKeyPair(curvename = 'prime256v1') {
  if (!['prime256v1', 'secp384r1', 'secp521r1'].includes(curvename)) {
    throw 'Invalid curvename. Please provide a valid curvename (prime256v1, secp384r1, or secp521r1).'
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: curvename,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  })
  return {
    privateKey: privateKey,
    publicKey: publicKey
  }
}
function getKeyInfo(key) {
  if (!key) {
    throw 'Invalid input: key is required.'
  }
  const keyinfo = KEYUTIL.getKey(key)
  if (keyinfo.n) {
    return {
      keyType: 'RSA',
      keyBits: keyinfo.n.bitLength(),
      isPrivate: keyinfo.isPrivate,
      isPublic: keyinfo.isPublic
    }
  }
  if (keyinfo.curveName) {
    return {
      keyType: 'ECDSA',
      curveName: keyinfo.curveName,
      isPrivate: keyinfo.isPrivate,
      isPublic: keyinfo.isPublic
    }
  }
  throw 'Invalid key format.'
}
function generateCsr({ commonName, subjectAltName, privateKey }) {
  if (!subjectAltName || !Array.isArray(subjectAltName) || subjectAltName.length == 0 || !privateKey) {
    throw 'Invalid input: subjectAltName and privateKey are required.'
  }
  const commonname = commonName || subjectAltName[0]
  if (commonname && !subjectAltName.includes(commonname)) {
    subjectAltName.unshift(commonname)
  }
  const subjectaltname = subjectAltName.map(item => {
    if (net.isIP(item)) {
      return { ip: item }
    } else {
      return { dns: item }
    }
  })
  let sigalg = 'SHA256withRSA'
  const keyinfo = getKeyInfo(privateKey)
  if (keyinfo.keyType == 'ECDSA') {
    if (keyinfo.curveName == 'secp256r1') {
      sigalg = 'SHA256withECDSA'
    }
    if (keyinfo.curveName == 'secp384r1') {
      sigalg = 'SHA384withECDSA'
    }
    if (keyinfo.curveName == 'secp521r1') {
      sigalg = 'SHA512withECDSA'
    }
  }
  const publickey = crypto.createPublicKey(privateKey).export({
    type: 'spki',
    format: 'pem'
  })
  const csr = new KJUR.asn1.csr.CertificationRequest({
    subject: {
      CN: commonname
    },
    sbjprvkey: privateKey,
    sbjpubkey: publickey,
    extreq: [
      {
        extname: 'subjectAltName',
        array: subjectaltname
      }
    ],
    sigalg: sigalg
  })
  const pemcsr = csr.getPEM()
  return pemcsr
}
function getCsrInfo(csrin) {
  if (!csrin) {
    throw 'Invalid input: csr is required.'
  }
  const csr = KJUR.asn1.csr.CSRUtil.getParam(csrin)
  return {
    commonName: csr.subject.str.match(/\/CN=([^,]+)/)[1],
    subjectAltName: csr.extreq.find(extension => extension.extname == 'subjectAltName').array.map(item => {
      return Object.values(item)[0]
    }),
    publicKey: csr.sbjpubkey,
    signatureAlgorithm: csr.sigalg
  }
}
function extractCertificates(certificate) {
  const certificatepattern = /-----BEGIN CERTIFICATE-----\n([\s\S]*?)\n-----END CERTIFICATE-----/g
  let match
  const certificates = []
  while ((match = certificatepattern.exec(certificate))) {
    certificates.push(match[0])
  }
  return certificates
}
function getCertificateInfo(certificatein) {
  if (!certificatein) {
    throw 'Invalid input: certificate is required.'
  }
  const certificates = extractCertificates(certificatein)
  let certificatesinfo = []
  certificates.forEach(item => {
    const certificate = new crypto.X509Certificate(item)
    const commonname = certificate.subject.match(/CN=([^,\\\n]+)/)[1]
    const issuercommonname = certificate.issuer.match(/CN=([^,\\\n]+)/)[1]
    let subjectaltname = []
    if (certificate.subjectAltName) {
      subjectaltname = certificate.subjectAltName.match(/:(.*?)(?=,|$)/g).map(match => match.slice(1).trim())
    }
    const x509 = new X509()
    x509.readCertPEM(item)
    certificatesinfo.push({
      commonName: commonname,
      subjectAltName: subjectaltname,
      issuerCommonName: issuercommonname,
      startDate: certificate.validFromDate,
      endDate: certificate.validToDate,
      authorityKeyIdentifier: x509.getExtAuthorityKeyIdentifier().kid.hex,
      serialNumber: x509.getSerialNumberHex()
    })
  })
  return certificatesinfo
}
module.exports = {
  generateRSAKeyPair,
  generateECDSAKeyPair,
  getKeyInfo,
  generateCsr,
  getCsrInfo,
  extractCertificates,
  getCertificateInfo
}