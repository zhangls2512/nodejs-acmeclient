const crypto = require('crypto')
const { X509 } = require('jsrsasign')
const net = require('net')
function generateRSAKeyPair(keybits = 2048) {
  return crypto.generateKeyPairSync('rsa', {
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
}
function generateECDSAKeyPair(curvename = 'prime256v1') {
  return crypto.generateKeyPairSync('ec', {
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
}
function generateMLDSAKeyPair(dimension = 65) {
  return crypto.generateKeyPairSync('ml-dsa-' + dimension, {
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  })
}
function getKeyInfo(key) {
  const isprivate = key.includes('-----BEGIN PRIVATE KEY-----')
  const ispublic = key.includes('-----BEGIN PUBLIC KEY-----')
  if (isprivate) {
    const keyinfo = crypto.createPrivateKey(key)
    if (keyinfo.asymmetricKeyType == 'rsa') {
      return {
        keyType: 'RSA',
        keyBits: keyinfo.asymmetricKeyDetails.modulusLength,
        isPrivate: isprivate,
        isPublic: ispublic
      }
    }
    if (keyinfo.asymmetricKeyType == 'ec') {
      return {
        keyType: 'ECDSA',
        curveName: keyinfo.asymmetricKeyDetails.namedCurve,
        isPrivate: isprivate,
        isPublic: ispublic
      }
    }
    if (keyinfo.asymmetricKeyType.startsWith('ml-dsa-')) {
      return {
        keyType: 'MLDSA',
        dimension: Number(keyinfo.asymmetricKeyType.split('-')[2]),
        isPrivate: isprivate,
        isPublic: ispublic
      }
    }
  }
  if (ispublic) {
    const keyinfo = crypto.createPublicKey(key)
    if (keyinfo.asymmetricKeyType == 'rsa') {
      return {
        keyType: 'RSA',
        keyBits: keyinfo.asymmetricKeyDetails.modulusLength,
        isPrivate: isprivate,
        isPublic: ispublic
      }
    }
    if (keyinfo.asymmetricKeyType == 'ec') {
      return {
        keyType: 'ECDSA',
        curveName: keyinfo.asymmetricKeyDetails.namedCurve,
        isPrivate: isprivate,
        isPublic: ispublic
      }
    }
    if (keyinfo.asymmetricKeyType.startsWith('ml-dsa-')) {
      return {
        keyType: 'MLDSA',
        dimension: Number(keyinfo.asymmetricKeyType.split('-')[2]),
        isPrivate: isprivate,
        isPublic: ispublic
      }
    }
  }
}
function generateCsr({ commonName, subjectAltName, privateKey }) {
  const commonname = commonName || subjectAltName[0]
  if (commonname && !subjectAltName.includes(commonname)) {
    subjectAltName.unshift(commonname)
  }
  let sigalg
  let sigalgoid = Buffer.from('')
  const keyinfo = getKeyInfo(privateKey)
  if (keyinfo.keyType == 'RSA') {
    sigalg = 'sha256'
    sigalgoid = '1.2.840.113549.1.1.11'
  }
  if (keyinfo.keyType == 'ECDSA') {
    if (keyinfo.curveName == 'prime256v1') {
      sigalg = 'sha256'
      sigalgoid = Buffer.from('06082a8648ce3d040302', 'hex')
    }
    if (keyinfo.curveName == 'secp384r1') {
      sigalg = 'sha384'
      sigalgoid = Buffer.from('06082a8648ce3d040303', 'hex')
    }
    if (keyinfo.curveName == 'secp521r1') {
      sigalg = 'sha512'
      sigalgoid = Buffer.from('06082a8648ce3d040304', 'hex')
    }
  }
  if (keyinfo.keyType == 'MLDSA') {
    if (keyinfo.dimension == 44) {
      sigalgoid = Buffer.from('0609608648016503040311', 'hex')
    }
    if (keyinfo.dimension == 65) {
      sigalgoid = Buffer.from('0609608648016503040312', 'hex')
    }
    if (keyinfo.dimension == 87) {
      sigalgoid = Buffer.from('0609608648016503040313', 'hex')
    }
  }
  const publickey = crypto.createPublicKey(privateKey).export({
    type: 'spki',
    format: 'der'
  })
  function asn1node(tag, value) {
    const tagbuf = Buffer.from([tag])
    let lengthbuf
    const length = value.length
    if (length <= 127) {
      lengthbuf = Buffer.from([length])
    } else {
      const tempbytes = []
      let templength = length
      while (templength > 0) {
        tempbytes.unshift(templength & 0xff)
        templength >>= 8
      }
      lengthbuf = Buffer.concat([Buffer.from([0x80 | tempbytes.length]), Buffer.from(tempbytes)])
    }
    return Buffer.concat([tagbuf, lengthbuf, value])
  }
  const subject = asn1node(0x30, asn1node(0x31, asn1node(0x30, Buffer.concat([Buffer.from('0603550403', 'hex'), asn1node(0x0c, Buffer.from(commonname))]))))
  const sans = []
  function ipv6buffer(ip) {
    const result = Buffer.alloc(16)
    let fullparts = []
    const parts = ip.split(':')
    const emptyindex = parts.indexOf('')
    if (emptyindex != -1) {
      const left = parts.slice(0, emptyindex).filter(Boolean)
      const right = parts.slice(emptyindex + 1).filter(Boolean)
      const missingcount = 8 - (left.length + right.length)
      const middle = new Array(missingcount).fill('0')
      fullparts = [...left, ...middle, ...right]
    } else {
      fullparts = parts
    }
    for (let i = 0; i < 8; i++) {
      const val = parseInt(fullparts[i], 16) || 0
      result.writeUInt16BE(val, i * 2)
    }
    return result
  }
  subjectAltName.forEach(name => {
    const ipversion = net.isIP(name)
    if (ipversion == 0) {
      sans.push(asn1node(0x82, Buffer.from(name)))
    }
    if (ipversion == 4) {
      sans.push(asn1node(0x87, Buffer.from(name.split('.').map(item => Number(item)))))
    }
    if (ipversion == 6) {
      sans.push(asn1node(0x87, ipv6buffer(name)))
    }
  })
  const attributes = asn1node(0xa0, asn1node(0x30, Buffer.concat([Buffer.from('06092a864886f70d01090e', 'hex'), asn1node(0x31, asn1node(0x30, asn1node(0x30, Buffer.concat([Buffer.from('0603551d11', 'hex'), asn1node(0x04, asn1node(0x30, Buffer.concat(sans)))]))))])))
  const version = asn1node(0x02, Buffer.from([0x00]))
  const csi = asn1node(0x30, Buffer.concat([version, subject, publickey, attributes]))
  const signature = crypto.sign(sigalg, csi, privateKey)
  const csrder = asn1node(0x30, Buffer.concat([csi, asn1node(0x30, sigalgoid), asn1node(0x03, Buffer.concat([Buffer.from([0x00]), signature]))]))
  return '-----BEGIN CERTIFICATE REQUEST-----\n' + csrder.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE REQUEST-----'
}
function getCsrInfo(csrpem) {
  const csrder = Buffer.from(csrpem.replace(/-----BEGIN CERTIFICATE REQUEST-----/g, '').replace(/-----END CERTIFICATE REQUEST-----/g, '').replace(/\s/g, ''), 'base64')
  const result = {
    commonName: '',
    subjectAltName: [],
    publicKey: '',
    signatureAlgorithm: ''
  }
  const oidmap = {
    '2a864886f70d01010b': 'SHA256withRSA',
    '2a8648ce3d040302': 'SHA256withECDSA',
    '2a8648ce3d040303': 'SHA384withECDSA',
    '2a8648ce3d040304': 'SHA512withECDSA',
    '608648016503040311': 'ML-DSA-44',
    '608648016503040312': 'ML-DSA-65',
    '608648016503040313': 'ML-DSA-87'
  }
  function readnode(buffer, offset) {
    let ptr = offset
    const tag = buffer[ptr++]
    let length = buffer[ptr++]
    if (length & 0x80) {
      const lenbytes = length & 0x7f
      length = 0
      for (let i = 0; i < lenbytes; i++) {
        length = (length << 8) | buffer[ptr++]
      }
    }
    const valuestart = ptr
    const valueend = ptr + length
    return {
      tag: tag,
      length: length,
      value: buffer.subarray(valuestart, valueend),
      raw: buffer.subarray(offset, valueend),
      nextoffset: valueend
    }
  }
  const root = readnode(csrder, 0)
  const csi = readnode(root.value, 0)
  result.signatureAlgorithm = oidmap[readnode(readnode(root.value, csi.nextoffset).value, 0).value.toString('hex')]
  const version = readnode(csi.value, 0)
  const subject = readnode(csi.value, readnode(csi.value, 0).nextoffset)
  const spki = readnode(csi.value, subject.nextoffset)
  result.publicKey = '-----BEGIN PUBLIC KEY-----\n' + spki.raw.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END PUBLIC KEY-----'
  let subptr = 0
  while (subptr < subject.value.length) {
    const node = readnode(subject.value, subptr)
    if (node.tag == 0x31 || node.tag == 0x30) {
      let innerptr = 0
      while (innerptr < node.value.length) {
        const innernode = readnode(node.value, innerptr)
        if (innernode.tag == 0x30) {
          const oidnode = readnode(innernode.value, 0)
          if (oidnode.tag == 0x06 && oidnode.value.toString('hex') == '550403') {
            const valnode = readnode(innernode.value, oidnode.nextoffset)
            result.commonName = valnode.value.toString()
          }
        }
        innerptr = innernode.nextoffset
      }
    }
    subptr = node.nextoffset
  }
  if (spki.nextoffset < csi.value.length) {
    const attributes = readnode(csi.value, spki.nextoffset)
    let attrptr = 0
    while (attrptr < attributes.value.length) {
      const attrnode = readnode(attributes.value, attrptr)
      if (attrnode.tag == 0x30) {
        const oidnode = readnode(attrnode.value, 0)
        if (oidnode.tag == 0x06 && oidnode.value.toString('hex') == '2a864886f70d01090e') {
          const setnode = readnode(attrnode.value, oidnode.nextoffset)
          const seqnode = readnode(setnode.value, 0)
          const subseqnode = readnode(seqnode.value, 0)
          const extoidnode = readnode(subseqnode.value, 0)
          if (extoidnode.tag == 0x06 && extoidnode.value.toString('hex') == '551d11') {
            const octetnode = readnode(subseqnode.value, extoidnode.nextoffset)
            const sanseq = readnode(octetnode.value, 0)
            let sanptr = 0
            while (sanptr < sanseq.value.length) {
              const sanitem = readnode(sanseq.value, sanptr)
              if (sanitem.tag == 0x82) {
                result.subjectAltName.push(sanitem.value.toString())
              }
              if (sanitem.tag == 0x87) {
                if (sanitem.length == 4) {
                  result.subjectAltName.push(Array.from(sanitem.value).join('.'))
                }
                if (sanitem.length == 16) {
                  const parts = []
                  for (let i = 0; i < 16; i += 2) {
                    parts.push(sanitem.value.readUInt16BE(i).toString(16))
                  }
                  result.subjectAltName.push(parts.join(':').replace(/(^|:)(0:)+/g, '::').replace(/::+/g, '::'))
                }
              }
              sanptr = sanitem.nextoffset
            }
          }
        }
      }
      attrptr = attrnode.nextoffset
    }
  }
  return result
}
function extractCertificates(certificate) {
  const regex = /-----BEGIN CERTIFICATE-----[[\s\S]*?-----END CERTIFICATE-----/g
  const matches = certificate.match(regex)
  if (!matches) {
    return []
  }
  return matches
}
function getCertificateInfo(certificatein) {
  const certificates = extractCertificates(certificatein)
  const certificatesinfo = []
  certificates.forEach(item => {
    const certificate = new crypto.X509Certificate(item)
    let commonname = ''
    try {
      commonname = certificate.subject.match(/CN=([^,\\\n]+)/)[1]
    } catch {
    }
    let subjectaltname = []
    if (certificate.subjectAltName) {
      subjectaltname = certificate.subjectAltName.match(/:(.*?)(?=,|$)/g).map(match => match.slice(1).trim())
    }
    const x509 = new X509()
    x509.readCertPEM(item)
    let authorityKeyIdentifier = ''
    try {
      authorityKeyIdentifier = x509.getExtAuthorityKeyIdentifier().kid.hex
    } catch {
    }
    certificatesinfo.push({
      commonName: commonname,
      subjectAltName: subjectaltname,
      issuerCommonName: certificate.issuer.match(/CN=([^,\\\n]+)/)[1],
      startDate: new Date(certificate.validFrom),
      endDate: new Date(certificate.validTo),
      authorityKeyIdentifier: authorityKeyIdentifier,
      serialNumber: certificate.serialNumber.toLowerCase()
    })
  })
  return certificatesinfo
}
module.exports = {
  generateRSAKeyPair,
  generateECDSAKeyPair,
  generateMLDSAKeyPair,
  getKeyInfo,
  generateCsr,
  getCsrInfo,
  extractCertificates,
  getCertificateInfo
}