const crypto = require('crypto')
const net = require('net')
const pkijs = require('pkijs')
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
function oidtobuffer(oid) {
  const parts = oid.split('.').map(item => Number(item))
  let bytes = [parts[0] * 40 + parts[1]]
  for (let i = 2; i < parts.length; i++) {
    let item = parts[i]
    const chunks = []
    while (item > 0) {
      chunks.unshift(item & 0x7f)
      item >>= 7
    }
    for (let j = 0; j < chunks.length - 1; j++) {
      chunks[j] |= 0x80
    }
    bytes = bytes.concat(chunks)
  }
  return Buffer.from(bytes)
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
    sigalgoid = oidtobuffer('1.2.840.113549.1.1.11')
  }
  if (keyinfo.keyType == 'ECDSA') {
    if (keyinfo.curveName == 'prime256v1') {
      sigalg = 'sha256'
      sigalgoid = oidtobuffer('1.2.840.10045.4.3.2')
    }
    if (keyinfo.curveName == 'secp384r1') {
      sigalg = 'sha384'
      sigalgoid = oidtobuffer('1.2.840.10045.4.3.3')
    }
    if (keyinfo.curveName == 'secp521r1') {
      sigalg = 'sha512'
      sigalgoid = oidtobuffer('1.2.840.10045.4.3.4')
    }
  }
  if (keyinfo.keyType == 'MLDSA') {
    if (keyinfo.dimension == 44) {
      sigalgoid = oidtobuffer('2.16.840.1.101.3.4.3.17')
    }
    if (keyinfo.dimension == 65) {
      sigalgoid = oidtobuffer('2.16.840.1.101.3.4.3.18')
    }
    if (keyinfo.dimension == 87) {
      sigalgoid = oidtobuffer('2.16.840.1.101.3.4.3.19')
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
  const subject = asn1node(0x30, asn1node(0x31, asn1node(0x30, Buffer.concat([asn1node(0x06, oidtobuffer('2.5.4.3')), asn1node(0x0c, Buffer.from(commonname))]))))
  const sans = []
  function ipv6buffer(ip) {
    const result = Buffer.alloc(16)
    let fullparts = []
    const parts = ip.split(':')
    const emptyindex = parts.indexOf('')
    if (emptyindex != -1) {
      const left = parts.slice(0, emptyindex).filter(item => item)
      const right = parts.slice(emptyindex + 1).filter(item => item)
      const missingcount = 8 - (left.length + right.length)
      const middle = new Array(missingcount).fill('0')
      fullparts = left.concat(middle).concat(right)
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
  const attributes = asn1node(0xa0, asn1node(0x30, Buffer.concat([asn1node(0x06, oidtobuffer('1.2.840.113549.1.9.14')), asn1node(0x31, asn1node(0x30, asn1node(0x30, Buffer.concat([asn1node(0x06, oidtobuffer('2.5.29.17')), asn1node(0x04, asn1node(0x30, Buffer.concat(sans)))]))))])))
  const version = asn1node(0x02, Buffer.from([0x00]))
  const csi = asn1node(0x30, Buffer.concat([version, subject, publickey, attributes]))
  const signature = crypto.sign(sigalg, csi, privateKey)
  const csrder = asn1node(0x30, Buffer.concat([csi, asn1node(0x30, asn1node(0x06, sigalgoid)), asn1node(0x03, Buffer.concat([Buffer.from([0x00]), signature]))]))
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
    '1.2.840.10045.4.1': 'sha1WithECDSA',
    '1.2.840.10045.4.3.1': 'sha224WithECDSA',
    '1.2.840.10045.4.3.2': 'sha256WithECDSA',
    '1.2.840.10045.4.3.3': 'sha384WithECDSA',
    '1.2.840.10045.4.3.4': 'sha512WithECDSA',
    '2.16.840.1.101.3.4.3.9': 'sha3-224WithECDSA',
    '2.16.840.1.101.3.4.3.10': 'sha3-256WithECDSA',
    '2.16.840.1.101.3.4.3.11': 'sha3-384WithECDSA',
    '2.16.840.1.101.3.4.3.12': 'sha3-512WithECDSA',
    '1.2.840.10040.4.3': 'sha1WithDSA',
    '2.16.840.1.101.3.4.3.1': 'sha224WithDSA',
    '2.16.840.1.101.3.4.3.2': 'sha256WithDSA',
    '1.2.840.1.101.3.4.3.3': 'sha384WithDSA',
    '1.2.840.1.101.3.4.3.4': 'sha512WithDSA',
    '2.16.840.1.101.3.4.3.5': 'sha3-224WithDSA',
    '2.16.840.1.101.3.4.3.6': 'sha3-256WithDSA',
    '2.16.840.1.101.3.4.3.7': 'sha3-384WithDSA',
    '2.16.840.1.101.3.4.3.8': 'sha3-512WithDSA',
    '1.2.840.113549.1.1.2': 'md2WithRSA',
    '1.2.840.113549.1.1.3': 'md4WithRSA',
    '1.2.840.113549.1.1.4': 'md5WithRSA',
    '1.3.36.3.3.1.2': 'ripemd160WithRSA',
    '1.2.840.113549.1.1.5': 'sha1WithRSA',
    '1.2.840.113549.1.1.11': 'sha256WithRSA',
    '1.2.840.113549.1.1.12': 'sha384WithRSA',
    '1.2.840.113549.1.1.13': 'sha512WithRSA',
    '1.2.840.113549.1.1.14': 'sha224WithRSA',
    '1.2.840.113549.1.1.15': 'sha512-224WithRSA',
    '1.2.840.113549.1.1.16': 'sha512-256WithRSA',
    '1.2.156.10197.1.504': 'sm3WithRSA',
    '2.16.840.1.101.3.4.3.13': 'sha3-224WithRSA',
    '2.16.840.1.101.3.4.3.14': 'sha3-256WithRSA',
    '2.16.840.1.101.3.4.3.15': 'sha3-384WithRSA',
    '2.16.840.1.101.3.4.3.16': 'sha3-512WithRSA',
    '2.16.840.1.101.3.4.3.17': 'ML-DSA-44',
    '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
    '2.16.840.1.101.3.4.3.19': 'ML-DSA-87'
  }
  const oidhexmap = {}
  Object.keys(oidmap).forEach(oid => {
    oidhexmap[oidtobuffer(oid).toString('hex')] = oidmap[oid]
  })
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
  result.signatureAlgorithm = oidhexmap[readnode(readnode(root.value, csi.nextoffset).value, 0).value.toString('hex')]
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
          if (oidnode.tag == 0x06 && oidnode.value.toString('hex') == oidtobuffer('2.5.4.3').toString('hex')) {
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
        if (oidnode.tag == 0x06 && oidnode.value.toString('hex') == oidtobuffer('1.2.840.113549.1.9.14').toString('hex')) {
          const setnode = readnode(attrnode.value, oidnode.nextoffset)
          const seqnode = readnode(setnode.value, 0)
          const subseqnode = readnode(seqnode.value, 0)
          const extoidnode = readnode(subseqnode.value, 0)
          if (extoidnode.tag == 0x06 && extoidnode.value.toString('hex') == oidtobuffer('2.5.29.17').toString('hex')) {
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
    const pkicertificate = pkijs.Certificate.fromBER(certificate.raw)
    certificatesinfo.push({
      commonName: commonname,
      subjectAltName: subjectaltname,
      issuerCommonName: certificate.issuer.match(/CN=([^,\\\n]+)/)[1],
      startDate: new Date(certificate.validFrom),
      endDate: new Date(certificate.validTo),
      authorityKeyIdentifier: Buffer.from(pkicertificate.extensions.find(item => item.extnID == '2.5.29.35').parsedValue.keyIdentifier.valueBlock.valueHexView).toString('hex'),
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