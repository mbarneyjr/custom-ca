import { existsSync, mkdirSync, writeFileSync } from 'fs';
import forge from 'node-forge';
import { randomUUID } from 'crypto';
import { constants } from './constants.mjs';

/**
 * @param {{
 *   name: string
 *   keyPair: forge.pki.rsa.KeyPair
 *   attributes: forge.pki.CertificateField[]
 * }} options
 */
export async function generateSelfSignedCertificate({ name, keyPair, attributes }) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = keyPair.publicKey;
  cert.serialNumber = randomUUID().replace(/-/g, '');
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  cert.setSubject(attributes);
  cert.setIssuer(attributes);
  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: true,
    },
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyCertSign: true,
      cRLSign: true,
    },
  ]);
  cert.sign(keyPair.privateKey, forge.md.sha256.create());
  cert.signature = await cert.signature;
  if (!existsSync(`${constants.outDir}/${name}`)) {
    mkdirSync(`${constants.outDir}/${name}`);
  }
  writeFileSync(`${constants.outDir}/${name}/cert.self-signed.pem`, forge.pki.certificateToPem(cert));
  return cert;
}

/**
 * @param {{
 *   name: string
 *   keyPair: forge.pki.rsa.KeyPair
 *   attributes: forge.pki.CertificateField[]
 * }} options
 */
export async function generateCsr({ name, keyPair, attributes }) {
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keyPair.publicKey;
  csr.setSubject(attributes);
  csr.sign(keyPair.privateKey, forge.md.sha256.create());
  csr.signature = await csr.signature;
  writeFileSync(`${constants.outDir}/${name}/csr.pem`, forge.pki.certificationRequestToPem(csr));
  return csr;
}

/**
 * @param {{
 *   name: string
 *   csr: forge.pki.CertificateSigningRequest
 *   issuingKeypair: forge.pki.rsa.KeyPair
 *   issuingCa: forge.pki.Certificate
 *   caCert: boolean
 * }} options
 */
export async function issueCert({ name, csr, issuingKeypair, issuingCa, caCert }) {
  if (!csr.verify()) {
    throw new Error('CSR not verified');
  }
  const cert = forge.pki.createCertificate();
  cert.serialNumber = randomUUID().replace(/-/g, '');
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  cert.setSubject(csr.subject.attributes);
  cert.setIssuer(issuingCa.subject.attributes);
  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: caCert === true,
    },
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyCertSign: caCert === true,
      cRLSign: caCert === true,
    },
  ]);
  if (csr.publicKey) {
    cert.publicKey = csr.publicKey;
  }
  cert.sign(issuingKeypair.privateKey, forge.md.sha256.create());
  cert.signature = await cert.signature;
  writeFileSync(`${constants.outDir}/${name}/cert.pem`, forge.pki.certificateToPem(cert));
  return cert;
}
