import { existsSync, mkdirSync } from 'fs';
import { generateKeyPair, getKmsKey } from './lib/keys.mjs';
import { generateCsr, issueCert, generateSelfSignedCertificate } from './lib/cert.mjs';
import { constants } from './lib/constants.mjs';

/**
 * @param {Record<string, string>} attributes
 */
function getAttributes(attributes) {
  const result = [];
  for (let [key, value] of Object.entries(attributes)) {
    result.push({
      name: key,
      value,
    });
  }
  return result;
}

async function main() {
  if (!existsSync(constants.outDir)) {
    mkdirSync(constants.outDir);
  }

  // root CA
  // const rootKeypair = await getKmsKey('your-kms-key-arn-here');
  const rootKeypair = generateKeyPair({ name: 'root' });
  const rootCert = await generateSelfSignedCertificate({
    name: 'root',
    keyPair: rootKeypair,
    attributes: getAttributes({ commonName: 'root' }),
  });

  // intermediate CA
  const intKeypair = generateKeyPair({ name: 'intermediate' });
  const intCsr = await generateCsr({
    name: 'intermediate',
    keyPair: intKeypair,
    attributes: getAttributes({
      commonName: 'int',
    }),
  });
  const intCert = await issueCert({
    name: 'intermediate',
    caCert: true,
    csr: intCsr,
    issuingKeypair: rootKeypair,
    issuingCa: rootCert,
  });

  // leaf certificate
  const leafKeypair = generateKeyPair({ name: 'leaf' });
  const leafCsr = await generateCsr({
    name: 'leaf',
    keyPair: leafKeypair,
    attributes: getAttributes({
      commonName: 'leaf',
    }),
  });
  const leafCert = await issueCert({
    name: 'leaf',
    caCert: false,
    csr: leafCsr,
    issuingKeypair: intKeypair,
    issuingCa: intCert,
  });
}

await main();
