import { existsSync, mkdirSync, writeFileSync } from 'fs';
import forge from 'node-forge';
import { constants } from './constants.mjs';
import { KMSClient, SignCommand, GetPublicKeyCommand } from '@aws-sdk/client-kms';

/**
 * @param {{
 *   name: string
 * }} options
 */
export function generateKeyPair({ name }) {
  const forgeKeypair = forge.pki.rsa.generateKeyPair(4096);
  if (!existsSync(`${constants.outDir}/${name}`)) {
    mkdirSync(`${constants.outDir}/${name}`);
  }
  writeFileSync(`${constants.outDir}/${name}/private-key.pem`, forge.pki.privateKeyToPem(forgeKeypair.privateKey));
  writeFileSync(`${constants.outDir}/${name}/public-key.pem`, forge.pki.publicKeyToPem(forgeKeypair.publicKey));
  return forgeKeypair;
}

/**
 * @param {string} kmsKeyId
 */
export async function getKmsKey(kmsKeyId) {
  const kms = new KMSClient();
  const getPublicKeyResponse = await kms.send(new GetPublicKeyCommand({ KeyId: kmsKeyId }));
  const publicKey = forge.pki.publicKeyFromAsn1(
    forge.asn1.fromDer(forge.util.decode64(Buffer.from(getPublicKeyResponse.PublicKey ?? '').toString('base64'))),
  );
  /** @type {forge.pki.rsa.PrivateKey} */
  const privateKey = {
    /**
     * @param {forge.md.MessageDigest | forge.Bytes} md
     * @param {forge.pki.rsa.SignatureScheme} scheme
     * @returns {Promise<forge.Bytes>}
     */
    async sign(md, scheme) {
      /** @type {forge.Base64} */
      let bytes;
      if (typeof md === 'string') {
        bytes = forge.util.encode64(md);
      } else {
        bytes = forge.util.encode64(md.digest().getBytes());
      }
      const kmsArray = Uint8Array.from(Buffer.from(bytes, 'base64'));
      const response = await kms.send(
        new SignCommand({
          KeyId: kmsKeyId,
          Message: kmsArray,
          MessageType: 'DIGEST',
          SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
        }),
      );
      const base64EncodedSignature = Buffer.from(response.Signature ?? '').toString('base64');
      return forge.util.decode64(base64EncodedSignature);
    },
  };
  return {
    publicKey,
    privateKey,
  };
}
