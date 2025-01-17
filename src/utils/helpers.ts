import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { ASN1HEX, X509 } from "jsrsasign";

const x509 = new X509();
/**
 * Converts a big-endian array to a little-endian array.
 * @param {number[]} bigEndianArray - The big-endian array.
 * @returns {number[]} The little-endian array, reversed in chunks of 32 bytes.
 */
export function toLittleEndian(bigEndianArray: number[]): number[] {
  const chunkSize = 32;
  const littleEndianArray: number[] = [];
  for (let i = 0; i < bigEndianArray.length; i += chunkSize) {
    const chunk = bigEndianArray.slice(i, i + chunkSize);
    littleEndianArray.push(...chunk.reverse());
  }
  return littleEndianArray;
}

/**
 * Encodes a length value into a TLV-compliant format.
 * Supports single-byte, two-byte, and three-byte encodings.
 *
 * @param {number} length - The length to encode.
 * @returns {number[]} The encoded length as an array of bytes.
 * @throws {Error} If the length exceeds 65535.
 */
export function encodeTLVLength(length: number): number[] {
  if (length <= 127) {
    return [length];
  } else if (length <= 255) {
    return [0x81, length];
  } else if (length <= 65535) {
    return [0x82, (length >> 8) & 0xff, length & 0xff];
  } else {
    throw new Error("Length exceeds maximum supported size of 65535.");
  }
}
export function encodeLength(length: number): number[] {
  if (length <= 255) {
    return [length];
  } else {
    return [0x00, (length >> 8) & 0xff, length & 0xff];
  }
}

/**
 * Parses a secure object payload from the NFC chip into key-value pairs.
 *
 * @param {number[]} payload - The payload to parse.
 * @returns {Record<string, number[]>} An object mapping tags (e.g., "TAG_1") to their associated byte values.
 */
export function parseSecureObjectPayload(
  payload: number[]
): Record<string, number[]> {
  const parsedData = new Map<string, number[]>();
  let index = 0;

  while (index < payload.length) {
    const tag = payload[index];
    index += 1;

    let length = payload[index];
    index += 1;

    if (length === 0x81) {
      length = payload[index];
      index += 1;
    } else if (length === 0x82) {
      length = (payload[index] << 8) | payload[index + 1];
      index += 2;
    }
    const value = payload.slice(index, index + length);
    index += length;

    switch (tag) {
      case 0x41:
        parsedData.set("TAG_1", value);
        break;
      case 0x42:
        parsedData.set("TAG_2", value);
        break;
      case 0x43:
        parsedData.set("TAG_3", value);
        break;
      case 0x44:
        parsedData.set("TAG_4", value);
        break;
      case 0x45:
        parsedData.set("TAG_5", value);
        break;
      case 0x46:
        parsedData.set("TAG_6", value);
        break;
      default:
        break;
    }
  }

  return Object.fromEntries(parsedData);
}

/**
 * Verifies and extracts the parsed address from the secure object payload.
 * Combines TAG_1 through TAG_5, hashes them, and verifies the signature in TAG_6.
 *
 * @param {Record<string, number[]>} parsedData - The parsed data from the payload.
 * @param {Uint8Array} attestationKey - The attestation key for verification.
 * @returns {Promise<number[] | null>} The verified address (TAG_1) or null if verification fails.
 */
export async function verifyAndExtractParsedAddress(
  parsedData: {
    [k: string]: number[];
  },
  attestationKey: Uint8Array
): Promise<number[] | null> {
  const dataToVerify = new Uint8Array([
    ...parsedData["TAG_1"],
    ...parsedData["TAG_2"],
    ...parsedData["TAG_3"],
    ...parsedData["TAG_4"],
    ...parsedData["TAG_5"],
  ]);

  const hash = sha256(dataToVerify);
  if (p256.verify(new Uint8Array(parsedData["TAG_6"]), hash, attestationKey)) {
    return parsedData["TAG_1"];
  }
  return null;
}

/**
 * Extracts attributes from the parsed data.
 *
 * @param {number[]} parsedData - The parsed data as an array of bytes.
 * @returns {Record<string, any>} The extracted attributes, including object ID, class, and policies.
 */
export function extractAttributes(parsedData: number[]): Record<string, any> {
  const objectId = parsedData.slice(0, 4);
  const objectClass = parsedData[4];
  const authenticationIndicator = parsedData[5];
  const authCounter = parsedData.slice(6, 8);
  const authID = parsedData.slice(8, 12);
  const maxAuthAttempt = parsedData.slice(13, 14);
  const policy = parsedData.slice(14, parsedData.length - 1);
  const origin = parsedData[parsedData.length - 1];
  return {
    objectId,
    objectClass,
    authenticationIndicator,
    authCounter,
    authID,
    maxAuthAttempt,
    policy,
    origin,
  };
}

/**
 * Verifies the stored data from the NFC chip.
 * Parses the response, verifies the address, and extracts attributes.
 *
 * @param {number[]} response - The response from the NFC chip.
 * @param {Uint8Array} attestationKey - The attestation key for verification.
 * @param {string} errorMsg - The error message to throw if verification fails.
 * @returns {Promise<{data: number[], attributes: any}>}
 *   The verified data and its attributes.
 * @throws {Error} If verification fails.
 */
export async function verifyData(
  response: number[],
  attestationKey: Uint8Array,
  errorMsg: string
): Promise<{ data: number[]; attributes: any }> {
  const parsed = parseSecureObjectPayload(response);
  const data = await verifyAndExtractParsedAddress(parsed, attestationKey);
  if (!data) throw new Error(errorMsg);
  return { data, attributes: extractAttributes(parsed["TAG_2"]) };
}

/**
 * Parses an X.509 certificate from a DER-encoded number array and verifies its signature.
 *
 * @param {number[]} derCert - The DER-encoded certificate as a number array.
 * @param {Uint8Array} certificatePubkey - The public key for signature verification.
 * @returns {Promise<Uint8Array>} The parsed certificate's public key as a Uint8Array.
 * @throws {Error} If the certificate signature is invalid.
 */
export async function parseX509FromNumberArray(
  derCert: number[],
  certificatePubkey: Uint8Array
): Promise<Uint8Array> {
  const hexCert = bytesToHex(derCert);
  x509.readCertHex(hexCert);
  const tbsCert = ASN1HEX.getTLVbyList(x509.hex, 0, [0], "30");
  if (tbsCert) {
    const hash = sha256(hexToUint8Array(tbsCert));
    const signature = x509.getSignatureValueHex();
    if (p256.verify(signature, hash, certificatePubkey)) {
      return hexToUint8Array(x509.getSPKIValue());
    }
  }
  throw new Error("Unauthorised certificate signature.");
}

/**
 * Converts a hexadecimal string into a Uint8Array.
 *
 * @param {string} hexString - The hexadecimal string to convert.
 * @returns {Uint8Array} The resulting Uint8Array.
 * @throws {Error} If the input string is invalid or contains non-hexadecimal characters.
 */
export function hexToUint8Array(hexString: string): Uint8Array {
  if (hexString.length % 2 !== 0) {
    throw new Error("Invalid hexadecimal string: length must be even.");
  }

  const bytes = [];
  for (let i = 0; i < hexString.length; i += 2) {
    const byte = hexString.slice(i, i + 2);
    const value = parseInt(byte, 16);
    if (isNaN(value)) {
      throw new Error(
        `Invalid hexadecimal string: contains invalid characters.`
      );
    }
    bytes.push(value);
  }

  return new Uint8Array(bytes);
}

/**
 * Converts a Uint8Array or byte array to a hexadecimal string.
 *
 * @param {Uint8Array | number[]} byteArray - The array of bytes to convert.
 * @returns {string} The resulting hexadecimal string.
 */
export function bytesToHex(byteArray: Uint8Array | number[]): string {
  return Array.from(byteArray, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}
