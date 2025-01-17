import bs58 from "bs58";
import {
  createAddress,
  readData,
  readDataWithAttestation,
  selectApplet,
  signEd25519,
} from "./apdu";
import { Chain, INfcHandler, NfcTech } from "./types";
import {
  BLOCKCHAIN,
  hexToUint8Array,
  parseX509FromNumberArray,
  toLittleEndian,
  verifyData,
} from "./utils";
/**
 * A singleton class to manage NFC operations with secure elements.
 * This class provides methods for reading secure data, signing payloads,
 * and interacting with NFC chips.
 */
export default class NfcCore {
  private nfcHandler: INfcHandler;
  private isAndroid: boolean;
  private isReady: boolean = false;
  private static TIMEOUT: number = 5 * 1000;
  private static MAX_APDU_SIZE: number = 900;
  private static ASSET_ID: number[] = [0x00, 0x00, 0x00, 0x00]; // Reserved ID for the asset
  private static CHAIN_ID: number[] = [0x01, 0x00, 0x00, 0x00]; // Reserved ID for the public key
  private static ATTESTATION_KEY: number[] = [0xf0, 0x00, 0x00, 0x12]; // Provisioned attestation key by NXP
  private static ATTESTATION_KEY_CERT: number[] = [0xf0, 0x00, 0x00, 0x13]; // Provisioned attestation key certificate by NXP
  private static AID: number[] = [
    0xa0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01, 0x03,
    0x00, 0x00, 0x00, 0x00,
  ];
  private static CERTIFICATE_PUBKEY = hexToUint8Array(
    "04999e37435ffbdc7078f13a3e005ba9dba6c6f89bd150d779903daff84b2520cdee050155bead493f625f894eb04a54315e86844ee4a58c78471e9ca6149163b4"
  ); // Certificate Pubkey from NXP

  /**
   * Creates a new instance of NfcProxy.
   *
   * @param {INfcHandler} nfcHandler - The NFC handler implementation.
   * @param {boolean} isAndroid - The NFC handler implementation.
   */
  constructor(nfcHandler: INfcHandler, isAndroid: boolean) {
    this.nfcHandler = nfcHandler;
    this.isAndroid = isAndroid;
    this.init();
  }

  private async init() {
    try {
      const supported = await this.nfcHandler.isSupported();
      if (supported) {
        await this.nfcHandler.start();
        this.isReady = true;
      } else {
        throw Error("NFC is not supported on this device.");
      }
    } catch (error) {}
  }

  /**
   * Closes the current NFC connection.
   * This method should be called after completing NFC operations to release resources.
   *
   * @throws {Error} If the NFC handler fails to cancel the technology request.
   */
  public async close() {
    await this.nfcHandler.cancelTechnologyRequest();
  }

  /**
   * Reads secure element data from the NFC chip, including wallet addresses and optional mint information.
   *
   * @returns {Promise<{walletAddress: string; mint: string | null; blockchain: Chain | null} | undefined>}
   *   An object containing the wallet address, optional mint, and blockchain information, or undefined if an error occurs.
   *
   * @throws {Error} If NFC operations fail, including technology request or data parsing.
   */
  public async readSecureElement(): Promise<
    | { walletAddress: string; mint: string | null; blockchain: Chain | null }
    | undefined
  > {
    try {
      await this.ensureReady();
      const attestationKeyCertificateResponse = await this.transceiveAndCheck(
        readData(NfcCore.ATTESTATION_KEY_CERT),
        "Reading attestation key certificate failed"
      );
      const attestationKey = await parseX509FromNumberArray(
        attestationKeyCertificateResponse.slice(4),
        NfcCore.CERTIFICATE_PUBKEY
      );
      const storedAddress = await this.readStoredPubkey(attestationKey);

      const storedAsset = await this.readStoredAsset(attestationKey);

      return {
        walletAddress: bs58.encode(toLittleEndian(storedAddress)),
        mint: storedAsset ? bs58.encode(storedAsset.slice(1)) : null,
        blockchain:
          Object.entries(BLOCKCHAIN).find(
            (x) => storedAsset && x[1].id === storedAsset[0]
          )?.[1] ?? null,
      };
    } catch (error: any) {
      throw new Error(error.message);
    } finally {
      await this.close();
    }
  }

  /**
   * Signs a raw payload using the NFC chip and returns the signed payload.
   *
   * @param {Uint8Array} payload - The raw payload to be signed.
   *
   * @returns {Promise<number[]>} The signed payload as an array of bytes.
   *
   * @throws {Error} If the payload size exceeds the maximum allowed size,
   *                 or if NFC operations fail.
   */
  public async signRawPayload(payload: Uint8Array): Promise<number[]> {
    try {
      if (payload.length > NfcCore.MAX_APDU_SIZE) {
        throw new Error(
          `Transaction size cannot exceed ${NfcCore.MAX_APDU_SIZE} bytes, Size: ${payload.length}`
        );
      }
      await this.ensureReady();
      const response = await this.transceiveAndCheck(
        signEd25519(NfcCore.CHAIN_ID, Array.from(payload)),
        "Signing Transaction failed"
      );
      return toLittleEndian(response.slice(4));
    } catch (error: any) {
      throw new Error(error.message);
    } finally {
      await this.close();
    }
  }

  /**
   * Ensures that the NFC manager is ready for operations.
   * Initializes the NFC technology and selects the applet.
   *
   * @throws {Error} If the NFC manager is not initialized, or if applet selection fails.
   */
  private async ensureReady() {
    if (!this.isReady) {
      throw Error("NFC is not supported on this device.");
    }
    await this.nfcHandler.requestTechnology(NfcTech.IsoDep, {
      invalidateAfterFirstRead: false,
    });
    if (this.isAndroid) {
      // only works for android, by default ios have a timeout of 60s
      await this.nfcHandler.setTimeout(NfcCore.TIMEOUT);
    }
    await this.transceiveAndCheck(
      selectApplet(NfcCore.AID),
      "Selecting Applet failed"
    );
  }

  /**
   * Sends a command to the NFC chip and verifies the response.
   *
   * @param {number[]} command - The command to send to the NFC chip.
   * @param {string} errorMsg - The error message to throw if the command fails.
   *
   * @returns {Promise<number[]>} The NFC chip's response, excluding status bytes.
   *
   * @throws {Error} If the NFC chip's response indicates an error.
   */
  private async transceiveAndCheck(
    command: number[],
    errorMsg: string
  ): Promise<number[]> {
    const response = await this.nfcHandler.isoDepHandler.transceive(command);
    if (response.at(-2) !== 0x90 || response.at(-1) !== 0x00) {
      throw new Error(errorMsg);
    }
    return response.slice(0, -2);
  }

  /**
   * Reads the stored public key from the NFC chip.
   *
   * @param {Uint8Array} attestationKey - The attestation key used for verification.
   *
   * @returns {Promise<number[]>} The stored public key as an array of bytes.
   *
   * @throws {Error} If the key attributes are invalid, or if the key cannot be read.
   */
  private async readStoredPubkey(
    attestationKey: Uint8Array
  ): Promise<number[]> {
    const storedPubkey = await this.readStoredDataWithFallback(
      () => readDataWithAttestation(NfcCore.CHAIN_ID, NfcCore.ATTESTATION_KEY),
      () => createAddress(NfcCore.CHAIN_ID, BLOCKCHAIN.SOLANA.curve),
      attestationKey,
      "Reading Public Key failed",
      "Generating Public Key failed"
    );
    if (!storedPubkey) {
      throw new Error("Unable to read publickey");
    }
    const { data: pubKey, attributes } = storedPubkey;
    if (attributes.objectClass !== 1) {
      throw new Error("Object is not a valid key");
    }
    if (attributes.origin !== 2) {
      throw new Error("Key is not generated from secure element!");
    }
    if (attributes.authenticationIndicator === 2) {
      throw new Error("Key should not be an authentication object");
    }
    if (attributes.policy.join("") !== [8, 0, 0, 0, 0, 24, 32, 0, 0].join("")) {
      throw new Error("Key policy is not set correctly");
    }

    return pubKey;
  }

  /**
   * Reads the stored asset data from the NFC chip.
   *
   * @param {Uint8Array} attestationKey - The attestation key used for verification.
   *
   * @returns {Promise<number[] | null>} The stored asset as an array of bytes, or null if no asset is found.
   *
   * @throws {Error} If the asset policy is incorrect or if the data cannot be read.
   */
  private async readStoredAsset(
    attestationKey: Uint8Array
  ): Promise<number[] | null> {
    const storedAsset = await this.readStoredDataWithFallback(
      () => readDataWithAttestation(NfcCore.ASSET_ID, NfcCore.ATTESTATION_KEY),
      undefined,
      attestationKey,
      "Reading Stored Asset failed",
      undefined
    );
    if (!storedAsset) {
      return null;
    }
    const { data: mint, attributes } = storedAsset;
    if (attributes.policy.join("") !== [8, 0, 0, 0, 0, 0, 32, 0, 0].join("")) {
      throw new Error("Asset is set with wrong policy");
    }

    return mint;
  }

  /**
   * Reads stored data from the NFC chip with a fallback mechanism to create the data if it does not exist.
   *
   * @param {() => number[]} readCommand - A function that generates the command to read the data.
   * @param {(() => number[]) | undefined} createCommand - A function that generates the command to create the data, or undefined if creation is not supported.
   * @param {Uint8Array} attestationKey - The attestation key used for verification.
   * @param {string} readErrorMsg - The error message to throw if reading fails.
   * @param {string | undefined} createErrorMsg - The error message to throw if creation fails.
   *
   * @returns {Promise<{data: number[]; attributes: any} | null>}
   *   The stored data and its attributes, or null if both reading and creation fail.
   *
   * @throws {Error} If verification fails or if both reading and creation fail.
   */
  private async readStoredDataWithFallback(
    readCommand: () => number[],
    createCommand: (() => number[]) | undefined,
    attestationKey: Uint8Array,
    readErrorMsg: string,
    createErrorMsg: string | undefined
  ): Promise<{ data: number[]; attributes: any } | null> {
    try {
      let response = await this.transceiveAndCheck(readCommand(), readErrorMsg);
      return verifyData(response, attestationKey, readErrorMsg);
    } catch {
      if (!createCommand || !createErrorMsg) {
        return null;
      }
      await this.transceiveAndCheck(createCommand(), createErrorMsg);
      const response = await this.transceiveAndCheck(
        readCommand(),
        readErrorMsg
      );
      return verifyData(response, attestationKey, readErrorMsg);
    }
  }
}
