export interface INfcHandler {
  start(): Promise<void>;
  isSupported(): Promise<boolean>;
  requestTechnology(
    tech: NfcTech | NfcTech[],
    options?: RegisterTagEventOpts
  ): Promise<NfcTech | null>;
  cancelTechnologyRequest(): Promise<void>;
  isoDepHandler: IsoDepHandler;
  setTimeout(timeout: number): Promise<void>; // Optional
}

interface IsoDepHandler {
  transceive: (bytes: number[]) => Promise<number[]>;
}
export enum NfcTech {
  Ndef = "Ndef",
  NfcA = "NfcA",
  NfcB = "NfcB",
  NfcF = "NfcF",
  NfcV = "NfcV",
  IsoDep = "IsoDep",
  MifareClassic = "MifareClassic",
  MifareUltralight = "MifareUltralight",
  MifareIOS = "mifare",
  Iso15693IOS = "iso15693",
  FelicaIOS = "felica",
  NdefFormatable = "NdefFormatable",
}
interface RegisterTagEventOpts {
  alertMessage?: string;
  invalidateAfterFirstRead?: boolean;
  isReaderModeEnabled?: boolean;
  readerModeFlags?: number;
  readerModeDelay?: number;
}
