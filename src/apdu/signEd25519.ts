import { encodeLength, encodeTLVLength } from "../utils";

export const signEd25519 = (chainId: number[], message: number[]) => {
  const payload = [
    0x41,
    0x04,
    ...chainId,
    0x42,
    0x01,
    0xa3,
    0x43,
    ...encodeTLVLength(message.length),
    ...message,
  ];

  return [
    0x80,
    0x03,
    0x0c,
    0x09,
    ...encodeLength(payload.length),
    ...payload,
    ...(payload.length > 255 ? [0x00, 0x40] : [0x00]),
  ];
};
