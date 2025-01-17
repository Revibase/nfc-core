export const readDataWithAttestation = (
  key: number[],
  attestation_key: number[]
) => {
  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  return [
    0x80,
    0x22,
    0x00,
    0x00,
    0x21,
    0x41,
    0x04,
    ...key,
    0x45,
    0x04,
    ...attestation_key,
    0x46,
    0x01,
    0x21,
    0x47,
    0x10,
    ...randomBytes,
    0x00,
  ];
};
