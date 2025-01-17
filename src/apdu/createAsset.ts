export const createAsset = (
  id: number[],
  assetIdentifier: number[],
  assetId: number[]
) => {
  const data = [id].concat(assetId);
  const payload = [
    0x11,
    0x09,
    0x08,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x20,
    0x00,
    0x00,
    0x41,
    0x04,
    ...assetIdentifier,
    0x43,
    0x02,
    0x00,
    data.length,
    0x44,
    data.length,
    ...data,
  ];

  return [0x80, 0x01, 0x06, 0x00, payload.length, ...payload];
};
