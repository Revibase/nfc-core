export const readData = (key: number[]) => {
  return [
    0x80,
    0x02,
    0x00,
    0x00,
    ...[0x00, 0x00, 0x06],
    0x41,
    0x04,
    ...key,
    ...[0x00, 0x00],
  ];
};
