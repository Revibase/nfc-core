import { Chain } from "../types";

export const BLOCKCHAIN: Record<string, Chain> = {
  SOLANA: { id: 0x01, curve: 0x40, name: "Solana" },
  ETHEREUM: { id: 0x02, curve: 0x41, name: "Ethereum" },
  BITCOIN: { id: 0x03, curve: 0x42, name: "Bitcoin" },
};
