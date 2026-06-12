// DESIGN §6.6 / §10 — screen_inventory.json(Phase1→Phase2/WebUI の唯一の契約)の入出力。

import { readFileSync, writeFileSync } from "node:fs";
import type { Screen } from "@veritas/core";

export interface ScreenInventory {
  version: 1;
  generatedAt: string;
  startUrl: string;
  screens: Screen[];
}

export function buildInventory(startUrl: string, screens: Screen[], now: Date = new Date()): ScreenInventory {
  return { version: 1, generatedAt: now.toISOString(), startUrl, screens };
}

export function writeScreenInventory(path: string, inventory: ScreenInventory): void {
  writeFileSync(path, `${JSON.stringify(inventory, null, 2)}\n`, "utf8");
}

export function readScreenInventory(path: string): ScreenInventory {
  return JSON.parse(readFileSync(path, "utf8")) as ScreenInventory;
}
