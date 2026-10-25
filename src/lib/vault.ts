export interface VaultEntry {
  id: string;
  domain: string;
  username: string;
  created_at: string;
  favorite: boolean;
}

export interface PasswordGeneratorOptions {
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
}

export const MIN_GENERATED_PASSWORD_LENGTH = 8;
export const MAX_GENERATED_PASSWORD_LENGTH = 128;

export const MIN_MASTER_PASSWORD_LENGTH = 8;
export const LEGACY_USERNAME = "[indisponível — registro legado]";
export const CLIPBOARD_CLEAR_MS = 15_000;
export const AUTO_LOCK_MS = 5 * 60 * 1000;

export function createInactivityTimer(onTimeout: () => void, delayMs: number) {
  let timer: ReturnType<typeof setTimeout> | null = null;

  return {
    reset() {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => {
        timer = null;
        onTimeout();
      }, delayMs);
    },
    cancel() {
      if (timer) clearTimeout(timer);
      timer = null;
    },
  };
}

export async function clearClipboard(clear: () => Promise<void>): Promise<void> {
  await clear();
}

export function validateMasterPassword(password: string, confirmation: string): string | null {
  if (Array.from(password).length < MIN_MASTER_PASSWORD_LENGTH) {
    return `A senha mestra deve ter pelo menos ${MIN_MASTER_PASSWORD_LENGTH} caracteres.`;
  }
  if (password !== confirmation) {
    return "As senhas não coincidem.";
  }
  return null;
}

export function validateEntryFields(domain: string, password: string): string | null {
  if (!domain.trim() || !password) {
    return "Domínio e senha são obrigatórios.";
  }
  return null;
}

export function filterEntries(
  list: VaultEntry[],
  query: string,
  favoritesOnly = false,
): VaultEntry[] {
  const candidates = favoritesOnly ? list.filter((entry) => entry.favorite) : list;
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) return candidates;
  return candidates.filter(
    (entry) =>
      entry.domain.toLowerCase().includes(normalizedQuery) ||
      entry.username.toLowerCase().includes(normalizedQuery),
  );
}

export function generatePassword(
  length: number,
  options: PasswordGeneratorOptions,
): string {
  if (
    !Number.isInteger(length) ||
    length < MIN_GENERATED_PASSWORD_LENGTH ||
    length > MAX_GENERATED_PASSWORD_LENGTH
  ) {
    throw new RangeError(
      `O tamanho deve ficar entre ${MIN_GENERATED_PASSWORD_LENGTH} e ${MAX_GENERATED_PASSWORD_LENGTH} caracteres.`,
    );
  }

  const groups = [
    options.uppercase ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ" : "",
    options.lowercase ? "abcdefghijklmnopqrstuvwxyz" : "",
    options.numbers ? "0123456789" : "",
    options.symbols ? "!@#$%^&*()-_=+[]{};:,.?/" : "",
  ].filter((group) => group.length > 0);

  if (groups.length === 0) {
    throw new Error("Selecione pelo menos um tipo de caractere.");
  }

  const availableCharacters = groups.join("");
  const password = groups.map((group) => group[randomIndex(group.length)]);

  while (password.length < length) {
    password.push(availableCharacters[randomIndex(availableCharacters.length)]);
  }

  for (let index = password.length - 1; index > 0; index -= 1) {
    const swapIndex = randomIndex(index + 1);
    [password[index], password[swapIndex]] = [password[swapIndex], password[index]];
  }

  return password.join("");
}

function randomIndex(maxExclusive: number): number {
  const uint32Range = 0x1_0000_0000;
  const rejectionLimit = Math.floor(uint32Range / maxExclusive) * maxExclusive;
  const randomValue = new Uint32Array(1);

  do {
    crypto.getRandomValues(randomValue);
  } while (randomValue[0] >= rejectionLimit);

  return randomValue[0] % maxExclusive;
}

export function usernameForEditing(username: string): string {
  return username === LEGACY_USERNAME ? "" : username;
}
