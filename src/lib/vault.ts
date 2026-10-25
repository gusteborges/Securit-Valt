export interface VaultEntry {
  id: string;
  domain: string;
  username: string;
  created_at: string;
}

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

export function filterEntries(list: VaultEntry[], query: string): VaultEntry[] {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) return list;
  return list.filter(
    (entry) =>
      entry.domain.toLowerCase().includes(normalizedQuery) ||
      entry.username.toLowerCase().includes(normalizedQuery),
  );
}

export function usernameForEditing(username: string): string {
  return username === LEGACY_USERNAME ? "" : username;
}
