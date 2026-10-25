import { describe, expect, it } from "vitest";
import {
  AUTO_LOCK_MS,
  clearClipboard,
  CLIPBOARD_CLEAR_MS,
  createInactivityTimer,
  filterEntries,
  LEGACY_USERNAME,
  MIN_MASTER_PASSWORD_LENGTH,
  usernameForEditing,
  validateEntryFields,
  validateMasterPassword,
  type VaultEntry,
} from "./vault";
import { afterEach, vi } from "vitest";

const entries: VaultEntry[] = [
  { id: "1", domain: "Example.com", username: "Ana@Example.com", created_at: "2025-01-01" },
  { id: "2", domain: "mail.test", username: "bia", created_at: "2025-01-02" },
];

describe("clipboard timeout", () => {
  it("is configured to fifteen seconds, independently from the inactivity lock", () => {
    expect(CLIPBOARD_CLEAR_MS).toBe(15_000);
    expect(AUTO_LOCK_MS).toBe(5 * 60 * 1000);
  });
});

afterEach(() => {
  vi.useRealTimers();
});

describe("clearClipboard", () => {
  it("calls the native clipboard clear operation", async () => {
    const clear = vi.fn().mockResolvedValue(undefined);

    await clearClipboard(clear);

    expect(clear).toHaveBeenCalledTimes(1);
  });

  it("propagates clipboard write failures so the UI can report them", async () => {
    const clear = vi.fn().mockRejectedValue(new Error("permission denied"));

    await expect(clearClipboard(clear)).rejects.toThrow("permission denied");
  });
});

describe("createInactivityTimer", () => {
  it("runs the timeout only after five minutes without a reset", () => {
    vi.useFakeTimers();
    const onTimeout = vi.fn();
    const timer = createInactivityTimer(onTimeout, AUTO_LOCK_MS);

    timer.reset();
    vi.advanceTimersByTime(AUTO_LOCK_MS - 1);
    expect(onTimeout).not.toHaveBeenCalled();

    timer.reset();
    vi.advanceTimersByTime(AUTO_LOCK_MS - 1);
    expect(onTimeout).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(onTimeout).toHaveBeenCalledOnce();
  });

  it("can cancel a pending timeout", () => {
    vi.useFakeTimers();
    const onTimeout = vi.fn();
    const timer = createInactivityTimer(onTimeout, AUTO_LOCK_MS);

    timer.reset();
    timer.cancel();
    vi.advanceTimersByTime(AUTO_LOCK_MS);

    expect(onTimeout).not.toHaveBeenCalled();
  });
});

describe("validateMasterPassword", () => {
  it("accepts matching passwords with at least eight Unicode characters", () => {
    expect(validateMasterPassword("🔐🔐🔐🔐🔐🔐🔐🔐", "🔐🔐🔐🔐🔐🔐🔐🔐")).toBeNull();
  });

  it("rejects passwords shorter than the configured minimum", () => {
    expect(validateMasterPassword("abc1234", "abc1234")).toContain(
      `${MIN_MASTER_PASSWORD_LENGTH} caracteres`,
    );
  });

  it("rejects mismatched confirmations", () => {
    expect(validateMasterPassword("password1", "password2")).toBe("As senhas não coincidem.");
  });
});

describe("validateEntryFields", () => {
  it("accepts a non-empty domain and password", () => {
    expect(validateEntryFields("example.com", "secret")).toBeNull();
  });

  it("rejects an empty or whitespace-only domain and an empty password", () => {
    expect(validateEntryFields("  ", "secret")).toBe("Domínio e senha são obrigatórios.");
    expect(validateEntryFields("example.com", "")).toBe("Domínio e senha são obrigatórios.");
  });
});

describe("filterEntries", () => {
  it("matches domain and username without case sensitivity", () => {
    expect(filterEntries(entries, "EXAMPLE")).toEqual([entries[0]]);
    expect(filterEntries(entries, "BIA")).toEqual([entries[1]]);
  });

  it("returns all entries for a blank query and none for no match", () => {
    expect(filterEntries(entries, "  ")).toBe(entries);
    expect(filterEntries(entries, "missing")).toEqual([]);
  });
});

describe("usernameForEditing", () => {
  it("clears the legacy placeholder but preserves real usernames", () => {
    expect(usernameForEditing(LEGACY_USERNAME)).toBe("");
    expect(usernameForEditing("ana")).toBe("ana");
  });
});
