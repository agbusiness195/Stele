/**
 * Basic i18n (internationalization) foundation for the Kervyx protocol.
 *
 * Provides translated protocol messages in five languages:
 * English, German, French, Spanish, and Japanese.
 * Supports runtime locale switching, custom translation overrides,
 * and fallback to the key itself when no translation is found.
 *
 * @packageDocumentation
 */

// ─── Types ───────────────────────────────────────────────────────────────────

/** Supported locale identifiers. */
export type Locale = 'en' | 'de' | 'fr' | 'es' | 'ja';

/** A catalog of translations for a single locale. */
export interface TranslationCatalog {
  /** The locale this catalog belongs to. */
  locale: Locale;
  /** Key-value mapping of translation keys to translated strings. */
  translations: Record<string, string>;
}

// ─── Translation keys ────────────────────────────────────────────────────────

/** Core protocol messages that need translation. */
export const TRANSLATION_KEYS = {
  COVENANT_VIOLATED: 'covenant_violated',
  ACCESS_DENIED: 'access_denied',
  TRUST_INSUFFICIENT: 'trust_insufficient',
  CERTIFICATE_EXPIRED: 'certificate_expired',
  COMPLIANCE_WARNING: 'compliance_warning',
  AUDIT_PASSED: 'audit_passed',
  AUDIT_FAILED: 'audit_failed',
  IDENTITY_VERIFIED: 'identity_verified',
  IDENTITY_UNVERIFIED: 'identity_unverified',
  ENFORCEMENT_ACTIVE: 'enforcement_active',
} as const;

// ─── Translation catalogs ────────────────────────────────────────────────────

/** All built-in translation catalogs indexed by locale. */
export const CATALOGS: Record<Locale, TranslationCatalog> = {
  en: {
    locale: 'en',
    translations: {
      covenant_violated: 'Covenant has been violated',
      access_denied: 'Access denied',
      trust_insufficient: 'Trust score is insufficient',
      certificate_expired: 'Certificate has expired',
      compliance_warning: 'Compliance warning detected',
      audit_passed: 'Audit passed successfully',
      audit_failed: 'Audit failed',
      identity_verified: 'Identity has been verified',
      identity_unverified: 'Identity is unverified',
      enforcement_active: 'Enforcement is active',
    },
  },
  de: {
    locale: 'de',
    translations: {
      covenant_violated: 'Vereinbarung wurde verletzt',
      access_denied: 'Zugriff verweigert',
      trust_insufficient: 'Vertrauenswert ist unzureichend',
      certificate_expired: 'Zertifikat ist abgelaufen',
      compliance_warning: 'Compliance-Warnung erkannt',
      audit_passed: 'Audit erfolgreich bestanden',
      audit_failed: 'Audit fehlgeschlagen',
      identity_verified: 'Identität wurde verifiziert',
      identity_unverified: 'Identität ist nicht verifiziert',
      enforcement_active: 'Durchsetzung ist aktiv',
    },
  },
  fr: {
    locale: 'fr',
    translations: {
      covenant_violated: 'Le contrat a été violé',
      access_denied: 'Accès refusé',
      trust_insufficient: 'Score de confiance insuffisant',
      certificate_expired: 'Le certificat a expiré',
      compliance_warning: 'Avertissement de conformité détecté',
      audit_passed: 'Audit réussi',
      audit_failed: 'Audit échoué',
      identity_verified: 'Identité vérifiée',
      identity_unverified: 'Identité non vérifiée',
      enforcement_active: 'Application active',
    },
  },
  es: {
    locale: 'es',
    translations: {
      covenant_violated: 'El convenio ha sido violado',
      access_denied: 'Acceso denegado',
      trust_insufficient: 'Puntuación de confianza insuficiente',
      certificate_expired: 'El certificado ha expirado',
      compliance_warning: 'Advertencia de cumplimiento detectada',
      audit_passed: 'Auditoría aprobada exitosamente',
      audit_failed: 'Auditoría fallida',
      identity_verified: 'Identidad verificada',
      identity_unverified: 'Identidad no verificada',
      enforcement_active: 'Aplicación activa',
    },
  },
  ja: {
    locale: 'ja',
    translations: {
      covenant_violated: '契約に違反しました',
      access_denied: 'アクセスが拒否されました',
      trust_insufficient: '信頼スコアが不十分です',
      certificate_expired: '証明書の有効期限が切れています',
      compliance_warning: 'コンプライアンス警告が検出されました',
      audit_passed: '監査に合格しました',
      audit_failed: '監査に失敗しました',
      identity_verified: '本人確認が完了しました',
      identity_unverified: '本人確認が未完了です',
      enforcement_active: '強制適用が有効です',
    },
  },
};

// ─── Module-level state ──────────────────────────────────────────────────────

/** The current default locale. */
let defaultLocale: Locale = 'en';

// ─── Functions ───────────────────────────────────────────────────────────────

/**
 * Translate a key into the specified locale.
 *
 * Falls back to the default locale if no locale is specified.
 * Returns the key itself if no translation is found.
 *
 * @param key - The translation key (e.g. 'covenant_violated').
 * @param locale - Optional locale override. Uses the default locale if omitted.
 * @returns The translated string, or the key itself if not found.
 */
export function t(key: string, locale?: Locale): string {
  const targetLocale = locale ?? defaultLocale;
  const catalog = CATALOGS[targetLocale];

  if (catalog && key in catalog.translations) {
    return catalog.translations[key]!;
  }

  // Fall back to English if the target locale doesn't have the key
  if (targetLocale !== 'en') {
    const enCatalog = CATALOGS.en;
    if (key in enCatalog.translations) {
      return enCatalog.translations[key]!;
    }
  }

  // Return the key itself as a last resort
  return key;
}

/**
 * Set the module-level default locale.
 *
 * Subsequent calls to `t()` without an explicit locale will use this value.
 *
 * @param locale - The locale to set as default.
 */
export function setDefaultLocale(locale: Locale): void {
  defaultLocale = locale;
}

/**
 * Get the current default locale.
 *
 * @returns The current default locale.
 */
export function getDefaultLocale(): Locale {
  return defaultLocale;
}

/**
 * Add or override a single translation entry.
 *
 * If the locale's catalog doesn't exist yet, it is created automatically.
 *
 * @param locale - The target locale.
 * @param key - The translation key.
 * @param value - The translated string.
 */
export function addTranslation(locale: Locale, key: string, value: string): void {
  const catalog = CATALOGS[locale];
  if (catalog) {
    catalog.translations[key] = value;
  }
}

/**
 * Return all supported locale identifiers.
 *
 * @returns An array of supported Locale strings.
 */
export function getSupportedLocales(): Locale[] {
  return Object.keys(CATALOGS) as Locale[];
}
