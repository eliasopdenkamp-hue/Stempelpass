/**
 * Login MFA bootstrap must fail closed when the membership query is filtered
 * (for example by RLS because app.tenant_id is not set). A NULL result is not
 * equivalent to "MFA not required".
 */
export interface MfaBootstrapRow { required: boolean | null | undefined }

export function requireVerifiedMfaBootstrap(row: MfaBootstrapRow | undefined): boolean {
  if (!row || typeof row.required !== 'boolean') throw new Error('MFA_BOOTSTRAP_UNVERIFIED');
  return row.required;
}
