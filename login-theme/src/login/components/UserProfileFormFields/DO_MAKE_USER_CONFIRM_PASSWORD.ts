/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. Off: sign-up has no confirm field.
 */

// Change this to true to disable the confirm password field
// The draft has no confirm field; Keycloakify mirrors the password into a hidden one.
export const DO_MAKE_USER_CONFIRM_PASSWORD = false;
