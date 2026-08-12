/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/components/LogoutOtherSessions.tsx" --revert
 *
 * "Sign out of other devices", offered wherever a credential changes — updating
 * a password, registering a passkey, setting up an authenticator.
 *
 * Rebuilt on @gryt/ui so it matches the remember-me checkbox on the sign-in
 * page, which is the only other checkbox in the theme. The name and the default
 * are Keycloak's contract: it posts `logout-sessions=on`, and it is checked by
 * default because changing a credential usually means you think somebody else
 * has the old one.
 */

import { Checkbox } from "@gryt/ui";
import { useI18n } from "../i18n";

export function LogoutOtherSessions() {
  const { msg } = useI18n();

  return (
    <div id="kc-form-options" className="gryt-auth-row">
      <label className="gryt-auth-remember">
        <Checkbox id="logout-sessions" name="logout-sessions" value="on" defaultChecked />
        {msg("logoutOtherSessions")}
      </label>
    </div>
  );
}
