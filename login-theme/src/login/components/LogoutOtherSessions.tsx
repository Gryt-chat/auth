/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. Keycloak posts `logout-sessions=on`; checked by default.
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
