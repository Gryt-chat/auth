/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/pages/login-reset-password/Form.tsx" --revert
 *
 * Rebuilt on @gryt/ui. Field names and ids are Keycloak's contract; only the
 * rendering changed.
 */

import { Button, TextField } from "@gryt/ui";
import { kcSanitize } from "@keycloakify/login-ui/kcSanitize";
import { assert } from "tsafe/assert";
import { useI18n } from "../../i18n";
import { useKcContext } from "../../KcContext";

export function Form() {
  const { kcContext } = useKcContext();
  assert(kcContext.pageId === "login-reset-password.ftl");

  const { msg, msgStr } = useI18n();

  return (
    <form
      id="kc-reset-password-form"
      className="gryt-auth-form"
      action={kcContext.url.loginAction}
      method="post"
    >
      <div>
        <TextField
          id="username"
          name="username"
          type="text"
          label={
            !kcContext.realm.loginWithEmailAllowed
              ? msgStr("username")
              : !kcContext.realm.registrationEmailAsUsername
                ? msgStr("usernameOrEmail")
                : msgStr("email")
          }
          autoFocus
          defaultValue={kcContext.auth.attemptedUsername ?? ""}
          aria-invalid={kcContext.messagesPerField.existsError("username")}
        />
        {kcContext.messagesPerField.existsError("username") && (
          <span
            id="input-error-username"
            className="gryt-auth-error"
            aria-live="polite"
            dangerouslySetInnerHTML={{
              __html: kcSanitize(kcContext.messagesPerField.get("username")),
            }}
          />
        )}
      </div>

      <div id="kc-form-buttons" className="gryt-auth-actions">
        <Button type="submit" size="large">
          {msgStr("doSubmit")}
        </Button>
      </div>

      <div id="kc-form-options" className="gryt-auth-footer">
        <a className="gryt-auth-link" href={kcContext.url.loginUrl}>
          {msg("backToLogin")}
        </a>
      </div>
    </form>
  );
}
