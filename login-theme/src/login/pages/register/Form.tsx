/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. The fields still come from UserProfileFormFields, at runtime.
 */

import { Button } from "@gryt/ui";
import { useLayoutEffect, useState } from "react";
import { assert } from "tsafe/assert";
import { UserProfileFormFields } from "../../components/UserProfileFormFields";
import { useI18n } from "../../i18n";
import { useKcContext } from "../../KcContext";
import { TermsAcceptance } from "./TermsAcceptance";

export function Form() {
  const { kcContext } = useKcContext();
  assert(kcContext.pageId === "register.ftl");

  const { msg, msgStr } = useI18n();

  const [isFormSubmittable, setIsFormSubmittable] = useState(false);
  const [areTermsAccepted, setAreTermsAccepted] = useState(false);

  useLayoutEffect(() => {
    (window as any)["onSubmitRecaptcha"] = () => {
      const form = document.getElementById("kc-register-form");
      if (form instanceof HTMLFormElement) form.requestSubmit();
    };

    return () => {
      delete (window as any)["onSubmitRecaptcha"];
    };
  }, []);

  return (
    <form
      id="kc-register-form"
      className="gryt-auth-form"
      action={kcContext.url.registrationAction}
      method="post"
    >
      <UserProfileFormFields
        onIsFormSubmittableValueChange={setIsFormSubmittable}
      />

      {kcContext.termsAcceptanceRequired && (
        <TermsAcceptance
          areTermsAccepted={areTermsAccepted}
          onAreTermsAcceptedValueChange={setAreTermsAccepted}
        />
      )}

      {kcContext.recaptchaRequired &&
        (kcContext.recaptchaVisible ||
          kcContext.recaptchaAction === undefined) && (
          <div
            className="g-recaptcha"
            data-size="compact"
            data-sitekey={kcContext.recaptchaSiteKey}
            data-action={kcContext.recaptchaAction}
          />
        )}

      <div id="kc-form-buttons" className="gryt-auth-actions">
        <Button
          type="submit"
          size="large"
          disabled={
            !isFormSubmittable ||
            (kcContext.termsAcceptanceRequired && !areTermsAccepted)
          }
        >
          {msgStr("doRegister")}
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
