/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. A "Show" pill inside the field, as in the draft.
 */

import type { JSX } from "react";
import { useEffect, useState } from "react";
import { useI18n } from "../i18n";

export function PasswordWrapper(props: {
  passwordInputId: string;
  children: JSX.Element;
}) {
  const { passwordInputId, children } = props;

  const { msgStr } = useI18n();

  const [isPasswordRevealed, setRevealed] = useState(false);
  const toggleIsPasswordRevealed = () => setRevealed((r) => !r);

  // Keycloakify's own hook asserts the input exists on first run, which StrictMode's remount breaks.
  useEffect(() => {
    const input = document.getElementById(passwordInputId);
    if (input instanceof HTMLInputElement) input.type = isPasswordRevealed ? "text" : "password";
  });

  return (
    <div className="gryt-auth-password">
      {children}
      <button
        type="button"
        className="gryt-auth-reveal"
        aria-label={msgStr(isPasswordRevealed ? "hidePassword" : "showPassword")}
        aria-controls={passwordInputId}
        aria-pressed={isPasswordRevealed}
        onMouseDown={(e) => e.preventDefault()}
        onClick={toggleIsPasswordRevealed}
      >
        {msgStr(isPasswordRevealed ? "grytHide" : "grytShow")}
      </button>
    </div>
  );
}
