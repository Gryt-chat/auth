/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. Phosphor, not Font Awesome: PatternFly's icon font is gone.
 */

import { IconButton } from "@gryt/ui";
import { Eye, EyeSlash } from "@phosphor-icons/react";
import { useIsPasswordRevealed } from "@keycloakify/login-ui/tools/useIsPasswordRevealed";
import type { JSX } from "react";
import { useI18n } from "../i18n";

export function PasswordWrapper(props: {
  passwordInputId: string;
  children: JSX.Element;
}) {
  const { passwordInputId, children } = props;

  const { msgStr } = useI18n();

  const { isPasswordRevealed, toggleIsPasswordRevealed } =
    useIsPasswordRevealed({ passwordInputId });

  return (
    <div className="gryt-auth-password">
      {children}
      <IconButton
        type="button"
        size="small"
        className="gryt-auth-reveal"
        aria-label={msgStr(isPasswordRevealed ? "hidePassword" : "showPassword")}
        aria-controls={passwordInputId}
        onClick={toggleIsPasswordRevealed}
      >
        {isPasswordRevealed ? <EyeSlash size={18} /> : <Eye size={18} />}
      </IconButton>
    </div>
  );
}
