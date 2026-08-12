/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/components/PasswordWrapper.tsx" --revert
 *
 * The reveal toggle beside a password field.
 *
 * The original renders a Font Awesome <i> for the eye icon. That icon font
 * arrived with PatternFly, which this theme no longer loads, so it rendered as
 * an empty pill. Phosphor instead — the same icon set @gryt/ui itself uses,
 * imported directly rather than through a wrapper library.
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
