/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/pages/select-authenticator/Page.tsx" --revert
 *
 * "Select login method" — the page a passkey user meets, because the browser
 * flow offers webauthn-authenticator-passwordless and the password form as two
 * alternatives at the same level.
 *
 * The original renders each option as a bare <button type="submit"> and leans on
 * kcClsx for the list styling. doUseDefaultCss is false here, so those classes
 * resolve to nothing and the page's own baseline painted every option as a
 * filled accent pill — two primary actions of different widths with centred
 * two-line labels, which is neither a list nor a choice.
 *
 * These are options, not actions: one row each, left-aligned, name over
 * explanation, chevron on the right. The submit-button semantics are kept
 * exactly — Keycloak posts `authenticationExecution`, and the value is what
 * decides which credential the flow continues with.
 */

import { CaretRightIcon } from "@phosphor-icons/react";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "select-authenticator.ftl");

    const { url, auth } = kcContext;
    const { msg, advancedMsg } = useI18n();

    return (
        <Template displayInfo={false} headerNode={msg("loginChooseAuthenticator")}>
            <form
                id="kc-select-credential-form"
                className="gryt-auth-form"
                action={url.loginAction}
                method="post"
            >
                <ul className="gryt-auth-options">
                    {auth.authenticationSelections.map((authenticationSelection, i) => (
                        <li key={i}>
                            <button
                                className="gryt-auth-option"
                                type="submit"
                                name="authenticationExecution"
                                value={authenticationSelection.authExecId}
                            >
                                <span className="gryt-auth-option-text">
                                    <span className="gryt-auth-option-name">
                                        {advancedMsg(authenticationSelection.displayName)}
                                    </span>
                                    <span className="gryt-auth-option-help">
                                        {advancedMsg(authenticationSelection.helpText)}
                                    </span>
                                </span>
                                {/* Decorative: the row is already a button with an
                                    accessible name from the text beside it. */}
                                <CaretRightIcon
                                    className="gryt-auth-option-chevron"
                                    size={16}
                                    aria-hidden
                                />
                            </button>
                        </li>
                    ))}
                </ul>
            </form>
        </Template>
    );
}
