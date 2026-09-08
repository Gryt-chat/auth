/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. Keycloak posts `authenticationExecution`; the value decides.
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
