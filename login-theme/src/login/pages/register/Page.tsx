/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. Google and Apple, then terms and the sign-in link, below the form.
 */

import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { Template } from "../../components/Template";
import { useI18n } from "../../i18n";
import { SocialProviders } from "../login/SocialProviders";
import { Form } from "./Form";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "register.ftl");

    const { msg, msgStr, advancedMsg } = useI18n();

    return (
        <Template
            headerNode={
                kcContext.messageHeader !== undefined
                    ? advancedMsg(kcContext.messageHeader)
                    : msg("registerTitle")
            }
            subtitleNode={msgStr("grytRegisterSub")}
            displayMessage={kcContext.messagesPerField.exists("global")}
            socialProvidersNode={kcContext.social?.providers?.length ? <SocialProviders /> : null}
            displayInfo
            infoNode={
                <div className="gryt-auth-info-stack">
                    <p className="gryt-auth-note">
                        {msg("grytTermsBefore")}{" "}
                        <a className="gryt-auth-link" href="https://gryt.chat/terms" target="_blank" rel="noreferrer">{msg("grytTerms")}</a>{" "}
                        {msg("grytTermsAnd")}{" "}
                        <a className="gryt-auth-link" href="https://gryt.chat/privacy" target="_blank" rel="noreferrer">{msg("grytPrivacy")}</a>.
                    </p>
                    <span id="kc-form-options">
                        {msg("grytHaveAccount")}{" "}
                        <a className="gryt-auth-link" href={kcContext.url.loginUrl}>
                            {msg("doLogIn")}
                        </a>
                    </span>
                </div>
            }
        >
            <Form />
        </Template>
    );
}
