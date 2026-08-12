/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/pages/login-verify-email/Page.tsx" --revert
 *
 * Every account that gets made lands here — the realm sets verifyEmail, so
 * registration ends on this page rather than signed in.
 *
 * The one useful thing to do here is not on this page: go and read your email.
 * So it deliberately has no primary button. What it does instead is separate the
 * three jobs the original ran together in two paragraphs of body text — what
 * happened, where it went, and what to do if it didn't arrive.
 *
 * The re-send offer keeps Keycloak's own sentence, link and all. Splitting it
 * into a button would need a label, and the only label available is
 * "Click here" — every alternative would be a string invented here, untranslated
 * in the twenty-nine other languages the catalogue ships. It gets a rule and a
 * quiet block instead, which is what it deserves: a fallback, not an action.
 */

import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "login-verify-email.ftl");

    const { msg, msgStr } = useI18n();
    const { url, user } = kcContext;

    return (
        <Template displayInfo={false} headerNode={msgStr("emailVerifyTitle")}>
            <div className="gryt-auth-form">
                {/* The address is passed through the message rather than pulled
                    out beside it: it is the {0} of instruction1, and in several
                    languages that placeholder is not at the end of the sentence. */}
                <p className="gryt-auth-prose">
                    {msg("emailVerifyInstruction1", user?.email ?? "")}
                </p>

                <div className="gryt-auth-alternatives">
                    <p className="gryt-auth-note">
                        {msg("emailVerifyInstruction2")}{" "}
                        <a className="gryt-auth-link" href={url.loginAction}>
                            {msgStr("doClickHere")}
                        </a>{" "}
                        {msg("emailVerifyInstruction3")}
                    </p>
                </div>
            </div>
        </Template>
    );
}
