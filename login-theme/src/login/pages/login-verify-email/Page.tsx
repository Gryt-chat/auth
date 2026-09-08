/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. No primary button: the thing to do is read your email.
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
