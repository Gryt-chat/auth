/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. `totp`, `totpSecret`, `mode` and `userLabel` post under those names.
 */

import { Button, TextField } from "@gryt/ui";
import { kcSanitize } from "@keycloakify/login-ui/kcSanitize";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";
import { LogoutOtherSessions } from "../../components/LogoutOtherSessions";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "login-config-totp.ftl");

    const { msg, msgStr, advancedMsg } = useI18n();
    const { totp, url, messagesPerField, isAppInitiatedAction, mode } = kcContext;

    const totpError = messagesPerField.existsError("totp");
    const labelError = messagesPerField.existsError("userLabel");

    return (
        <Template
            headerNode={msgStr("loginTotpTitle")}
            displayMessage={!messagesPerField.existsError("totp", "userLabel")}
        >
            <div className="gryt-auth-form">
                <ol id="kc-totp-settings" className="gryt-auth-steps">
                    <li>
                        <p className="gryt-auth-prose">{msg("loginTotpStep1")}</p>
                        <ul id="kc-totp-supported-apps" className="gryt-auth-applist">
                            {totp.supportedApplications.map(app => (
                                <li key={app}>{advancedMsg(app)}</li>
                            ))}
                        </ul>
                    </li>

                    {mode == "manual" ? (
                        <>
                            <li>
                                <p className="gryt-auth-prose">{msg("loginTotpManualStep2")}</p>
                                <p id="kc-totp-secret-key" className="gryt-auth-secret">
                                    {totp.totpSecretEncoded}
                                </p>
                                <p className="gryt-auth-note">
                                    <a className="gryt-auth-link" href={totp.qrUrl} id="mode-barcode">
                                        {msg("loginTotpScanBarcode")}
                                    </a>
                                </p>
                            </li>
                            <li>
                                <p className="gryt-auth-prose">{msg("loginTotpManualStep3")}</p>
                                <ul className="gryt-auth-facts">
                                    <li id="kc-totp-type">
                                        {msg("loginTotpType")}: {msg(`loginTotp.${totp.policy.type}`)}
                                    </li>
                                    <li id="kc-totp-algorithm">
                                        {msg("loginTotpAlgorithm")}: {totp.policy.getAlgorithmKey()}
                                    </li>
                                    <li id="kc-totp-digits">
                                        {msg("loginTotpDigits")}: {totp.policy.digits}
                                    </li>
                                    {totp.policy.type === "totp" ? (
                                        <li id="kc-totp-period">
                                            {msg("loginTotpInterval")}: {totp.policy.period}
                                        </li>
                                    ) : (
                                        <li id="kc-totp-counter">
                                            {msg("loginTotpCounter")}: {totp.policy.initialCounter}
                                        </li>
                                    )}
                                </ul>
                            </li>
                        </>
                    ) : (
                        <li>
                            <p className="gryt-auth-prose">{msg("loginTotpStep2")}</p>
                            {/* A light surface behind it deliberately: the QR is
                                black-on-transparent, and on this theme's dark
                                card that leaves a black square a camera cannot
                                read. */}
                            <div className="gryt-auth-qr">
                                <img
                                    id="kc-totp-secret-qr-code"
                                    src={`data:image/png;base64, ${totp.totpSecretQrCode}`}
                                    alt={msgStr("loginTotpStep2")}
                                />
                            </div>
                            <p className="gryt-auth-note">
                                <a className="gryt-auth-link" href={totp.manualUrl} id="mode-manual">
                                    {msg("loginTotpUnableToScan")}
                                </a>
                            </p>
                        </li>
                    )}

                    <li>
                        <p className="gryt-auth-prose">{msg("loginTotpStep3")}</p>
                        <p className="gryt-auth-note">{msg("loginTotpStep3DeviceName")}</p>
                    </li>
                </ol>

                <form action={url.loginAction} id="kc-totp-settings-form" method="post">
                    <div className="gryt-auth-form">
                        <div>
                            <TextField
                                id="totp"
                                name="totp"
                                type="text"
                                inputMode="numeric"
                                autoComplete="one-time-code"
                                label={msgStr("authenticatorCode")}
                                required
                                error={totpError}
                                aria-invalid={totpError}
                            />
                            {totpError && (
                                <span
                                    id="input-error-otp-code"
                                    className="gryt-auth-error"
                                    aria-live="polite"
                                    dangerouslySetInnerHTML={{
                                        __html: kcSanitize(messagesPerField.get("totp"))
                                    }}
                                />
                            )}
                        </div>

                        <input type="hidden" id="totpSecret" name="totpSecret" value={totp.totpSecret} />
                        {mode && <input type="hidden" id="mode" value={mode} />}

                        <div>
                            <TextField
                                id="userLabel"
                                name="userLabel"
                                type="text"
                                autoComplete="off"
                                label={msgStr("loginTotpDeviceName")}
                                required={totp.otpCredentials.length >= 1}
                                error={labelError}
                                aria-invalid={labelError}
                            />
                            {labelError && (
                                <span
                                    id="input-error-otp-label"
                                    className="gryt-auth-error"
                                    aria-live="polite"
                                    dangerouslySetInnerHTML={{
                                        __html: kcSanitize(messagesPerField.get("userLabel"))
                                    }}
                                />
                            )}
                        </div>

                        <LogoutOtherSessions />

                        <div id="kc-form-buttons" className="gryt-auth-actions">
                            <Button type="submit" id="saveTOTPBtn" size="large">
                                {msgStr("doSubmit")}
                            </Button>
                            {isAppInitiatedAction && (
                                <Button
                                    type="submit"
                                    id="cancelTOTPBtn"
                                    name="cancel-aia"
                                    value="true"
                                    tone="neutral"
                                    size="large"
                                >
                                    {msg("doCancel")}
                                </Button>
                            )}
                        </div>
                    </div>
                </form>
            </div>
        </Template>
    );
}
