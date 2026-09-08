/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. No PatternFly.
 */

import type { ReactNode } from "react";
import type { ClassKey } from "@keycloakify/login-ui/useKcClsx";

// The library's own stylesheet — the same one the client and the docs import.
// This is what stops the login page being a separate design problem.
import "@gryt/ui/styles.css";
import "./gryt.css";

type Classes = { [key in ClassKey]?: string };

type StyleLevelCustomization = {
    doUseDefaultCss: boolean;
    classes?: Classes;
    loadCustomStylesheet?: () => void;
    Provider?: (props: { children: ReactNode }) => ReactNode;
};

export function useStyleLevelCustomization(): StyleLevelCustomization {
    return {
        // No PatternFly. Keycloak's default login CSS is what the old theme spent 610 lines
        // fighting; these pages are @gryt/ui, so it would only give those rules a target.
        doUseDefaultCss: false
    };
}
