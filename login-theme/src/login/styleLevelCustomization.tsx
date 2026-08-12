/**
 * This file has been claimed for ownership from @keycloakify/login-ui version 250004.7.2.
 * To relinquish ownership and restore this file to its original content, run the following command:
 * 
 * $ npx keycloakify own --path "login/styleLevelCustomization.tsx" --revert
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
        // No PatternFly. Keycloak's default login CSS is what the old theme
        // spent 610 lines fighting; these pages are built from @gryt/ui
        // instead, so loading it would only give those rules something to
        // override.
        doUseDefaultCss: false
    };
}
