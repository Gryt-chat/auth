import { GRYT_MARK } from "@gryt/owl";
import { useEffect, useState } from "react";

type Mode = "idle" | "watch" | "hide" | "peek";

/* A revealed password is a text input that still says "password" in its autocomplete. */
function modeOf(el: Element | null): Mode {
  if (el instanceof HTMLButtonElement && el.getAttribute("aria-controls")) {
    el = document.getElementById(el.getAttribute("aria-controls")!);
  }
  if (!(el instanceof HTMLInputElement)) return "idle";
  if (el.type === "password") return "hide";
  if (el.autocomplete.includes("password")) return "peek";
  return el.type === "text" || el.type === "email" ? "watch" : "idle";
}

/** The logo owl. It watches the email field, ducks for a password and peeks when one is shown. */
export function OwlMark() {
  const [mode, setMode] = useState<Mode>("idle");
  const [looking, setLooking] = useState(false);

  useEffect(() => {
    const update = () => setTimeout(() => setMode(modeOf(document.activeElement)));
    const events = ["focusin", "focusout", "click"] as const;
    events.forEach((e) => document.addEventListener(e, update));
    return () => events.forEach((e) => document.removeEventListener(e, update));
  }, []);

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const next = () => {
      timer = setTimeout(() => {
        setLooking(true);
        timer = setTimeout(() => {
          setLooking(false);
          next();
        }, 2000);
      }, 4000 + Math.random() * 5000);
    };
    next();
    return () => clearTimeout(timer);
  }, []);

  const act = mode === "idle" && looking ? " is-looking" : "";
  return (
    <span className="gryt-auth-owl">
      <svg className={`gryt-auth-owl-art is-${mode}${act}`} viewBox="0 0 1024 1024" aria-hidden>
        <g className="gryt-auth-owl-body">
          <path fill="#A495E3" d={GRYT_MARK.body} />
          {GRYT_MARK.wings.map((d) => (
            <path key={d} fill="#7C6EC3" d={d} />
          ))}
          <path fill="#B5A8E6" d={GRYT_MARK.disc} />
          <g className="gryt-auth-owl-eyes">
            {GRYT_MARK.eyes.map((d) => (
              <path key={d} className="gryt-auth-owl-eye" fill="#2E2D5F" d={d} />
            ))}
          </g>
          <path fill="#2E2D5F" d={GRYT_MARK.beak} />
        </g>
      </svg>
    </span>
  );
}
