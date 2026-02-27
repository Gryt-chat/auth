// Gryt Keycloak theme helper:
// - Email + password UX:
//   - Login label says "Email" (Keycloak still posts "username")
//   - Registration shows only Email + Password; hides Username / First / Last name
//   - Auto-fills hidden fields from the email so Keycloak validation passes
//
// This is intentionally a stopgap; later we can configure User Profile in-realm.
(function () {
  function findInput(selectorList) {
    for (const sel of selectorList) {
      const el = document.querySelector(sel);
      if (el) return el;
    }
    return null;
  }

  function setLabelText(forId, text) {
    const label = document.querySelector(`label[for="${forId}"]`);
    if (label) label.textContent = text;
  }

  function hideFormGroupFor(input) {
    if (!input) return;
    let p = input.parentElement;
    while (p) {
      if (p.classList.contains("pf-c-form__group") || p.classList.contains("form-group")) {
        p.style.display = "none";
        return;
      }
      p = p.parentElement;
    }
  }

  function sanitizeToSlug(value) {
    return (value || "")
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 50);
  }

  function simpleHash(str) {
    // Deterministic tiny hash to help keep usernames unique-ish across similar localparts.
    // Not security-related.
    let h = 0;
    for (let i = 0; i < str.length; i++) {
      h = (h * 31 + str.charCodeAt(i)) | 0;
    }
    return Math.abs(h);
  }

  function apply() {
    // Remove password visibility toggle ("eye") everywhere
    for (const btn of document.querySelectorAll("[data-password-toggle]")) {
      btn.remove();
    }

    // On the login page, move "Register" link right under the Sign In button
    const registerLink =
      document.querySelector("#kc-registration a") ||
      document.querySelector("a[href*='login-actions/registration']");
    const formButtons = document.getElementById("kc-form-buttons");
    if (registerLink && formButtons && !document.querySelector(".gryt-secondary-button")) {
      const a = registerLink.cloneNode(true);
      a.textContent = "Create a new account";
      a.classList.add("gryt-secondary-button");
      a.setAttribute("role", "button");
      a.setAttribute("tabindex", "8");

      formButtons.insertAdjacentElement("afterend", a);
    }

    // Login page: call it "Email" (Keycloak still uses name="username")
    const loginForm = document.getElementById("kc-form-login");
    if (loginForm) {
      setLabelText("username", "Email");
      const loginUserInput = findInput(["#username", 'input[name="username"]']);
      if (loginUserInput) {
        loginUserInput.setAttribute("autocomplete", "email");
        loginUserInput.setAttribute("inputmode", "email");
        loginUserInput.setAttribute("placeholder", "Email");
      }
    }

    // Registration page: show only email + password
    const registerForm = document.getElementById("kc-register-form") || document.querySelector("form[action*='registration']");
    if (!registerForm) return;

    const emailInput = findInput(["#email", 'input[name="email"]']);
    if (!emailInput) return;

    const usernameInput = findInput(["#username", 'input[name="username"]']);
    const firstNameInput = findInput(["#firstName", 'input[name="firstName"]']);
    const lastNameInput = findInput(["#lastName", 'input[name="lastName"]']);

    // Hide fields we don't want to collect
    if (usernameInput) hideFormGroupFor(usernameInput);
    hideFormGroupFor(firstNameInput);
    hideFormGroupFor(lastNameInput);

    // Force hidden fields derived from email so Keycloak validation passes
    function sync() {
      const email = (emailInput.value || "").trim();
      if (!email) return;

      const emailSlug = sanitizeToSlug(email.replace("@", "-at-"));
      const local = sanitizeToSlug(email.split("@")[0]);
      const suffix = simpleHash(email).toString(36).slice(0, 6);
      const derivedUsername = (emailSlug || local || "user") + "-" + suffix;

      if (usernameInput) usernameInput.value = derivedUsername.slice(0, 50);
    }

    emailInput.addEventListener("input", sync);
    emailInput.addEventListener("change", sync);
    sync();

    // Terms acceptance checkbox
    var submitBtn = registerForm.querySelector('input[type="submit"], button[type="submit"]');
    if (submitBtn && !document.getElementById("gryt-terms-checkbox")) {
      var wrapper = document.createElement("div");
      wrapper.className = "gryt-terms-group";

      var checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.id = "gryt-terms-checkbox";
      checkbox.name = "gryt-terms-accepted";

      var label = document.createElement("label");
      label.setAttribute("for", "gryt-terms-checkbox");
      label.innerHTML =
        'I agree to the <a href="https://gryt.chat/terms" target="_blank" rel="noreferrer">Terms of Use</a> ' +
        'and <a href="https://gryt.chat/privacy" target="_blank" rel="noreferrer">Privacy Policy</a>';

      var errorMsg = document.createElement("div");
      errorMsg.className = "gryt-terms-error";
      errorMsg.textContent = "You must accept the Terms of Use to continue.";

      wrapper.appendChild(checkbox);
      wrapper.appendChild(label);
      wrapper.appendChild(errorMsg);

      var btnGroup = submitBtn.closest(".pf-c-form__group") || submitBtn.parentElement;
      btnGroup.parentElement.insertBefore(wrapper, btnGroup);

      registerForm.addEventListener("submit", function (e) {
        if (!checkbox.checked) {
          e.preventDefault();
          wrapper.classList.add("gryt-terms-error-visible");
          checkbox.focus();
        }
      });

      checkbox.addEventListener("change", function () {
        if (checkbox.checked) {
          wrapper.classList.remove("gryt-terms-error-visible");
        }
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", apply);
  } else {
    apply();
  }
})();

