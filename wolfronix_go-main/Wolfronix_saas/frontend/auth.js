const API_BASE = "http://localhost:5000/api";

function showError(elementId, message) {
  const errorElement = document.getElementById(elementId);
  if (errorElement) {
    errorElement.textContent = message;
    errorElement.classList.remove("hidden");
  }
}

function clearError(elementId) {
  const errorElement = document.getElementById(elementId);
  if (errorElement) {
    errorElement.textContent = "";
    errorElement.classList.add("hidden");
  }
}

function clearAllErrors() {
  const errorIds = [
    "firstNameError",
    "lastNameError",
    "emailError",
    "phoneNumberError",
    "passwordError",
    "confirmPasswordError",
    "termsError",
    "phonePasswordError"
  ];
  errorIds.forEach(clearError);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function showSuccess(message) {
  const div = document.createElement("div");
  div.className =
    "fixed top-4 right-4 bg-green-500 text-white px-6 py-3 rounded-lg shadow-lg z-50 animate-slide-in";
  div.textContent = message;
  document.body.appendChild(div);
  setTimeout(() => div.remove(), 3000);
}

function updatePasswordStrength() {
  const passwordInput = document.getElementById("password");
  const strengthBar = document.getElementById("strengthBar");
  const strengthText = document.getElementById("strengthText");

  if (!passwordInput || !strengthBar || !strengthText) return;

  const password = passwordInput.value;
  let strength = 0;
  let label = "";
  let color = "";

  if (password.length === 0) {
    strengthBar.style.width = "0%";
    strengthText.textContent = "";
    return;
  }

  if (password.length >= 8) strength += 25;
  if (password.match(/[a-z]+/)) strength += 25;
  if (password.match(/[A-Z]+/)) strength += 25;
  if (password.match(/[0-9]+/)) strength += 12.5;
  if (password.match(/[^a-zA-Z0-9]+/)) strength += 12.5;

  if (strength >= 75) {
    label = "Strong password";
    color = "#10B981";
  } else if (strength >= 50) {
    label = "Medium password";
    color = "#F59E0B";
  } else {
    label = "Weak password";
    color = "#EF4444";
  }

  strengthBar.style.width = strength + "%";
  strengthBar.style.backgroundColor = color;
  strengthText.textContent = label;
  strengthText.style.color = color;
}

document.addEventListener("DOMContentLoaded", () => {
  const inputs = [
    "firstName",
    "lastName",
    "email",
    "phoneNumber",
    "company",
    "password",
    "confirmPassword",
    "phonePassword"
  ];
  inputs.forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener("input", () => {
        clearError(id + "Error");
        if (id === "password") updatePasswordStrength();
      });
    }
  });

  const terms = document.getElementById("terms");
  if (terms) {
    terms.addEventListener("change", () => clearError("termsError"));
  }
});

async function register(event) {
  event.preventDefault();
  clearAllErrors();

  const firstNameEl = document.getElementById("firstName");
  const lastNameEl = document.getElementById("lastName");
  const emailEl = document.getElementById("email");
  const phoneNumberEl = document.getElementById("phoneNumber");
  const passwordEl = document.getElementById("password");
  const confirmPasswordEl = document.getElementById("confirmPassword");
  const companyEl = document.getElementById("company");
  const termsEl = document.getElementById("terms");

  const formData = {
    firstName: firstNameEl ? firstNameEl.value.trim() : "",
    lastName: lastNameEl ? lastNameEl.value.trim() : "",
    email: emailEl ? emailEl.value.trim() : "",
    phoneNumber: phoneNumberEl ? phoneNumberEl.value.trim() : "",
    password: passwordEl ? passwordEl.value.trim() : "",
    confirmPassword: confirmPasswordEl ? confirmPasswordEl.value.trim() : "",
    company: companyEl ? companyEl.value.trim() : "",
  };

  let isValid = true;

  if (!formData.firstName) {
    showError("firstNameError", "First name is required");
    isValid = false;
  }

  if (!formData.lastName) {
    showError("lastNameError", "Last name is required");
    isValid = false;
  }

  if (!formData.email) {
    showError("emailError", "Email is required");
    isValid = false;
  } else if (!isValidEmail(formData.email)) {
    showError("emailError", "Please enter a valid email");
    isValid = false;
  }

  if (!formData.phoneNumber) {
    showError("phoneNumberError", "Phone number is required");
    isValid = false;
  }

  if (!formData.password) {
    showError("passwordError", "Password is required");
    isValid = false;
  } else if (formData.password.length < 8) {
    showError("passwordError", "Password must be at least 8 characters");
    isValid = false;
  }

  if (!formData.confirmPassword) {
    showError("confirmPasswordError", "Please confirm your password");
    isValid = false;
  } else if (formData.password !== formData.confirmPassword) {
    showError("confirmPasswordError", "Passwords do not match");
    isValid = false;
  }

  if (termsEl && !termsEl.checked) {
    showError("termsError", "You must accept the terms and conditions");
    isValid = false;
  }

  if (!isValid) return;

  const button = event.target.querySelector('button[type="submit"]');
  const originalBtnContent = button.innerHTML;
  if (button) {
    button.disabled = true;
    button.innerHTML = '<span class="relative z-10">Creating account...</span>';
  }

  try {
    const payload = {
      firstName: formData.firstName,
      lastName: formData.lastName,
      email: formData.email,
      phoneNumber: formData.phoneNumber,
      password: formData.password,
      company: formData.company
    };

    const res = await fetch(`${API_BASE}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const result = await res.json();

    if (!res.ok) {
      if (result.message && result.message.toLowerCase().includes("phone")) {
        showError("phoneNumberError", result.message);
      } else {
        showError("emailError", result.message || "Registration failed");
      }
      throw new Error(result.message || "Registration failed");
    }

    localStorage.setItem("token", result.token);
    showSuccess("Registration successful! Redirecting...");
    setTimeout(() => {
      window.location.href = "dashboard.html";
    }, 1500);
  } catch (error) {
    if (button) {
      button.disabled = false;
      button.innerHTML = originalBtnContent;
    }
  }
}

async function handleLogin(event) {
  event.preventDefault();
  clearAllErrors();

  const button = event.target.querySelector('button[type="submit"]');
  const originalBtnContent = button.innerHTML;

  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value.trim();

  if (!email || !isValidEmail(email)) {
    showError("emailError", "Valid email is required");
    return;
  }
  if (!password) {
    showError("passwordError", "Password is required");
    return;
  }

  if (button) {
    button.disabled = true;
    button.innerHTML = '<span class="relative z-10">Signing in...</span>';
  }

  try {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, method: "email" }),
    });
    const result = await res.json();
    if (!res.ok) throw new Error(result.message);

    if (result.mfaRequired) {
      if (typeof window.onMfaRequired === 'function') {
        window.onMfaRequired(result);
        if (button) {
          button.disabled = false;
          button.innerHTML = originalBtnContent;
        }
        return;
      } else {
        throw new Error("MFA required but not supported on this page");
      }
    }

    localStorage.setItem("token", result.token);
    showSuccess("Login successful! Redirecting...");
    setTimeout(() => { window.location.href = "dashboard.html"; }, 1000);
  } catch (error) {
    showError("emailError", error.message || "Login failed");
    if (button) {
      button.disabled = false;
      button.innerHTML = originalBtnContent;
    }
  }
}

async function verifyMfaLogin(tempToken, phoneToken) {
  try {
    const res = await fetch(`${API_BASE}/auth/verify-mfa`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tempToken, phoneToken })
    });
    const result = await res.json();
    if (!res.ok) throw new Error(result.message);

    localStorage.setItem("token", result.token);
    return true;
  } catch (e) {
    throw e;
  }
}

async function loadUser() {
  const token = localStorage.getItem("token");
  if (!token) {
    window.location.href = "login.html";
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/user/me`, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    if (!res.ok) {
      console.error("Failed to load user:", await res.text());
      localStorage.removeItem("token");
      window.location.href = "login.html";
      return;
    }

    const user = await res.json();

    const nameEl = document.getElementById("dashboardUserName");
    const emailEl = document.getElementById("dashboardUserEmail");
    const initEl = document.getElementById("userInitials");

    if (nameEl) nameEl.textContent = `${user.firstName} ${user.lastName}`;
    if (emailEl) emailEl.textContent = user.email;
    if (initEl) initEl.textContent =
      user.firstName[0].toUpperCase() + user.lastName[0].toUpperCase();

    if (document.getElementById("firstName")) {
      const setField = (id, val, defaultPlaceholder) => {
        const el = document.getElementById(id);
        if (el) {
          el.value = val || "";
          el.placeholder = val || defaultPlaceholder;
        }
      };

      setField("firstName", user.firstName, "John");
      setField("lastName", user.lastName, "Doe");
      setField("email", user.email, "you@company.com");
      setField("phoneNumber", user.phoneNumber, "+1234567890");
      setField("company", user.company, "Your company");
    }
  } catch (error) {
    console.error("Error loading user:", error);
  }
}

function logout() {
  localStorage.removeItem("token");
  window.location.href = "login.html";
}

function loginWithGoogle() {
  window.location.href = `${API_BASE}/auth/google`;
}

// Expose WolfronixAuth for UI updates
const WolfronixAuth = {
  getUser: () => {
    const token = localStorage.getItem("token");
    if (!token) return null;
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(window.atob(base64));
    } catch (e) {
      return null;
    }
  },
  logout: logout
};