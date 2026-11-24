// --- 1. SMS / EMAIL PHISHING & SPAM DETECTOR ---
const msgInput = document.getElementById("msgInput");
const scanMsgBtn = document.getElementById("scanMsgBtn");
const msgResult = document.getElementById("msgResult");
const msgRiskLevel = document.getElementById("msgRiskLevel");
const msgFlags = document.getElementById("msgFlags");

scanMsgBtn.addEventListener("click", () => {
  const text = msgInput.value.trim();
  if (!text) return;

  const lowerText = text.toLowerCase();
  const flags = [];
  let riskScore = 0;

  // Check 1: Urgency & Threat triggers
  const urgencyWords = ["urgent", "immediately", "suspended", "blocked", "expire", "within 24 hours", "action required", "kyc"];
  const foundUrgency = urgencyWords.filter(word => lowerText.includes(word));
  if (foundUrgency.length > 0) {
    flags.push(`⚠️ High-urgency / fear-inducing words detected (${foundUrgency.join(", ")}).`);
    riskScore += 2;
  }

  // Check 2: Financial / Reward bait
  const baitWords = ["lottery", "winner", "prize", "cashback", "refund", "claim now", "free gift", "credited"];
  const foundBait = baitWords.filter(word => lowerText.includes(word));
  if (foundBait.length > 0) {
    flags.push(`⚠️ Financial reward or refund bait keywords found (${foundBait.join(", ")}).`);
    riskScore += 2;
  }

  // Check 3: Sensitive credential requests
  const sensitiveWords = ["otp", "cvv", "pin", "password", "bank details", "pan card", "aadhaar"];
  const foundSensitive = sensitiveWords.filter(word => lowerText.includes(word));
  if (foundSensitive.length > 0) {
    flags.push(`🚨 Requests or mentions sensitive credentials (${foundSensitive.join(", ")}). Legitimate services never ask for these.`);
    riskScore += 3;
  }

  // Check 4: Embedded links or shortened URLs
  if (/https?:\/\/|www\.|bit\.ly|tinyurl|t\.co/i.test(text)) {
    flags.push("⚠️ Contains an external or shortened link—verify sender before clicking.");
    riskScore += 2;
  }

  msgResult.classList.remove("hidden");
  msgFlags.innerHTML = "";

  if (riskScore === 0) {
    msgRiskLevel.textContent = "🟢 Safe / Low Risk — No common spam or phishing triggers found.";
    msgRiskLevel.style.color = "#3fb950";
    msgFlags.innerHTML = "<li>Message appears normal. Still verify the sender's official email or phone number.</li>";
  } else if (riskScore <= 3) {
    msgRiskLevel.textContent = "🟡 Suspicious — Verify sender before taking action.";
    msgRiskLevel.style.color = "#d29922";
  } else {
    msgRiskLevel.textContent = "🔴 High Phishing / Scam Risk — Likely fraudulent message!";
    msgRiskLevel.style.color = "#f85149";
  }

  flags.forEach(flag => {
    const li = document.createElement("li");
    li.textContent = flag;
    msgFlags.appendChild(li);
  });
});

// --- 2. PASSWORD STRENGTH CHECKER ---
const passwordInput = document.getElementById("passwordInput");
const togglePass = document.getElementById("togglePass");
const strengthFill = document.getElementById("strengthFill");
const strengthText = document.getElementById("strengthText");

togglePass.addEventListener("click", () => {
  const isHidden = passwordInput.type === "password";
  passwordInput.type = isHidden ? "text" : "password";
  togglePass.textContent = isHidden ? "Hide" : "Show";
});

passwordInput.addEventListener("input", () => {
  const val = passwordInput.value;
  let score = 0;

  const hasLength = val.length >= 8;
  const hasUpper = /[A-Z]/.test(val);
  const hasNumber = /[0-9]/.test(val);
  const hasSymbol = /[^A-Za-z0-9]/.test(val);

  updateCheck("lenCheck", hasLength, "At least 8 characters");
  updateCheck("upperCheck", hasUpper, "Contains uppercase letter (A-Z)");
  updateCheck("numCheck", hasNumber, "Contains number (0-9)");
  updateCheck("symCheck", hasSymbol, "Contains special character (!@#$...)");

  if (hasLength) score++;
  if (hasUpper) score++;
  if (hasNumber) score++;
  if (hasSymbol) score++;

  const levels = [
    { width: "0%", color: "transparent", label: "0% — Waiting for input..." },
    { width: "25%", color: "#f85149", label: "25% — Weak (Easily crackable)" },
    { width: "50%", color: "#d29922", label: "50% — Moderate (Add more variety)" },
    { width: "75%", color: "#58a6ff", label: "75% — Good (Almost there)" },
    { width: "100%", color: "#3fb950", label: "100% — Strong (Secure password)" }
  ];

  strengthFill.style.width = levels[score].width;
  strengthFill.style.backgroundColor = levels[score].color;
  strengthText.textContent = `Strength: ${levels[score].label}`;
  strengthText.style.color = score === 0 ? "#e6edf3" : levels[score].color;
});

function updateCheck(id, passed, text) {
  const el = document.getElementById(id);
  el.textContent = `${passed ? "✅" : "❌"} ${text}`;
  el.style.color = passed ? "#3fb950" : "#8b949e";
}

// --- 3. PHISHING URL HEURISTIC SCANNER ---
const urlInput = document.getElementById("urlInput");
const scanUrlBtn = document.getElementById("scanUrlBtn");
const urlResult = document.getElementById("urlResult");
const riskLevel = document.getElementById("riskLevel");
const urlFlags = document.getElementById("urlFlags");

scanUrlBtn.addEventListener("click", () => {
  const rawUrl = urlInput.value.trim();
  if (!rawUrl) return;

  const flags = [];
  let riskScore = 0;

  if (rawUrl.startsWith("http://")) {
    flags.push("⚠️ Uses insecure HTTP instead of HTTPS.");
    riskScore += 2;
  }

  if (rawUrl.includes("@")) {
    flags.push("🚨 Contains '@' symbol (often used to mask real destination domain).");
    riskScore += 3;
  }

  if (/https?:\/\/\d{1,3}(\.\d{1,3}){3}/.test(rawUrl)) {
    flags.push("🚨 Uses raw IP address instead of a legitimate domain name.");
    riskScore += 3;
  }

  const suspiciousWords = ["login", "verify", "secure", "update", "bank", "free", "account"];
  const lowerUrl = rawUrl.toLowerCase();
  const matchedWords = suspiciousWords.filter(word => lowerUrl.includes(word));
  if (matchedWords.length >= 2) {
    flags.push(`⚠️ Multiple urgency/credential keywords detected (${matchedWords.join(", ")}).`);
    riskScore += 2;
  }

  if (rawUrl.length > 75) {
    flags.push("⚠️ Unusually long URL (>75 chars), common in obfuscated links.");
    riskScore += 1;
  }

  urlResult.classList.remove("hidden");
  urlFlags.innerHTML = "";

  if (riskScore === 0) {
    riskLevel.textContent = "🟢 Low Risk — No obvious phishing patterns found.";
    riskLevel.style.color = "#3fb950";
    urlFlags.innerHTML = "<li>Standard URL structure detected. Always verify the domain spelling manually.</li>";
  } else if (riskScore <= 2) {
    riskLevel.textContent = "🟡 Medium Risk — Proceed with caution.";
    riskLevel.style.color = "#d29922";
  } else {
    riskLevel.textContent = "🔴 High Risk — Strong phishing indicators detected!";
    riskLevel.style.color = "#f85149";
  }

  flags.forEach(flag => {
    const li = document.createElement("li");
    li.textContent = flag;
    urlFlags.appendChild(li);
  });
});