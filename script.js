/**
 * Phishing URL Risk Checker - Frontend JavaScript
 * 
 * Responsibilities:
 * 1. Client-side URL input validation.
 * 2. Communicating with the Core Java backend (/api/check).
 * 3. Rendering risk results (Low/Medium/High), score meter, anatomy, and reasons.
 * 4. Providing an intuitive, beginner-friendly experience.
 */

// Base API URL: Supports both direct Java server serving (relative) 
// or VS Code Live Server / file:// (absolute to localhost:8080)
const API_BASE_URL = window.location.origin.includes("localhost:8080")
    ? ""
    : "http://localhost:8080";

// DOM Elements
const urlInput = document.getElementById("urlInput");
const checkBtn = document.getElementById("checkBtn");
const clearBtn = document.getElementById("clearBtn");
const spinner = document.getElementById("spinner");
const validationError = document.getElementById("validationError");
const resultsSection = document.getElementById("resultsSection");

// Result DOM Elements
const riskCard = document.getElementById("riskCard");
const riskBadge = document.getElementById("riskBadge");
const riskScoreText = document.getElementById("riskScoreText");
const meterFill = document.getElementById("meterFill");
const targetUrlDisplay = document.getElementById("targetUrlDisplay");
const reasonsList = document.getElementById("reasonsList");

// Anatomy Elements
const anatomyProtocol = document.getElementById("anatomyProtocol");
const anatomyHost = document.getElementById("anatomyHost");
const anatomyLength = document.getElementById("anatomyLength");
const anatomyRulesCount = document.getElementById("anatomyRulesCount");

// Sample URL Buttons
const sampleChips = document.querySelectorAll(".sample-chips .chip");

/* ==========================================================================
   Event Listeners
   ========================================================================== */

// 1. Submit on Check Button click
checkBtn.addEventListener("click", () => {
    handleUrlCheck();
});

// 2. Submit on 'Enter' key press
urlInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
        event.preventDefault();
        handleUrlCheck();
    }
});

// 3. Clear button click
clearBtn.addEventListener("click", () => {
    urlInput.value = "";
    clearBtn.classList.remove("show");
    hideError();
    resultsSection.classList.add("hidden");
    urlInput.focus();
});

// 4. Toggle clear button & hide error as user types
urlInput.addEventListener("input", () => {
    hideError();
    if (urlInput.value.trim().length > 0) {
        clearBtn.classList.add("show");
    } else {
        clearBtn.classList.remove("show");
    }
});

// 5. Sample URL chips click
sampleChips.forEach((chip) => {
    chip.addEventListener("click", () => {
        const sampleUrl = chip.getAttribute("data-url");
        if (sampleUrl) {
            urlInput.value = sampleUrl;
            clearBtn.classList.add("show");
            hideError();
            handleUrlCheck();
        }
    });
});

/* ==========================================================================
   Validation & Submission Handlers
   ========================================================================== */

/**
 * Validates user input before requesting analysis from Core Java backend.
 */
function validateInput(rawUrl) {
    const trimmed = rawUrl.trim();

    // Check 1: Empty input
    if (trimmed.length === 0) {
        return { isValid: false, message: "Please enter a URL to analyze." };
    }

    // Check 2: Contains spaces
    if (/\s/.test(trimmed)) {
        return { isValid: false, message: "URLs cannot contain spaces." };
    }

    // Check 3: Basic URL pattern test (must look like a plausible web address or IP)
    // Allows domain names, localhost, IP addresses, with or without protocol
    const urlPattern = /^(https?:\/\/)?([a-zA-Z0-9-._~%]+)(:\d+)?(\/[^\s]*)?$/i;
    if (!urlPattern.test(trimmed)) {
        return { isValid: false, message: "Please enter a valid URL format (e.g. https://example.com)." };
    }

    return { isValid: true, message: "" };
}

/**
 * Normalizes the URL by prepending http:// if no protocol was typed.
 */
function normalizeUrl(rawUrl) {
    let url = rawUrl.trim();
    if (!/^https?:\/\//i.test(url)) {
        url = "http://" + url;
    }
    return url;
}

/**
 * Main coordinator function to validate and execute the check.
 */
async function handleUrlCheck() {
    const rawInput = urlInput.value;
    const validation = validateInput(rawInput);

    if (!validation.isValid) {
        showError(validation.message);
        return;
    }

    hideError();
    const finalUrl = normalizeUrl(rawInput);

    // Update input display if protocol was auto-added
    urlInput.value = finalUrl;
    clearBtn.classList.add("show");

    // Show loading state
    setLoading(true);

    try {
        // Request URL analysis from the Core Java backend server
        const analysisData = await fetchAnalysisFromJava(finalUrl);
        displayResults(analysisData, finalUrl);
    } catch (error) {
        console.warn("Could not reach Java backend server:", error);
        // Fallback: If Java server isn't running yet, display informative guidance
        showError(
            "⚠️ Could not connect to Core Java backend at http://localhost:8080.\n" +
            "Please ensure 'PhishingChecker.java' is running in your terminal."
        );
    } finally {
        setLoading(false);
    }
}

/**
 * Fetches analysis result from Core Java HttpServer.
 */
async function fetchAnalysisFromJava(url) {
    const endpoint = `${API_BASE_URL}/api/check?url=${encodeURIComponent(url)}`;
    
    // 5-second timeout to prevent infinite pending
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(endpoint, {
        method: "GET",
        signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Server responded with status: ${response.status}`);
    }

    return await response.json();
}

/* ==========================================================================
   UI Rendering Functions
   ========================================================================== */

/**
 * Displays the risk assessment result in the UI.
 */
function displayResults(data, analyzedUrl) {
    // 1. Unhide results section
    resultsSection.classList.remove("hidden");

    // 2. Display analyzed URL
    targetUrlDisplay.textContent = analyzedUrl;

    // 3. Update Risk Badge & Risk Score
    const riskLevel = data.riskLevel || "Low Risk";
    const score = typeof data.riskScore === "number" ? data.riskScore : 0;

    riskBadge.textContent = riskLevel;
    riskScoreText.textContent = `${score} / 100`;
    meterFill.style.width = `${Math.min(score, 100)}%`;

    // 4. Update Theme Classes based on Risk Level
    riskCard.classList.remove("risk-low", "risk-med", "risk-high");
    if (riskLevel === "High Risk") {
        riskCard.classList.add("risk-high");
    } else if (riskLevel === "Medium Risk") {
        riskCard.classList.add("risk-med");
    } else {
        riskCard.classList.add("risk-low");
    }

    // 5. Populate URL Anatomy Breakdown
    populateUrlAnatomy(analyzedUrl, data.reasons || []);

    // 6. Populate Reasons & Findings List
    populateReasonsList(data.reasons || [], riskLevel);

    // 7. Smooth scroll into view on small screens
    resultsSection.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

/**
 * Breaks down URL parts (Protocol, Host, Length, Flags) for the anatomy card.
 */
function populateUrlAnatomy(urlString, reasons) {
    try {
        const parsed = new URL(urlString);
        anatomyProtocol.textContent = parsed.protocol.toUpperCase().replace(":", "");
        anatomyHost.textContent = parsed.hostname || "-";
    } catch {
        anatomyProtocol.textContent = urlString.startsWith("https") ? "HTTPS" : "HTTP";
        anatomyHost.textContent = "Unparsed Host";
    }

    anatomyLength.textContent = `${urlString.length} chars`;
    anatomyRulesCount.textContent = `${reasons.length} rule${reasons.length === 1 ? "" : "s"}`;
}

/**
 * Renders each reason returned by the Java backend into the list.
 */
function populateReasonsList(reasons, riskLevel) {
    reasonsList.innerHTML = "";

    if (reasons.length === 0) {
        const li = document.createElement("li");
        li.className = "safe";
        li.innerHTML = `
            <span class="reason-icon">✅</span>
            <span>No common suspicious patterns detected. Standard domain syntax and length.</span>
        `;
        reasonsList.appendChild(li);
        return;
    }

    reasons.forEach((reason) => {
        const li = document.createElement("li");

        // Determine icon and style based on reason content or general risk level
        const lowerReason = reason.toLowerCase();
        if (lowerReason.includes("no obvious") || lowerReason.includes("safe")) {
            li.className = "safe";
            li.innerHTML = `<span class="reason-icon">✅</span><span>${escapeHtml(reason)}</span>`;
        } else if (riskLevel === "High Risk" || lowerReason.includes("raw ip") || lowerReason.includes("'@'")) {
            li.className = "danger";
            li.innerHTML = `<span class="reason-icon">⚠️</span><span>${escapeHtml(reason)}</span>`;
        } else {
            li.className = "warning";
            li.innerHTML = `<span class="reason-icon">⚡</span><span>${escapeHtml(reason)}</span>`;
        }

        reasonsList.appendChild(li);
    });
}

/**
 * Helper to display validation errors.
 */
function showError(msg) {
    validationError.textContent = msg;
    validationError.classList.add("active");
}

/**
 * Helper to hide validation errors.
 */
function hideError() {
    validationError.textContent = "";
    validationError.classList.remove("active");
}

/**
 * Helper to toggle button loading spinner.
 */
function setLoading(isLoading) {
    if (isLoading) {
        checkBtn.disabled = true;
        spinner.classList.add("active");
    } else {
        checkBtn.disabled = false;
        spinner.classList.remove("active");
    }
}

/**
 * Helper to prevent XSS when inserting strings into HTML.
 */
function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}
