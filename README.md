# Phishing URL Risk Checker

A simple, lightweight, rule-based **Phishing URL Risk Checker** built using only **HTML, CSS, JavaScript, and Core Java**.

> ⚠️ **Important Security Disclaimer:**
> This tool is an educational heuristic analyzer that inspects URLs for suspicious patterns using simple rules. It is **not a guaranteed phishing detector** and does not use machine learning or real-time threat intelligence feeds. A "Low Risk" result does not guarantee safety, and a "High Risk" result does not guarantee malice. Always exercise caution and never enter sensitive information into untrusted websites.

---

## 🚀 Features

1. **URL Risk Evaluation**: Analyzes any entered URL and classifies it as **Low Risk**, **Medium Risk**, or **High Risk**.
2. **Suspicious Pattern Detection**:
   - **`@` Symbol**: Detects user-credential obfuscation tricks (browsers ignore text before `@` and redirect to what follows).
   - **Raw IP Addresses**: Flags URLs using IP addresses (e.g. `http://192.168.1.1/login`) instead of registered domains.
   - **Missing HTTPS**: Warns if an unencrypted `http://` protocol is used.
   - **Unusually Long URLs**: Flags URLs exceeding 75 characters (often used to hide malicious redirects or parameters).
   - **Excessive Subdomains**: Detects multiple stacked subdomains (e.g. `paypal.com.verify.attacker.com`).
   - **Domain Hyphens**: Identifies hyphenated domains often used in brand typosquatting.
   - **Phishing Keywords**: Detects credential-harvesting keywords like `login`, `verify`, `banking`, `secure`, `account`.
   - **URL Shorteners**: Flags shortening services (e.g. `bit.ly`, `tinyurl.com`) that conceal the real destination.
3. **Transparent Reasoning**: Lists every rule triggered and explains *why* it was flagged.
4. **Interactive UI**:
   - Visual **Risk Meter** and animated status badges.
   - URL anatomy breakdown (Protocol, Host, Character Count, Flagged Rules).
   - Quick one-click **Sample Test URLs** for safe, medium, and high-risk demonstrations.
5. **Pure Standard Stack**:
   - **No external frameworks** (no Spring, no React, no Bootstrap, no Maven, no Gradle).
   - **No external APIs or AI/ML models**.
   - **No databases**.
   - Powered purely by **Core Java standard library** (`com.sun.net.httpserver.HttpServer`).

---

## 📁 Project Structure

```
Phishing URL Risk Checker/
├── index.html           # Frontend interface and HTML structure
├── style.css            # Responsive, modern styling and risk color themes
├── script.js            # Client-side input validation and API communication
├── PhishingChecker.java # Core Java backend HTTP server & rule-checking logic
└── README.md            # Project documentation and setup guide
```

---

## 🛠️ Prerequisites

To run this project, you only need:
1. **VS Code** (Visual Studio Code).
2. **Java Development Kit (JDK 11 or newer)** installed and added to your system `PATH`.
   - Check by opening a terminal and typing: `java -version`

---

## 💻 How to Run the Project in VS Code

### Step 1: Open the Project in VS Code
1. Launch **Visual Studio Code**.
2. Click **File > Open Folder...** (or press `Ctrl + K, Ctrl + O`).
3. Select the `Phishing URL Risk Checker` folder.

### Step 2: Open the Integrated Terminal
- Press `` Ctrl + ` `` (backtick) or select **Terminal > New Terminal** from the top menu bar.

### Step 3: Run the Java Backend Server
In the VS Code terminal, run:

```bash
java PhishingChecker.java
```

> **Note:** If you are using an older JDK version (Java 8 or below), compile first and then run:
> ```bash
> javac PhishingChecker.java
> java PhishingChecker
> ```

You should see output similar to:
```text
==================================================
   Phishing URL Risk Checker Server Started!
==================================================
 Open your browser and visit: http://localhost:8080
 API Endpoint available at : http://localhost:8080/api/check?url=<YOUR_URL>
 Press Ctrl+C in the terminal to stop the server.
==================================================
```

### Step 4: Open in Your Web Browser
Open your preferred web browser (Chrome, Edge, Firefox) and navigate to:

👉 **[http://localhost:8080](http://localhost:8080)**

---

## 🧪 Testing with Sample URLs

You can click any of the sample chips on the page or test with the following URLs:

| Sample URL | Expected Result | Reason Triggered |
| :--- | :--- | :--- |
| `https://www.wikipedia.org` | 🟢 **Low Risk** | HTTPS present, clean domain name, standard length. |
| `http://paypal-security-update.com/login` | 🟡 **Medium Risk** | Insecure HTTP, domain hyphen, sensitive keywords (`security`, `login`). |
| `http://192.168.1.1/banking/login-verify` | 🔴 **High Risk** | Raw IP address used as host, insecure HTTP, sensitive keywords. |
| `https://google.com@attacker-site.com/signin` | 🔴 **High Risk** | `@` symbol confusion trick, keyword (`signin`). |
| `http://example-verify-login.com/service/auth/session/token?id=992837192387192837192837192837192837` | 🔴 **High Risk** | Length > 75 chars, HTTP, hyphens, multiple keywords. |

---

## ⚙️ How the Heuristic Rules Work

```
       [ Entered URL ]
             │
             ▼
   [ JavaScript Validation ]
   (Check empty, spaces, basic format)
             │
             ▼
     [ Core Java Server ]
     (com.sun.net.httpserver)
             │
    ┌────────┴──────────────────────────┐
    │  Heuristic Rule Engine             │
    │  - Contains '@' symbol?     (+35)  │
    │  - Uses Raw IP Address?     (+35)  │
    │  - Missing HTTPS (HTTP)?    (+20)  │
    │  - Length > 75 characters?  (+15)  │
    │  - Excessive Subdomains?    (+15)  │
    │  - Phishing Keywords?       (+15)  │
    │  - Hyphen in Domain?        (+10)  │
    │  - Known URL Shortener?     (+20)  │
    └────────┬──────────────────────────┘
             │
             ▼
     [ Risk Classification ]
     - Score >= 50: High Risk
     - Score >= 20: Medium Risk
     - Score <  20: Low Risk
             │
             ▼
      [ JSON Response ]
             │
             ▼
      [ UI Rendered ]
```

---

## 🛑 How to Stop the Server
When you are done testing, click inside the VS Code terminal window and press:
```bash
Ctrl + C
```
