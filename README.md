Cache Poisoning Param-Miner v2.0 (Burp Suite Extension)
========================================================
![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

**An Automated Tool for Discovering Web Cache Poisoning Vulnerabilities**

Overview
--------

**Cache Poisoning Param-Miner** is a Burp Suite extension designed to automate the discovery of **unkeyed inputs** — HTTP headers, query parameters, and cookies that affect the server's response but are *not* included in the cache key.

Exploiting unkeyed inputs is the primary method for achieving **Web Cache Poisoning**. By injecting a malicious payload into an unkeyed input, an attacker can force the server to generate a poisoned response (e.g., reflecting XSS) that is then cached and served to other users.

This tool automates the tedious process of fuzzing headers/parameters/cookies, bypassing cache keys with busters, analyzing responses for reflections and cacheability, and automatically confirming whether a cache has been poisoned.

What's New in v2.0
------------------

-   **Parameter & Cookie Mining** — No longer limited to headers. Now fuzzes 20+ common unkeyed query parameters (UTM, tracking, JSONP, debug) and 12+ cookies (language, locale, theme, tracking).
-   **Automatic Poisoning Confirmation** — After detecting a cacheable reflection, the tool automatically sends a clean follow-up request to verify whether the poisoned response was actually cached and served back.
-   **Baseline Comparison** — A clean baseline request is sent before probing. Responses that differ significantly (>50 bytes) are flagged even without direct canary reflection.
-   **Parallelized Probing** — All probes now run concurrently across a 10-thread pool, dramatically speeding up scans.
-   **Improved Cacheability Analysis** — Validates cache header *values* (not just presence). `CF-Cache-Status: BYPASS` is correctly identified as non-cacheable. Checks for negative cache indicators (`no-store`, `private`, `no-cache`, `Pragma`, `Surrogate-Control`).
-   **Cryptographically Secure Canaries** — Uses `SecureRandom` to generate unique 24-character hex canaries per probe. No more predictable patterns.
-   **Progress Tracking** — Real-time progress bar and status label showing `"42/67 probes completed"`.
-   **Cancel Scan** — Abort a running scan at any time via the toolbar.
-   **Export Results** — Export findings to CSV or JSON for reporting.
-   **Color-Coded Risk Table** — Critical (red), High (orange), Medium (amber), Info (blue) with a dedicated "Confirmed" column.
-   **Thread Safety & Stability** — Synchronized table model, null-safe response handling, proper executor shutdown on extension unload, and capped result list (10,000 max).

Features
--------

### 1\. Multi-Input Mining (Headers, Parameters, Cookies)

The extension fuzzes **32 headers**, **20 query parameters**, and **12 cookies** known to cause cache poisoning.

**Headers** include:

| Category | Examples |
|----------|---------|
| Forwarding | `X-Forwarded-Host`, `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Forwarded-Prefix`, `Forwarded`, `Via` |
| Host Override | `X-Host`, `X-Original-URL`, `X-Rewrite-URL`, `X-Original-Host` |
| IP Spoofing | `X-Real-IP`, `X-Client-IP`, `Fastly-Client-IP`, `True-Client-IP`, `CF-Connecting-IP`, `X-Azure-ClientIP`, `X-ProxyUser-Ip` |
| Other | `Origin`, `Referer`, `X-WAP-Profile`, `Accept-Language` |

**Parameters** include: `utm_source`, `utm_medium`, `fbclid`, `gclid`, `callback`, `jsonp`, `_`, `redirect`, `debug`, `preview`, and more.

**Cookies** include: `language`, `locale`, `region`, `currency`, `theme`, `dark_mode`, `tracking_id`, and more.

### 2\. Dynamic Cache Busting

Every probe request gets a unique, cryptographically random cache buster parameter (`?cb=[hex]`) to guarantee a fresh backend response.

### 3\. Canary Injection & Detection

-   **Injection:** A unique `SecureRandom`-generated canary (e.g., `cpm-a3f8c1d9e4b2...`) is injected into each target input — one per probe to avoid ambiguity.

-   **Detection:** The tool checks the response body for the canary string.

-   **Analysis:** If reflected, response headers are analyzed to determine cacheability, checking both positive indicators (`Age`, `X-Cache: HIT`, `CF-Cache-Status: HIT`, `Cache-Control: public`) and negative indicators (`no-store`, `private`, `no-cache`).

### 4\. Automatic Poisoning Confirmation

When a reflection is found in a cacheable response, the tool automatically:

1.  Waits briefly for the cache to store the response.
2.  Sends a **clean request** (without the injected input) to the same cache-busted URL.
3.  If the canary appears in the clean response, the cache has been **confirmed poisoned** — the result is upgraded to **Critical** risk.

You can also manually re-confirm any result via the right-click context menu.

### 5\. Baseline Comparison

Before probing, a clean baseline request is sent. If a probe response differs significantly in body length (>50 bytes) but doesn't contain a direct canary reflection, it's flagged as an **Info** result for manual investigation.

### 6\. Dedicated UI Dashboard

Results are displayed in a custom **"Cache Miner"** tab with:

-   **7-Column Table:** #, Type, Input Name, Risk, Cacheable?, Confirmed, Reflection Context
-   **Color-Coded Risk Cells:** Critical (red), High (orange-red), Medium (amber), Info (blue)
-   **Split View:** Click any result row to see the full Request and Response side-by-side.
-   **Toolbar:** Export CSV, Export JSON, Clear All, Cancel Scan buttons.
-   **Progress Bar:** Real-time scan progress with probe count.
-   **Context Menu:** Right-click to re-confirm poisoning, delete items, or clear history.

### 7\. Export Results

Export all findings to **CSV** or **JSON** for integration with reports and collaboration:

```
[
  {"type":"Header","input":"X-Forwarded-Host","risk":"Critical","cacheable":"Yes (CF-Cache-Status: HIT)","confirmed":"YES - POISONED!","context":"..."}
]
```

Installation
------------

### Prerequisites

-   Java Development Kit (JDK) 17+.

-   Burp Suite (Community or Professional).

-   Gradle.

### Build from Source

1.  Clone the repository:

    ```
    git clone https://github.com/tobiasGuta/Cache-Poisoning-Param-Miner-Burp-Suite-Extension.git
    cd Cache-Poisoning-Param-Miner-Burp-Suite-Extension/CachePoisonMiner
    ```

2.  Build the JAR file:

    ```
    ./gradlew clean jar
    ```

3.  Load into Burp Suite:

    -   Navigate to **Extensions** → **Installed**.

    -   Click **Add** → Select `build/libs/CacheMiner.jar`.

Usage Guide
-----------

1.  **Identify a Target:** Find a page with cache headers (e.g., `X-Cache: HIT`, `Age: 10`, `CF-Cache-Status: HIT`).

2.  **Launch Miner:**

    -   Right-click the request in Proxy, Repeater, or Target.

    -   Select **Cache Poison Miner** → choose a scan mode:

        -   **Mine All** — Headers + Parameters + Cookies
        -   **Mine Headers Only**
        -   **Mine Parameters Only**
        -   **Mine Cookies Only**

3.  **Monitor Progress:**

    -   Open the **"Cache Miner"** tab.

    -   Watch the progress bar and status label at the bottom.

    -   Click **Cancel Scan** to abort if needed.

4.  **Analyze Results:**

    -   **Critical (Red):** Cache poisoning confirmed — the poisoned response was cached and served to a clean request.

    -   **High (Orange):** Reflection found in a cacheable response — strong candidate, verify manually.

    -   **Medium (Amber):** Reflection found but response appears non-cacheable.

    -   **Info (Blue):** Response body differs from baseline, but no direct canary reflection — investigate manually.

5.  **Verify & Confirm:**

    -   Click any row to inspect the full request/response.

    -   Right-click → **Re-confirm Poisoning** to re-test whether the cache is still poisoned.

6.  **Export:**

    -   Click **Export CSV** or **Export JSON** in the toolbar.

Tech Stack
----------

-   **Language:** Java 17+

-   **API:** Burp Suite Montoya API (2025.3)

-   **Concurrency:** `ExecutorService` with 10-thread pool (parallel probing)

-   **Security:** `SecureRandom` for canary & cache buster generation

-   **UI:** Swing (JTable with custom cell renderer, JToolBar, JProgressBar, JSplitPane)

Disclaimer
----------

This tool is for educational purposes and authorized security testing only. Do not use this tool on systems you do not have permission to test. The author is not responsible for any misuse.

---

<div align="center">
  <h3>☕ Support My Journey</h3>
</div>


<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>
