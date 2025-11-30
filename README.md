Cache Poisoning Param-Miner (Burp Suite Extension)
==================================================

**An Automated Tool for Discovering Web Cache Poisoning Vulnerabilities**

Overview
--------

**Cache Poisoning Param-Miner** is a Burp Suite extension designed to automate the discovery of "Unkeyed Inputs" HTTP headers or parameters that affect the server's response but are *not* included in the cache key.

Exploiting unkeyed inputs is the primary method for achieving **Web Cache Poisoning**. By injecting a malicious payload into an unkeyed header, an attacker can force the server to generate a poisoned response (e.g., reflecting XSS) that is then cached and served to other users.

This tool automates the tedious process of fuzzing headers, bypassing cache keys with "busters," and analyzing responses for reflections and cacheability.

Features
--------

### 1\. Automated Header Mining

The extension fuzzes a curated list of 15+ high-value headers known to cause cache poisoning, including:

-   `X-Forwarded-Host`

-   `X-Host`

-   `X-Original-URL`

-   `X-Forwarded-Scheme`

-   `Fastly-Client-IP`

### 2\. Dynamic Cache Busting

To ensure every test hits the backend (and not a stale cache), the tool automatically appends a dynamic cache buster parameter (`?cb=[timestamp]`) to every request.

### 3\. Canary Injection & Detection

-   **Injection:** A unique random "Canary" string (e.g., `canary92834`) is injected into each target header.

-   **Detection:** The tool parses the response body to see if the canary is reflected.

-   **Analysis:** If reflected, it analyzes response headers (`Age`, `X-Cache`, `CF-Cache-Status`) to determine if the response is cacheable.

### 4\. Dedicated UI Dashboard

Results are displayed in a custom **"Cache Miner"** tab.

-   **Split View:** Click any result to see the full Request and Response side-by-side.

-   **Risk Rating:** The table clearly indicates if a reflection is "High Risk" (Cacheable) or "Reflected Only" (Non-Cacheable).

Installation
------------

### Prerequisites

-   Java Development Kit (JDK) 21.

-   Burp Suite (Community or Professional).

-   Gradle.

### Build from Source

1.  Clone the repository:

    ```
    git clone https://github.com/tobiasGuta/Cache-Poisoning-Param-Miner-Burp-Suite-Extension-.git
    cd Cache-Poisoning-Param-Miner

    ```

2.  Build the JAR file:

    ```
    ./gradlew clean jar

    ```

3.  Load into Burp Suite:

    -   Navigate to **Extensions** -> **Installed**.

    -   Click **Add** -> Select `build/libs/CacheMiner.jar`.

Usage Guide
-----------

1.  **Identify a Cache Oracle:** Find a page that returns cache headers (e.g., `X-Cache: HIT` or `Age: 10`).

2.  **Launch Miner:**

    -   Right-click the request in Proxy or Repeater.

    -   Select **Mine for Unkeyed Headers**.

3.  **Analyze Results:**

    -   Open the **"Cache Miner"** tab.

    -   Look for rows where **Status** is "Reflected".

    -   **High Risk:** If the "Cacheable?" column says **"Yes (High Risk)"**, you have likely found a valid cache poisoning vector.

    -   **Verification:** Click the row to see the response. Verify where the canary is reflected (e.g., inside a `<meta>` tag or JS variable).

Tech Stack
----------

-   **Language:** Java 21

-   **API:** Burp Suite Montoya API

-   **Concurrency:** `ExecutorService` (Multi-threaded Fuzzing)

-   **UI:** Swing (JTable, JSplitPane)

Disclaimer
----------

This tool is for educational purposes and authorized security testing only. Do not use this tool on systems you do not have permission to test. The author is not responsible for any misuse.
