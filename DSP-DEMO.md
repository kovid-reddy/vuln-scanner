# 🛡️ WebScore — DSP Demo Guide

This guide details the single-command startup procedure, demonstration workflow, and quick troubleshooting steps for the **WebScore: OWASP Top 10 Security Scanner** DSP internship presentation.

---

## ⚡ Quick Start (The ONE Command)

From the root of the project directory (`vuln-scanner`), run in PowerShell:

```powershell
.\start-dsp-demo.ps1
```

---

## 🎯 Target Presentation Workflow

```text
Run .\start-dsp-demo.ps1
          ↓
Docker containers start (PostgreSQL, Redis, OWASP Juice Shop)
          ↓
Prisma Client generates
          ↓
WebScore API (:4000) + Scan Worker + Next.js Web (:3000) start
          ↓
Open browser: http://localhost:3000
          ↓
Enter target: http://localhost:3001
          ↓
Click "Scan"
          ↓
Live status updates (QUEUED → RUNNING → DONE)
          ↓
Inspect Findings, Severity Badges, Score Gauge & Export JSON Report
```

---

## 📋 Step-by-Step Meeting Walkthrough

### 1. Launch Environment
Run:
```powershell
.\start-dsp-demo.ps1
```
Wait until both `web` (port `3000`) and `api` (port `4000`) confirm they are listening.

### 2. Open WebScore Dashboard
Navigate to:
```text
http://localhost:3000
```

### 3. Enter the Local Vulnerable Target
Paste the local OWASP Juice Shop URL into the target input:
```text
http://localhost:3001
```

### 4. Execute the Security Scan
* **Option A (Full Scan)**: Leave mode on **"Scan all checks"** and click **Scan**.
* **Option B (Selective Checks)**: Click **"Choose checks"** to demonstrate specific vulnerability modules (e.g. *CORS*, *HTTP Method Abuse*, *Forced Browsing*, *SQL Injection*, *XSS*).

### 5. Review Results with Evaluators
Explain the core features rendered on the results page:
1. **Dynamic Security Score Gauge**: Risk-adjusted rating from 0 to 100 based on severity penalties (Critical: -40, High: -20, Medium: -10, Low: -5).
2. **Vulnerability Summary & Badges**: Breakdown of Critical, High, Medium, and Low issues detected on the target.
3. **Actionable Finding Cards**:
   * Vulnerability Title & Severity
   * Detailed Description & Attack Impact
   * Real HTTP Request/Response Evidence (e.g. exposed config files, accepted dangerous HTTP verbs)
   * Exact Remediation Instructions
4. **JSON Report Export**: Click **"Export JSON"** to download the structured assessment report.

---

## 🔧 Troubleshooting Guide

### 1. Docker Daemon Not Running
* **Symptom**: `❌ Docker is not running!` or error connecting to Docker named pipe.
* **Fix**:
  1. Open the Start Menu and launch **Docker Desktop**.
  2. Wait until the Docker status indicator at the bottom-left shows green ("Engine running").
  3. Re-run `.\start-dsp-demo.ps1`.

### 2. Port Already in Use (3000, 3001, 4000, 5432, or 6379)
* **Symptom**: `EADDRINUSE: address already in use :::3000` or `:::4000`.
* **Fix**: Identify and terminate the lingering Node process:
  ```powershell
  # Find process using the port (e.g. 4000 or 3000)
  Get-Process -Id (Get-NetTCPConnection -LocalPort 4000).OwningProcess | Stop-Process -Force
  Get-Process -Id (Get-NetTCPConnection -LocalPort 3000).OwningProcess | Stop-Process -Force
  ```

### 3. Juice Shop Container Already Running or Conflict
* **Symptom**: `Conflict: The container name "/juice-shop" is already in use`.
* **Fix**: The script handles this automatically. If manually needed:
  ```powershell
  docker restart juice-shop
  ```

### 4. API Cannot Connect to PostgreSQL or Redis
* **Symptom**: `[redis] Error: connect ECONNREFUSED` or Prisma connection error.
* **Fix**: Start the Docker containers:
  ```powershell
  docker start pg redis
  ```
  Verify status:
  ```powershell
  docker ps
  ```

### 5. Frontend Not Connecting to API
* **Symptom**: `Failed to start scan` or red error message in web UI.
* **Fix**:
  1. Verify the Fastify API is running on `http://localhost:4000/health`.
  2. Confirm `apps/web/.env.local` contains:
     ```env
     NEXT_PUBLIC_API_URL=http://localhost:4000
     ```

---

## 🛑 Stopping the Demo After Presentation

Press `Ctrl + C` in the terminal to stop the Next.js and Fastify servers.

To stop the background Docker containers when finished:
```powershell
docker stop pg redis juice-shop
```
