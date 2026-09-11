<!--Banner -->
<p align="center">
  <img src="demo-assets/banner.png" alt="WebScore Banner" width="100%">
</p>

<!-- Badges -->
<p align="center">

<img src="https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB"/>

<img src="https://img.shields.io/badge/Next.js-000000?style=for-the-badge&logo=next.js&logoColor=white"/>

<img src="https://img.shields.io/badge/Fastify-000000?style=for-the-badge&logo=fastify&logoColor=white"/>

<img src="https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white"/>

<img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white"/>

<img src="https://img.shields.io/badge/Prisma-2D3748?style=for-the-badge&logo=prisma&logoColor=white"/>

<img src="https://img.shields.io/badge/OWASP%20Top%2010-Security-critical?style=for-the-badge&color=8A2BE2"/>

<!-- intro -->
</p>
<p align="center">
**Analyze • Detect • Score • Secure**
</p>

## 📖 Overview

**WebScore** is a full-stack web application vulnerability scanner inspired by the **OWASP Top 10**.

It automatically analyzes websites, identifies security vulnerabilities, calculates an overall **security score**, and provides detailed remediation guidance to help developers build more secure applications.

Built with a scalable **Turborepo monorepo architecture**, WebScore separates the frontend, API, and scanning engine into independent services for improved maintainability and scalability.

## 📸 Dashboard Preview

<p align="center">
<img src="demo-assets/completed_scan_results_1783526772579.png" width="95%" alt="WebScore Dashboard">
</p>

<p align="center">
<i>WebScore dashboard showing scan configuration, real-time progress, vulnerability findings and overall security score.</i>
</p>

## 🚀 Why WebScore?

WebScore combines automated vulnerability detection, security scoring, and remediation guidance into a single platform to help developers identify and prioritize security risks efficiently.

### Highlights

- 🛡️ OWASP Top 10 inspired vulnerability detection
- 📊 Dynamic security scoring system
- ⚡ Background asynchronous scanning via BullMQ
- 🌐 Automatic endpoint crawling
- 📄 Actionable remediation recommendations
- 🏗️ Modular Turborepo monorepo architecture

---

## 🏗️ Architecture Overview

The project is structured as a TypeScript monorepo managed with **pnpm Workspaces** and **Turborepo**:

```mermaid
graph TD
    Web[apps/web<br>Next.js Frontend] -->|REST API calls| API[apps/api<br>Fastify Backend]
    API -->|Saves scan records| DB[(Supabase PostgreSQL)]
    API -->|Pushes jobs| Queue[BullMQ / Redis]
    Queue -->|Pulls jobs<br>same process| Worker[BullMQ Worker<br>apps/api/src/queue]
    Worker -->|Dynamic import| Scanner[apps/scanner<br>Security Engine]
    Scanner -->|Probes / Crawls| Target[Target Website]
```

| Package | Description |
|---------|-------------|
| **`apps/web`** | Next.js 16 + React 19 + Tailwind CSS v4 frontend. Starts scans, polls status, displays findings, score gauge, and JSON export. Deployed on **Vercel**. |
| **`apps/api`** | Fastify REST API. Accepts scan requests, persists results via Prisma, and hosts the BullMQ worker in the same process. Deployed on **Render**. |
| **`apps/scanner`** | Core security engine. Crawls pages, discovers endpoints, and runs all security checks. Imported dynamically by the worker — not a standalone service. |
| **`packages/shared-types`** | Shared TypeScript type definitions used by frontend, API, and scanner. |

---

## 🔍 Security Engine Capabilities

The scanner runs in two phases:

1. **Site-wide Checks**: Executed once against the target's root URL.
2. **Endpoint-specific Checks**: Runs a localized crawl (up to 40 pages, max depth 3) extracting `a[href]` links, forms, and API endpoint references from JavaScript (`fetch`/`axios`). Runs selected checks against all discovered endpoints in batches of 5.

### 🛡 Authentication

| Check ID | Level | Detection Strategy |
| :--- | :---: | :--- |
| `cookies` | 🌐 Site | Inspects cookies for missing **Secure**, **HttpOnly**, **SameSite** flags and validates security headers such as **HSTS**, **CSP**, and **X-Content-Type-Options**. |
| `jwt` | 🌐 Site | Tests JWT implementations for weak secrets, **none** algorithm abuse, and signature verification bypasses. |
| `csrf` | 🌐 Site | Detects missing CSRF tokens and insufficient protection for state-changing requests. |
| `ssrf` | 🌐 Site | Checks whether server-side requests can be redirected to internal networks or cloud metadata endpoints. |

### 🔓 Broken Access Control

| Check ID | Level | Detection Strategy |
| :--- | :---: | :--- |
| `cors` | 🌐 Site | Detects wildcard origins, origin reflection, and credentialed cross-origin requests. |
| `forced-browsing` | 🌐 Site | Discovers hidden files, backups, Git directories, admin panels, and exposed resources. |
| `http-method-abuse` | 🌐 Site | Tests support for unexpected HTTP methods such as **PUT**, **DELETE**, and **TRACE**. |
| `idor` | 🎯 Endpoint | Manipulates predictable identifiers to detect Insecure Direct Object Reference vulnerabilities. |

### 💉 Injection

| Check ID | Level | Detection Strategy |
| :--- | :---: | :--- |
| `sqli` | 🎯 Endpoint | Error-based • Boolean-blind • Time-based SQL Injection detection. |
| `xss` | 🎯 Endpoint | Reflected • DOM-based Cross-Site Scripting detection. |
| `ssti` | 🎯 Endpoint | Tests common template engines using standard SSTI payloads. |
| `os-command` | 🎯 Endpoint | Attempts OS command execution using Linux and Windows payloads. |
| `file-upload` | 🎯 Endpoint | Detects unrestricted file upload vulnerabilities and MIME bypasses. |
| `xxe` | 🎯 Endpoint | Tests XML parsers for XXE, SSRF, and local file disclosure. |

---

## 🎥 WebScore in Action

<p align="center">
  <img src="./demo-assets/run_demo_scan_1783526726800.webp" width="95%">
</p>

<p align="center">
  <em>Scanning a target website and generating a complete security report.</em>
</p>

## 🧮 Scoring System (WebScore)

The security score (from **0 to 100**) starts at `100` and subtracts penalties based on the severity of unique findings:

- 🛑 **CRITICAL** (e.g., SQLi, Command Injection) → **-40 points**
- 🟠 **HIGH** (e.g., CORS with credentials reflection, XXE) → **-20 points**
- 🟡 **MEDIUM** (e.g., CORS wildcard, CSRF) → **-10 points**
- 🔵 **LOW** (e.g., insecure cookies) → **-5 points**
- ⚪ **INFO** (e.g., server headers) → **-0 points**

**Rating Ranges:**
- 🟩 **80 – 100**: Good security posture
- 🟨 **50 – 79**: Moderate risks (needs attention)
- 🟥 **0 – 49**: Poor security posture (critical vulnerabilities present)

---

# ⚙️ Tech Stack

<div align="center">

| Layer | Technologies |
|:------|:-------------|
| 🎨 **Frontend** | Next.js 16 • React 19 • TypeScript • Tailwind CSS v4 |
| ⚙️ **Backend API** | Fastify • Node.js • TypeScript |
| 🔍 **Scanner Engine** | Node.js • Axios • Cheerio |
| 🗄️ **Database** | Supabase PostgreSQL • Prisma ORM |
| 📬 **Queue System** | BullMQ • Redis (ioredis) |
| ☁️ **Hosting** | Vercel (frontend) • Render (backend) |
| 🏗️ **Architecture** | Turborepo Monorepo • pnpm Workspaces |

</div>

<p align="center">
<img src="https://skillicons.dev/icons?i=react,ts,nodejs,postgres,redis,vercel,git"/>
</p>

---

## 🚀 Local Development

### Prerequisites

- [Node.js](https://nodejs.org/) v20+
- [pnpm](https://pnpm.io/) v9+
- A local **PostgreSQL** instance (or Docker)
- A local **Redis** instance (or Docker)

### 1. Install Dependencies

```bash
pnpm install
```

### 2. Configure Environment Variables

Copy the example files and fill in your local values:

```bash
cp apps/api/.env.example apps/api/.env
cp apps/web/.env.example apps/web/.env.local
```

**`apps/api/.env`** (local defaults work out of the box):
```env
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/vulnscanner"
REDIS_URL="redis://localhost:6379"
FRONTEND_URL="http://localhost:3000"
PORT=4000
NODE_ENV=development
```

**`apps/web/.env.local`**:
```env
NEXT_PUBLIC_API_URL=http://localhost:4000
```

### 3. Initialize the Database

Generate the Prisma client and apply migrations:

```bash
pnpm --filter api db:generate
pnpm --filter api db:migrate
```

### 4. Run Development Servers

Start all workspaces:

```bash
pnpm dev
```

Or run individually:

```bash
pnpm dev:api   # Starts Fastify API + BullMQ worker (same process)
pnpm dev:web   # Starts Next.js frontend
```

Open [http://localhost:3000](http://localhost:3000) to access the dashboard.

---

## 🌐 Production Deployment

WebScore uses three external services in production:

| Service | Purpose | Platform |
|---------|---------|----------|
| **Vercel** | Hosts the Next.js frontend | [vercel.com](https://vercel.com) |
| **Render** | Hosts the Fastify API + BullMQ worker | [render.com](https://render.com) |
| **Supabase** | PostgreSQL database | [supabase.com](https://supabase.com) |
| **Render Redis** | Redis for BullMQ job queue | Render internal service |

### Vercel (Frontend)

1. Connect your repository to Vercel.
2. Set **Root Directory** to `apps/web`.
3. Add environment variable in the Vercel dashboard:

   | Variable | Value |
   |----------|-------|
   | `NEXT_PUBLIC_API_URL` | Your Render backend URL, e.g. `https://vuln-scanner-api.onrender.com` |

### Render (Backend)

The repository includes a `render.yaml` blueprint. Connect your repository to Render and it will auto-configure the web service and Redis.

You must manually set the following in **Render → Service → Environment**:

| Variable | Value |
|----------|-------|
| `DATABASE_URL` | Supabase PostgreSQL connection string (from Supabase → Settings → Database) |
| `FRONTEND_URL` | Your Vercel deployment URL, e.g. `https://your-app.vercel.app` |

`REDIS_URL`, `NODE_ENV`, and `PORT` are auto-injected by `render.yaml`.

### Supabase (Database)

1. Create a new Supabase project.
2. Copy the **Connection String** from Supabase → Settings → Database → URI.
3. Paste it as `DATABASE_URL` in the Render dashboard.
4. Prisma migrations run automatically on every Render deploy via the `startCommand` in `render.yaml`.

### Database Migrations

Migrations live in `apps/api/prisma/migrations/` and are applied automatically at startup on Render:

```bash
# Applied automatically by render.yaml startCommand:
npx prisma migrate deploy
```

To run manually against production:
```bash
DATABASE_URL="<your-supabase-url>" npx prisma migrate deploy
```

---

## 📁 Repository Structure

```
vuln-scanner/
├── apps/
│   ├── api/                    # Fastify backend + BullMQ worker
│   │   ├── prisma/
│   │   │   ├── schema.prisma   # Database schema
│   │   │   └── migrations/     # Migration history
│   │   └── src/
│   │       ├── server.ts       # Entry point — starts API + imports worker
│   │       ├── db/prisma.ts    # Prisma client singleton
│   │       ├── routes/         # API route handlers
│   │       └── queue/          # BullMQ queue, worker, Redis connection
│   ├── scanner/                # Security engine (library — imported by worker)
│   │   └── src/
│   │       ├── orchestrator.ts # Scan coordinator
│   │       ├── checks/         # Individual security checks
│   │       └── utils/          # HTTP client, crawler
│   └── web/                    # Next.js frontend
│       ├── app/                # App Router pages
│       ├── components/         # UI components
│       └── lib/api.ts          # API client
├── packages/
│   └── shared-types/           # Shared TypeScript types
├── render.yaml                 # Render deployment blueprint
├── pnpm-workspace.yaml         # pnpm workspace config
├── turbo.json                  # Turborepo pipeline config
└── tsconfig.base.json          # Shared TypeScript config
```

---

## ⚖️ Legal Disclaimer

> [!WARNING]
> **WebScore** is intended solely for authorized security testing, research, and educational purposes.
>
> Only scan systems, applications, or APIs that you own or have explicit written permission to assess. Unauthorized security testing may violate applicable laws and regulations.
>
> The authors and contributors of WebScore are **not responsible** for any misuse, unauthorized activity, or damages resulting from the use of this software.

> 💙 Please use WebScore responsibly and help make the web a safer place.

## 📜 License

This project is currently **not licensed for public reuse or redistribution**.

All rights reserved © Kovid Reddy Kontham.
