# ==============================================================================
# WebScore - OWASP Top 10 Security Scanner: DSP Demo Startup Script
# ==============================================================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   WebScore - OWASP Security Scanner DSP Demo Setup" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Docker Availability
Write-Host "[1/5] Checking Docker daemon status..." -ForegroundColor Yellow
$dockerReady = $false
try {
    $null = docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        $dockerReady = $true
    }
} catch {
    $dockerReady = $false
}

if (-not $dockerReady) {
    Write-Host "      Docker is not responding. Attempting to start Docker Desktop..." -ForegroundColor Yellow
    $dockerPath = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    if (Test-Path $dockerPath) {
        Start-Process $dockerPath
        Write-Host "      Waiting for Docker daemon to become ready..." -ForegroundColor Yellow
        $retries = 30
        while ($retries -gt 0) {
            Start-Sleep -Seconds 2
            try {
                $null = docker info 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $dockerReady = $true
                    break
                }
            } catch {}
            $retries--
        }
    }
}

if (-not $dockerReady) {
    Write-Host "[ERROR] Docker is not running! Please start Docker Desktop and rerun this script." -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] Docker daemon is active and responding." -ForegroundColor Green

# 2. Start Required Containers (pg, redis, juice-shop)
Write-Host ""
Write-Host "[2/5] Initializing Docker containers..." -ForegroundColor Yellow

$allContainers = docker ps -a --format "{{.Names}}"

foreach ($name in @("pg", "redis")) {
    if ($allContainers -contains $name) {
        $status = docker inspect -f "{{.State.Status}}" $name
        if ($status -ne "running") {
            Write-Host "      Starting container: $name..." -ForegroundColor Gray
            docker start $name | Out-Null
        }
        Write-Host "  [OK] Container '$name' is running." -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Required container '$name' was not found in Docker. Please ensure PostgreSQL and Redis containers are created." -ForegroundColor Red
        exit 1
    }
}

# Juice Shop container
if ($allContainers -contains "juice-shop") {
    $jsStatus = docker inspect -f "{{.State.Status}}" "juice-shop"
    if ($jsStatus -ne "running") {
        Write-Host "      Starting container: juice-shop..." -ForegroundColor Gray
        docker start "juice-shop" | Out-Null
    }
    Write-Host "  [OK] Container 'juice-shop' is running." -ForegroundColor Green
} else {
    Write-Host "      Creating and starting container: juice-shop..." -ForegroundColor Gray
    docker run -d -p 3001:3000 --name juice-shop bkimminich/juice-shop | Out-Null
    Write-Host "  [OK] Container 'juice-shop' created and running on port 3001." -ForegroundColor Green
}

# 3. Verify Connectivity on Ports
Write-Host ""
Write-Host "[3/5] Verifying service connectivity..." -ForegroundColor Yellow

function Test-PortStatus([int]$port, [string]$name) {
    $test = Test-NetConnection -ComputerName "localhost" -Port $port -WarningAction SilentlyContinue
    if ($test.TcpTestSucceeded) {
        Write-Host "  [OK] $name is listening on localhost:$port" -ForegroundColor Green
        return $true
    } else {
        Write-Host "  [WAIT] Waiting for $name on localhost:$port..." -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        $test2 = Test-NetConnection -ComputerName "localhost" -Port $port -WarningAction SilentlyContinue
        if ($test2.TcpTestSucceeded) {
            Write-Host "  [OK] $name is listening on localhost:$port" -ForegroundColor Green
            return $true
        }
        Write-Host "  [FAIL] $name failed to connect on localhost:$port" -ForegroundColor Red
        return $false
    }
}

$pgOk = Test-PortStatus 5432 "PostgreSQL"
$redisOk = Test-PortStatus 6379 "Redis"
$jsOk = Test-PortStatus 3001 "OWASP Juice Shop"

if (-not ($pgOk -and $redisOk -and $jsOk)) {
    Write-Host "[ERROR] One or more background services failed to start. Please check Docker logs." -ForegroundColor Red
    exit 1
}

# 4. Generate Prisma Client if needed
Write-Host ""
Write-Host "[4/5] Syncing database schema..." -ForegroundColor Yellow
pnpm --filter api db:generate | Out-Null
Write-Host "  [OK] Prisma Client ready." -ForegroundColor Green

# 5. Instructions & Launch Development Server
Write-Host ""
Write-Host "[5/5] Launching WebScore Development Servers..." -ForegroundColor Yellow
Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  DSP DEMO READY!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  1. Open Dashboard:  http://localhost:3000" -ForegroundColor Cyan
Write-Host "  2. Target URL:      http://localhost:3001" -ForegroundColor Cyan
Write-Host "  3. Click:           'Scan' (or choose checks)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""

pnpm dev
