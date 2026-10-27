# ==============================================================================
# NEXORA DIGITAL STUDIO - HARDENED PREVIEW SERVER
# ==============================================================================
# Security Hardened: Path Traversal Protection, In-Memory Rate Limiting,
# OWASP Security Headers (CSP, HSTS, X-Frame, X-Content-Type), Strict CORS,
# and Blocked Sensitive File Extensions.

$port = 8888
$folder = $PSScriptRoot
if (-not $folder) { $folder = (Get-Location).Path }
$canonicalFolder = [System.IO.Path]::GetFullPath($folder).TrimEnd('\', '/')

$maxPort = $port + 50
while ($port -lt $maxPort) {
    try {
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://localhost:$port/")
        $listener.Prefixes.Add("http://127.0.0.1:$port/")
        $listener.Start()
        break
    } catch {
        $port++
    }
}

if (-not $listener.IsListening) {
    Write-Error "Could not start server on ports $port-$maxPort"
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Nexora Studio Hardened Server (Secure Mode) Active!" -ForegroundColor Green
Write-Host "  URL: http://localhost:$port/" -ForegroundColor Yellow
Write-Host "  Web Root: $canonicalFolder" -ForegroundColor Gray
Write-Host "  Security: CSP | Anti-Traversal | Rate Limiter | CORS Guard" -ForegroundColor DarkCyan
Write-Host "  Press Ctrl+C to stop" -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan

Start-Process "http://localhost:$port/"

# Safe MIME types whitelist (Never execute or serve arbitrary binaries)
$mimeTypes = @{
    ".html"  = "text/html; charset=utf-8"
    ".js"    = "application/javascript; charset=utf-8"
    ".mjs"   = "application/javascript; charset=utf-8"
    ".css"   = "text/css; charset=utf-8"
    ".svg"   = "image/svg+xml"
    ".png"   = "image/png"
    ".jpg"   = "image/jpeg"
    ".jpeg"  = "image/jpeg"
    ".webp"  = "image/webp"
    ".ico"   = "image/x-icon"
    ".woff"  = "font/woff"
    ".woff2" = "font/woff2"
    ".ttf"   = "font/ttf"
}

# Blocked extensions and sensitive configuration files (Defense in Depth)
$blockedExtensions = @(".ps1", ".bat", ".cmd", ".sh", ".vbs", ".exe", ".env", ".git", ".md", ".bak", ".old", ".log")
$blockedFiles = @("package.json", "package-lock.json", "vercel.json", "server.ps1", "Double-Click-To-Open.bat", "README.md")

# Sliding-window Rate Limiting Store: Client IP -> List of UTC timestamps
$rateLimitStore = [System.Collections.Hashtable]::Synchronized(@{})
$rateLimitWindowSeconds = 60
$rateLimitMaxRequests = 120

function Check-RateLimit($clientIp) {
    $now = [DateTime]::UtcNow
    $cutoff = $now.AddSeconds(-$rateLimitWindowSeconds)
    
    if (-not $rateLimitStore.ContainsKey($clientIp)) {
        $rateLimitStore[$clientIp] = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    }
    
    $list = $rateLimitStore[$clientIp]
    for ($i = $list.Count - 1; $i -ge 0; $i--) {
        if ($list[$i] -lt $cutoff) {
            $list.RemoveAt($i)
        }
    }
    
    if ($list.Count -ge $rateLimitMaxRequests) {
        return $false
    }
    
    [void]$list.Add($now)
    return $true
}

function Add-SecurityHeaders($response, $request) {
    # CORS: Allow same-origin / localhost
    $origin = $request.Headers["Origin"]
    if ($origin -and ($origin -match "^https?://(localhost|127\.0\.0\.1)(:\d+)?$")) {
        $response.Headers.Add("Access-Control-Allow-Origin", $origin)
        $response.Headers.Add("Access-Control-Allow-Credentials", "true")
    } else {
        $response.Headers.Add("Access-Control-Allow-Origin", "null")
    }
    $response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    $response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
    
    # Modern OWASP Security Headers
    $response.Headers.Add("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://wa.me mailto:;")
    $response.Headers.Add("X-Content-Type-Options", "nosniff")
    $response.Headers.Add("X-Frame-Options", "DENY")
    $response.Headers.Add("X-XSS-Protection", "1; mode=block")
    $response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin")
    $response.Headers.Add("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    $response.Headers.Add("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
    $response.Headers.Add("X-Permitted-Cross-Domain-Policies", "none")
}

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        $clientIp = $request.RemoteEndPoint.Address.ToString()
        
        # 1. Rate Limiting Check
        if (-not (Check-RateLimit $clientIp)) {
            Add-SecurityHeaders $response $request
            $response.StatusCode = 429
            $response.Headers.Add("Retry-After", "60")
            $msg = [System.Text.Encoding]::UTF8.GetBytes("429 Too Many Requests - Rate limit exceeded. Try again in 60s.")
            $response.ContentType = "text/plain; charset=utf-8"
            $response.ContentLength64 = $msg.Length
            $response.OutputStream.Write($msg, 0, $msg.Length)
            $response.Close()
            continue
        }
        
        # 2. Handle OPTIONS Preflight
        if ($request.HttpMethod -eq "OPTIONS") {
            Add-SecurityHeaders $response $request
            $response.StatusCode = 204
            $response.Close()
            continue
        }
        
        Add-SecurityHeaders $response $request
        
        # 3. Path Traversal & Canonical Path Verification
        $rawPath = [System.Uri]::UnescapeDataString($request.Url.LocalPath.TrimStart('/'))
        if ([string]::IsNullOrWhiteSpace($rawPath) -or $rawPath -eq '/') {
            $rawPath = "index.html"
        }
        
        try {
            $targetPath = [System.IO.Path]::GetFullPath((Join-Path $canonicalFolder $rawPath))
        } catch {
            $response.StatusCode = 400
            $response.Close()
            continue
        }
        
        # Enforce that target path is strictly within the web root folder
        if (-not $targetPath.StartsWith($canonicalFolder, [System.StringComparison]::OrdinalIgnoreCase)) {
            $response.StatusCode = 403
            $msg = [System.Text.Encoding]::UTF8.GetBytes("403 Forbidden - Access Denied.")
            $response.ContentType = "text/plain; charset=utf-8"
            $response.ContentLength64 = $msg.Length
            $response.OutputStream.Write($msg, 0, $msg.Length)
            $response.Close()
            continue
        }
        
        $filename = [System.IO.Path]::GetFileName($targetPath).ToLower()
        $ext = [System.IO.Path]::GetExtension($targetPath).ToLower()
        
        # 4. Check for Blocked Extensions or Sensitive Files
        if ($blockedExtensions -contains $ext -or $blockedFiles -contains $filename -or $filename.StartsWith(".")) {
            $response.StatusCode = 404
            $response.Close()
            continue
        }
        
        # Fallback to index.html for SPA routes if leaf file does not exist
        if (-not (Test-Path $targetPath -PathType Leaf)) {
            $targetPath = Join-Path $canonicalFolder "index.html"
            $ext = ".html"
        }
        
        # 5. Serve File with Safe Whitelisted MIME Type
        if ((Test-Path $targetPath -PathType Leaf) -and $mimeTypes.ContainsKey($ext)) {
            $mime = $mimeTypes[$ext]
            $bytes = [System.IO.File]::ReadAllBytes($targetPath)
            
            if ($ext -eq ".html") {
                $response.Headers.Add("Cache-Control", "no-cache, no-store, must-revalidate")
            } else {
                $response.Headers.Add("Cache-Control", "public, max-age=86400")
            }
            
            $response.ContentType = $mime
            $response.ContentLength64 = $bytes.Length
            $response.StatusCode = 200
            $response.OutputStream.Write($bytes, 0, $bytes.Length)
        } else {
            $response.StatusCode = 404
        }
        $response.Close()
    }
} finally {
    $listener.Stop()
    $listener.Close()
}
