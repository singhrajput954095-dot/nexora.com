# Nexora — Digital Agency Website

Nexora is a high-performance digital experiences, technology, and creative agency platform featuring interactive 3D WebGL gravity shaders, dynamic service estimators, and an authorized, security-hardened management portal.

## 🚀 Live Demo & Deployment
- **Production URL**: [https://nexora-agency-website.vercel.app](https://nexora-agency-website.vercel.app)
- **Deployment Platform**: Vercel (`npx vercel --prod`)

## ✨ Core Features
- **Agency Disciplines**: Web Development, Authorized Cybersecurity, Video Shooting & Production, Video Editing, and Creative Retouching.
- **Interactive Project Estimator**: Real-time pricing calculations, scope breakdowns, and inquiry generation.
- **Admin Management Portal**: Real-time management for client inquiries, custom work cards, tiered pricing, and direct phone settings.
- **Stealth Access**: Secret administrator key shortcut (`Ctrl + Shift + A`) with search engine blocking (`noindex`).

## 🛡️ Security Hardening & Defenses
- **Zero Plaintext Secrets**: Cryptographic Web Crypto SHA-256 salted password hashing (`AUTH_CONFIG`).
- **Brute-Force Protection**: 5-attempt threshold with automatic 15-minute security lockout.
- **Anti-Bot & Anti-Spam**: Contact form honeypot trapping with 30-second submission rate limiting.
- **Anti-XSS & Injection Protection**: HTML entity sanitization, dynamic CSS color validation, and CSV formula neutralization (OWASP CWE-1236).
- **Hardened Preview Server**: Path traversal guard, in-memory sliding-window IP rate limiter, and blocked config file rules.
- **OWASP Security Headers**: Configured in both `server.ps1` and `vercel.json` (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy).

## 🛠️ Local Development & Preview
To start the local preview server:
- Double-click `Double-Click-To-Open.bat`, or
- Run via PowerShell:
  ```powershell
  powershell -ExecutionPolicy Bypass -File server.ps1
  ```
- Or run the automated security audit:
  ```bash
  node ./scripts/security-audit.js
  ```

## 📦 Deployment
Deploy instantly via Vercel:
```bash
npx vercel --prod
```
