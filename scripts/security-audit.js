/**
 * NEXORA DIGITAL STUDIO - AUTOMATED SECURITY AUDIT SUITE
 * Validates codebase integrity, secrets hygiene, headers, and XSS sanitization.
 */

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');

const findings = [];
let passCount = 0;

function check(title, fn) {
  try {
    const result = fn();
    if (result === true) {
      console.log(`  [PASS] ${title}`);
      passCount++;
    } else {
      console.log(`  [FAIL] ${title} - ${result}`);
      findings.push({ title, error: result });
    }
  } catch (err) {
    console.log(`  [ERROR] ${title} - ${err.message}`);
    findings.push({ title, error: err.message });
  }
}

console.log('\n======================================================');
console.log('       NEXORA SECURITY AUDIT & INTEGRITY CHECK');
console.log('======================================================\n');

// 1. Check for Plaintext Password in admin.html
check('Zero Plaintext Passwords in admin.html', () => {
  const adminHtml = fs.readFileSync(path.join(ROOT_DIR, 'admin.html'), 'utf8');
  if (adminHtml.includes('password: \'nexora6969\'') || adminHtml.includes('nexora6969')) {
    return 'Hardcoded plaintext password detected in admin.html!';
  }
  if (!adminHtml.includes('passHash:') || !adminHtml.includes('phoneHash:')) {
    return 'Missing cryptographic salted hash configuration in admin.html!';
  }
  return true;
});

// 2. Check for Web Crypto & Salted Hashing Implementation
check('Web Crypto SHA-256 Hashing Active in admin.html', () => {
  const adminHtml = fs.readFileSync(path.join(ROOT_DIR, 'admin.html'), 'utf8');
  if (!adminHtml.includes('crypto.subtle.digest(\'SHA-256\'')) {
    return 'Web Crypto SHA-256 hashing function not found in admin.html!';
  }
  return true;
});

// 3. Check for Brute Force & Rate Limit Protection in admin.html
check('Brute Force Defense & Session Token Management', () => {
  const adminHtml = fs.readFileSync(path.join(ROOT_DIR, 'admin.html'), 'utf8');
  if (!adminHtml.includes('getLoginLockout') || !adminHtml.includes('generateSecureToken')) {
    return 'Missing brute force lockout or secure session token logic!';
  }
  return true;
});

// 4. Check for CSV Injection Defense in admin.html
check('CSV Formula Injection Defense in exportInquiriesCSV', () => {
  const adminHtml = fs.readFileSync(path.join(ROOT_DIR, 'admin.html'), 'utf8');
  if (!adminHtml.includes('sanitizeCsvCell')) {
    return 'Missing CSV cell formula injection sanitizer!';
  }
  return true;
});

// 5. Check for Public Admin Route Removal in index.html
check('Public Admin Portal Link Removed from Public Footer', () => {
  const indexHtml = fs.readFileSync(path.join(ROOT_DIR, 'index.html'), 'utf8');
  if (indexHtml.includes('href="admin.html"')) {
    return 'Public link to admin.html is still present in index.html!';
  }
  if (!indexHtml.includes('keydown') || !indexHtml.includes('ctrlKey')) {
    return 'Stealth admin key shortcut not found in index.html!';
  }
  return true;
});

// 6. Check for Anti-Spam Honeypot & Rate Limiting in index.html Form
check('Inquiry Form Honeypot & Rate Limiting', () => {
  const indexHtml = fs.readFileSync(path.join(ROOT_DIR, 'index.html'), 'utf8');
  if (!indexHtml.includes('form-hp-field')) {
    return 'Honeypot field not found in inquiry form!';
  }
  if (!indexHtml.includes('INQUIRY_COOLDOWN_MS')) {
    return 'Inquiry submission cooldown not configured!';
  }
  return true;
});

// 7. Check for Style & Attribute Injection Defense in index.html
check('CSS Injection Sanitization in dynamic renderServices', () => {
  const indexHtml = fs.readFileSync(path.join(ROOT_DIR, 'index.html'), 'utf8');
  if (!indexHtml.includes('sanitizeCssColor')) {
    return 'Missing sanitizeCssColor helper!';
  }
  return true;
});

// 8. Check server.ps1 Hardening
check('Path Traversal Guard & Security Headers in server.ps1', () => {
  const serverPs1 = fs.readFileSync(path.join(ROOT_DIR, 'server.ps1'), 'utf8');
  if (!serverPs1.includes('Content-Security-Policy') || !serverPs1.includes('X-Frame-Options')) {
    return 'Missing CSP or security headers in server.ps1!';
  }
  if (!serverPs1.includes('Check-RateLimit')) {
    return 'Missing sliding-window rate limiter in server.ps1!';
  }
  if (!serverPs1.includes('StartsWith($canonicalFolder')) {
    return 'Missing path traversal canonical verification in server.ps1!';
  }
  return true;
});

// 9. Check vercel.json Security Headers
check('Vercel.json Production Security Headers & Blocked Redirects', () => {
  const vercelJson = fs.readFileSync(path.join(ROOT_DIR, 'vercel.json'), 'utf8');
  if (!vercelJson.includes('Content-Security-Policy') || !vercelJson.includes('X-Content-Type-Options')) {
    return 'Missing security headers in vercel.json!';
  }
  if (!/server(\\|\.)+ps1/.test(vercelJson) || !vercelJson.includes('Double-Click-To-Open')) {
    return 'Missing redirects blocking sensitive files in vercel.json!';
  }
  return true;
});

// 10. Check .gitignore & .env.example
check('.gitignore and .env.example configuration', () => {
  if (!fs.existsSync(path.join(ROOT_DIR, '.gitignore'))) {
    return 'Missing .gitignore file!';
  }
  if (!fs.existsSync(path.join(ROOT_DIR, '.env.example'))) {
    return 'Missing .env.example template file!';
  }
  const gitignore = fs.readFileSync(path.join(ROOT_DIR, '.gitignore'), 'utf8');
  if (!gitignore.includes('.env') || !gitignore.includes('node_modules')) {
    return '.gitignore missing rules for .env or node_modules!';
  }
  return true;
});

console.log('\n======================================================');
console.log(` Audit Complete: ${passCount}/10 Checks Passed.`);
if (findings.length === 0) {
  console.log(' STATUS: ALL SECURITY CHECKS PASSED WITH ZERO ERRORS.');
} else {
  console.log(` WARNING: ${findings.length} issue(s) require remediation.`);
}
console.log('======================================================\n');
