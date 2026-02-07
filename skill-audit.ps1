# Skill Security Auditor
# Run before installing any new skill to detect suspicious patterns

param(
    [Parameter(Mandatory=$true)]
    [string]$SkillPath
)

$RED = "Red"
$YELLOW = "Yellow"
$GREEN = "Green"
$CYAN = "Cyan"

Write-Host "=== Skill Security Audit ===" -ForegroundColor $CYAN
Write-Host "Target: $SkillPath" -ForegroundColor $CYAN
Write-Host ""

$issues = 0

# 1. Check for credential stealing patterns
$credPatterns = @(
    '\.env',
    'credentials\.json',
    'api[_-]?key',
    'secret[_-]?key',
    'private[_-]?key',
    'password',
    'AKIA[0-9A-Z]{16}',  # AWS keys
    'ghp_[A-Za-z0-9]{36}',  # GitHub tokens
    'sk-[A-Za-z0-9]{20,}',  # OpenAI keys
    'moltbook_sk_'  # Moltbook keys
)

Write-Host "--- Credential Access Patterns ---" -ForegroundColor $YELLOW
foreach ($pattern in $credPatterns) {
    $matches = Get-ChildItem -Path $SkillPath -Recurse -File -ErrorAction SilentlyContinue | 
        Select-String -Pattern $pattern -ErrorAction SilentlyContinue
    if ($matches) {
        Write-Host "  [!] Found '$pattern':" -ForegroundColor $RED
        $matches | Select-Object -First 2 | ForEach-Object {
            Write-Host "      $($_.Filename):$($_.LineNumber)" -ForegroundColor $RED
        }
        $issues++
    }
}

# 2. Check for data exfiltration patterns
Write-Host ""
Write-Host "--- Data Exfiltration Patterns ---" -ForegroundColor $YELLOW
$exfilPatterns = @(
    'webhook\.site',
    'requestbin',
    'pipedream',
    'ngrok',
    'POST.*http',
    'fetch\s*\(',
    'curl.*-X\s*POST',
    'requests\.post',
    'http\.post',
    'axios\.post'
)

foreach ($pattern in $exfilPatterns) {
    $matches = Get-ChildItem -Path $SkillPath -Recurse -File -ErrorAction SilentlyContinue | 
        Select-String -Pattern $pattern -ErrorAction SilentlyContinue
    if ($matches) {
        Write-Host "  [!] Found '$pattern':" -ForegroundColor $RED
        $matches | Select-Object -First 2 | ForEach-Object {
            $line = $_.Line.Trim()
            if ($line.Length -gt 70) { $line = $line.Substring(0, 70) + "..." }
            Write-Host "      $line" -ForegroundColor $RED
        }
        $issues++
    }
}

# 3. Check for shell execution
Write-Host ""
Write-Host "--- Shell Execution Patterns ---" -ForegroundColor $YELLOW
$shellPatterns = @(
    'exec\s*\(',
    'system\s*\(',
    'popen',
    'subprocess',
    'child_process',
    'eval\s*\(',
    'os\.system',
    'shell=True'
)

foreach ($pattern in $shellPatterns) {
    $matches = Get-ChildItem -Path $SkillPath -Recurse -File -ErrorAction SilentlyContinue | 
        Select-String -Pattern $pattern -ErrorAction SilentlyContinue
    if ($matches) {
        Write-Host "  [?] Found '$pattern' (review needed):" -ForegroundColor $YELLOW
        $matches | Select-Object -First 2 | ForEach-Object {
            Write-Host "      $($_.Filename):$($_.LineNumber)" -ForegroundColor $YELLOW
        }
    }
}

# 4. Check for file system access outside skill dir
Write-Host ""
Write-Host "--- Filesystem Access Patterns ---" -ForegroundColor $YELLOW
$fsPatterns = @(
    '\.\./\.\.',  # Path traversal
    '~/\.',       # Home directory dotfiles
    '/etc/',
    'C:\\Users',
    '%USERPROFILE%',
    '%APPDATA%',
    '\$HOME'
)

foreach ($pattern in $fsPatterns) {
    $matches = Get-ChildItem -Path $SkillPath -Recurse -File -ErrorAction SilentlyContinue | 
        Select-String -Pattern $pattern -ErrorAction SilentlyContinue
    if ($matches) {
        Write-Host "  [!] Found '$pattern' (filesystem access):" -ForegroundColor $RED
        $matches | Select-Object -First 2 | ForEach-Object {
            Write-Host "      $($_.Filename):$($_.LineNumber)" -ForegroundColor $RED
        }
        $issues++
    }
}

# Summary
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor $CYAN
if ($issues -eq 0) {
    Write-Host "[OK] No obvious security issues found" -ForegroundColor $GREEN
    Write-Host "     Still review SKILL.md manually for suspicious instructions!" -ForegroundColor $YELLOW
} else {
    Write-Host "[WARNING] Found $issues potential security issue(s)" -ForegroundColor $RED
    Write-Host "          DO NOT install until reviewed!" -ForegroundColor $RED
}

exit $issues
