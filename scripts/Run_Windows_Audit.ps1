param(
    [string]$TargetPath = "",
    [string]$Mode = "standard",
    [switch]$NonInteractive
)

$ErrorActionPreference = "Continue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$RunnerPy = Join-Path $RepoRoot "white_hacker_runner.py"
$OutputDir = Join-Path $RepoRoot "strix_runs"

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host " 🛡️ AIホワイトハッカー 包括的セキュリティ監査ランチャー (Windows Client / Server)" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host " ※本ツールは読み取り専用(Read-Only)で検査を行い、既存ファイルの変更や外部送信は一切行いません。" -ForegroundColor Gray
Write-Host ""

function Find-WorkingPython {
    foreach ($cmd in @("python", "python3", "py")) {
        try {
            $ver = & $cmd --version 2>&1
            if ($LASTEXITCODE -eq 0 -and $ver -match "Python 3") {
                return $cmd
            }
        } catch {}
    }
    return $null
}

function Select-TargetFolderDialog {
    try {
        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = "セキュリティ監査を行うアプリ・サイトのフォルダを選択してください（キャンセル時は現在のフォルダ）"
        $dialog.ShowNewFolderButton = $false
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            return $dialog.SelectedPath
        }
    } catch {}
    return $RepoRoot
}

function Invoke-NativePowerShellAudit {
    param([string]$ScanPath)

    Write-Host "[INFO] Python未導入のWindows環境のため、Windows標準PowerShellネイティブ監査エンジンで実行します..." -ForegroundColor Yellow
    $runId = "run_" + (Get-Date -Format "yyyyMMdd_HHmmss")
    $runDir = Join-Path $OutputDir $runId
    $findingsDir = Join-Path $runDir "findings"
    New-Item -ItemType Directory -Force -Path $findingsDir | Out-Null

    $findings = @()
    $seq = 1

    # 1. Windows ファイアウォール検査 (読み取り専用)
    try {
        $fwOut = (netsh advfirewall show allprofiles 2>$null) -join "`n"
        if ($fwOut -match "State\s+OFF|状態\s+オフ") {
            $findings += [PSCustomObject]@{
                id = ("WH-{0:D3}" -f $seq); title = "Windowsファイアウォールの無効化（不正通信の素通りリスク）"
                domain_key = "infra_supply_chain"; role = "Windows端末・サーバー防衛担当"
                category = "Host Security: Windows Firewall Disabled"; severity = "HIGH"
                risk_priority_score = 80; file_path = "Windows_OS/Firewall"; line_number = 1
                code_snippet = "netsh advfirewall show allprofiles -> OFF"
                what_happens = "Windowsファイアウォールが無効なプロファイルがあり、LANや外部からの侵入を遮断できません。"
                remediation = "すべてのプロファイルでWindowsファイアウォールを有効化してください。"
                patch_example = "netsh advfirewall set allprofiles state on"
            }
            $seq++
        }
    } catch {}

    # 2. 危険な外部開放ポート検査 (読み取り専用 netstat)
    $riskyPorts = @{
        21 = "FTP (平文ファイル転送)"; 23 = "Telnet (平文リモート操作)"; 445 = "SMB (ファイル共有・ランサムウェア経路)"
        1433 = "SQL Server"; 3306 = "MySQL"; 3389 = "RDP (リモートデスクトップ)"; 6379 = "Redis"
    }
    try {
        $netLines = netstat -an 2>$null
        $seenPorts = @{}
        foreach ($line in $netLines) {
            if ($line -match "LISTENING" -and $line -match "(?:0\.0\.0\.0|\[\:\:\]):(\d+)\s") {
                $p = [int]$Matches[1]
                if ($riskyPorts.ContainsKey($p) -and -not $seenPorts.ContainsKey($p)) {
                    $seenPorts[$p] = $true
                    $sev = if ($p -eq 23 -or $p -eq 6379) { "CRITICAL" } else { "HIGH" }
                    $findings += [PSCustomObject]@{
                        id = ("WH-{0:D3}" -f $seq); title = "危険ポートの外部全体開放 (Port $p : $($riskyPorts[$p]))"
                        domain_key = "infra_supply_chain"; role = "ネットワーク・サーバー監査担当"
                        category = "Host Security: Exposed Port $p"; severity = $sev
                        risk_priority_score = 100; file_path = "Windows_Host/Port_$p"; line_number = $p
                        code_snippet = $line.Trim()
                        what_happens = "ポート $p ($($riskyPorts[$p])) が全ネットワーク(0.0.0.0)に開放されており、総当たり攻撃や侵入の標的になります。"
                        remediation = "不要なサービスを停止するか、ファイアウォール・VPNで接続元IPを制限してください。"
                        patch_example = "New-NetFirewallRule -DisplayName 'Block Port $p' -Direction Inbound -LocalPort $p -Protocol TCP -Action Block"
                    }
                    $seq++
                }
            }
        }
    } catch {}

    # 3. 対象フォルダ内のソースコード・設定ファイル検査
    $files = @()
    if (Test-Path $ScanPath) {
        $files = Get-ChildItem -Path $ScanPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.FullName -notmatch "\\(node_modules|\.git|\.next|dist|build|bin|obj|strix_runs)\\" -and
                $_.Extension -in @(".py",".ts",".tsx",".js",".jsx",".json",".yaml",".yml",".cs",".config",".ps1",".bat",".env",".php",".sql") -and
                $_.Name -ne "white_hacker_runner.py" -and $_.Name -ne "Run_Windows_Audit.ps1"
            } | Select-Object -First 300
    }

    foreach ($f in $files) {
        $lines = Get-Content -Path $f.FullName -ErrorAction SilentlyContinue
        if (-not $lines) { continue }
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $ln = [string]$lines[$i]
            if ($ln -match "(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|Password\s*=\s*[^;`"'\s]{4,})" -and $ln -notmatch "EXAMPLE|REDACTED|pattern") {
                $findings += [PSCustomObject]@{
                    id = ("WH-{0:D3}" -f $seq); title = "秘密鍵・パスワードの設定ファイル/コードへの平文埋め込み"
                    domain_key = "secrets_data"; role = "設定・シークレット担当"
                    category = "OWASP A02/A05: Hardcoded Secrets"; severity = "CRITICAL"
                    risk_priority_score = 125; file_path = $f.Name; line_number = ($i + 1)
                    code_snippet = "Detected secret/password pattern [REDACTED]"
                    what_happens = "APIキーやDBパスワードが平文で書き込まれており、情報漏洩や不正侵入の直接原因になります。"
                    remediation = "パスワードやキーを直ちに再発行し、環境変数またはWindows資格情報マネージャーへ移行してください。"
                    patch_example = "# 環境変数から読み込む構成へ変更"
                }
                $seq++
            }
            elseif ($ln -match "execute\(\s*f['`"]\s*(SELECT|INSERT|UPDATE|DELETE)" -or $ln -match "FromSqlRaw\(\s*`\$`"") {
                $findings += [PSCustomObject]@{
                    id = ("WH-{0:D3}" -f $seq); title = "SQLインジェクション（データベース不正命令注入）"
                    domain_key = "input_injection"; role = "入力注入担当"
                    category = "OWASP A03: SQL Injection"; severity = "CRITICAL"
                    risk_priority_score = 125; file_path = $f.Name; line_number = ($i + 1)
                    code_snippet = $ln.Trim()
                    what_happens = "入力文字を直接つないでSQLを実行しているため、全顧客データの抜き出しや改ざんが可能です。"
                    remediation = "プリペアドステートメント（パラメータバインド）を使用してください。"
                    patch_example = "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
                }
                $seq++
            }
            elseif ($ln -match "<compilation\s+[^>]*debug\s*=\s*['`"]true['`"]" -or $ln -match "<customErrors\s+[^>]*mode\s*=\s*['`"]Off['`"]") {
                $findings += [PSCustomObject]@{
                    id = ("WH-{0:D3}" -f $seq); title = "Windows IIS / Web.config デバッグ情報・詳細エラーの外部露出"
                    domain_key = "infra_supply_chain"; role = "Windowsサーバー設定担当"
                    category = "OWASP A05: Security Misconfiguration"; severity = "MEDIUM"
                    risk_priority_score = 36; file_path = $f.Name; line_number = ($i + 1)
                    code_snippet = $ln.Trim()
                    what_happens = "エラー発生時にサーバー内部のパスやプログラム構造が外部利用者の画面に丸見えになります。"
                    remediation = "本番環境では debug='false' および customErrors mode='On' (または RemoteOnly) に設定してください。"
                    patch_example = "<compilation debug=`"false`" /> / <customErrors mode=`"RemoteOnly`" />"
                }
                $seq++
            }
        }
    }

    # スコア計算 (100点満点 + 致命的欠陥ハードキャップ)
    $critCount = ($findings | Where-Object { $_.severity -eq "CRITICAL" }).Count
    $highCount = ($findings | Where-Object { $_.severity -eq "HIGH" }).Count
    $medCount  = ($findings | Where-Object { $_.severity -eq "MEDIUM" }).Count
    $rawScore = [Math]::Max(0, 100 - ($critCount * 15) - ($highCount * 10) - ($medCount * 4))
    $finalScore = $rawScore
    $capReason = "キャップ適用なし"
    if ($critCount -gt 0 -and $finalScore -gt 49) {
        $finalScore = 49
        $capReason = "CRITICAL（致命的弱点）が $critCount 件検出されたため、最高49点（Grade D: 要緊急是正）に上限固定しました。"
    } elseif ($highCount -gt 0 -and $finalScore -gt 69) {
        $finalScore = 69
        $capReason = "HIGH（高リスク弱点）が $highCount 件検出されたため、最高69点（Grade C: 修正必須）に上限固定しました。"
    }

    $grade = if ($finalScore -ge 95) { "S" } elseif ($finalScore -ge 85) { "A" } elseif ($finalScore -ge 70) { "B" } elseif ($finalScore -ge 50) { "C" } elseif ($finalScore -ge 30) { "D" } else { "F" }
    $htmlPath = Join-Path $runDir "report.html"
    $summaryPath = Join-Path $runDir "summary.md"

    $rowsHtml = ""
    foreach ($item in $findings) {
        $rowsHtml += "<div style='background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px;margin-bottom:14px;'>"
        $rowsHtml += "<h3 style='margin:0 0 8px 0;color:#f8fafc;'>[$($item.id)] [$($item.severity)] $($item.title)</h3>"
        $rowsHtml += "<p style='color:#94a3b8;font-size:13px;margin:0 0 8px 0;'>場所: <code>$($item.file_path):$($item.line_number)</code> ｜ 担当: $($item.role)</p>"
        $rowsHtml += "<p><strong>リスク内容:</strong> $($item.what_happens)</p>"
        $rowsHtml += "<p><strong>是正方法:</strong> $($item.remediation)</p>"
        $rowsHtml += "<pre style='background:#020617;padding:10px;border-radius:6px;color:#38bdf8;'><code>$($item.patch_example)</code></pre></div>"
    }
    if (-not $rowsHtml) {
        $rowsHtml = "<div style='background:#064e3b;padding:18px;border-radius:10px;'>✅ 今回の検査範囲では、重大なセキュリティホールは検出されませんでした。</div>"
    }

    $htmlContent = @"
<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>Windows セキュリティ監査レポート ($finalScore/100点)</title></head>
<body style="font-family:sans-serif;background:#0f172a;color:#f8fafc;padding:32px;line-height:1.6;">
<div style="max-width:960px;margin:0 auto;">
  <div style="background:#1e293b;border-left:8px solid #38bdf8;padding:24px;border-radius:12px;margin-bottom:24px;display:flex;justify-content:space-between;align-items:center;">
    <div>
      <h1 style="margin:0 0 8px 0;">🛡️ 包括的セキュリティ監査レポート (Windows Environment)</h1>
      <p style="margin:0;color:#cbd5e1;">検査対象: <code>$ScanPath</code> ｜ 検査ファイル数: $($files.Count) 件 ｜ $capReason</p>
    </div>
    <div style="text-align:center;background:#020617;padding:16px 28px;border-radius:12px;border:2px solid #38bdf8;">
      <div style="font-size:42px;font-weight:800;color:#38bdf8;">$finalScore<span style="font-size:18px;color:#94a3b8;">/100</span></div>
      <div style="font-size:18px;font-weight:700;">Grade $grade</div>
    </div>
  </div>
  <h2>📋 検出されたセキュリティホールと是正計画 ($($findings.Count) 件)</h2>
  $rowsHtml
</div></body></html>
"@
    Set-Content -Path $htmlPath -Value $htmlContent -Encoding UTF8
    Set-Content -Path $summaryPath -Value "# 包括セキュリティ監査レポート`n- 総合得点: **$finalScore / 100点 (Grade $grade)**`n- 検出件数: $($findings.Count) 件`n- HTMLレポート: $htmlPath" -Encoding UTF8

    Write-Host ""
    Write-Host "[OK] Windows監査レポートを生成しました: $htmlPath" -ForegroundColor Green
    Write-Host "  🏆 総合セキュリティ得点: $finalScore / 100 点 (Grade $grade)" -ForegroundColor Cyan
    Start-Process $htmlPath
}

$pyCmd = Find-WorkingPython

if (-not $NonInteractive -and [string]::IsNullOrWhiteSpace($TargetPath)) {
    Write-Host "実行したいメニュー番号を選んで Enter を押してください:" -ForegroundColor White
    Write-Host "  [1] フォルダを選択して包括セキュリティ監査＋Windows環境診断を実行（商談・現地診断用）" -ForegroundColor Green
    Write-Host "  [2] このWindows PC / サーバー全体の設定・Webフォルダ(C:\inetpub\wwwroot等)を診断" -ForegroundColor Yellow
    Write-Host "  [3] 商談プレゼン用「3秒体験デモ（69点 ➔ 修正 ➔ 100点）」を実行" -ForegroundColor Cyan
    Write-Host ""
    $choice = Read-Host "番号を入力 (デフォルト: 1)"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "1" }

    if ($choice -eq "3" -and $pyCmd) {
        & $pyCmd $RunnerPy demo
        exit 0
    } elseif ($choice -eq "2") {
        if (Test-Path "C:\inetpub\wwwroot") {
            $TargetPath = "C:\inetpub\wwwroot"
        } else {
            $TargetPath = $RepoRoot
        }
    } else {
        $TargetPath = Select-TargetFolderDialog
    }
}

if ([string]::IsNullOrWhiteSpace($TargetPath)) {
    $TargetPath = $RepoRoot
}

if ($pyCmd) {
    Write-Host "[INFO] Pythonエンジン ($pyCmd) で 100点満点包括監査＋ホスト環境診断を実行します..." -ForegroundColor Green
    if ($pyCmd -eq "py") {
        & py -3 $RunnerPy scan --target "$TargetPath" --mode $Mode --include-host-audit --open
    } else {
        & $pyCmd $RunnerPy scan --target "$TargetPath" --mode $Mode --include-host-audit --open
    }
} else {
    Invoke-NativePowerShellAudit -ScanPath $TargetPath
}
