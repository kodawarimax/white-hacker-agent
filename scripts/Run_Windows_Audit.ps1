param(
    [string]$TargetPath = "",
    [string]$Mode = "standard",
    [switch]$NonInteractive,
    [switch]$ForceNative,
    [switch]$NoOpen,
    [switch]$IncludeHost
)

$ErrorActionPreference = "Stop"
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
        } catch {
            Write-Verbose "Python runtime check skipped for $cmd"
        }
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
    } catch {
        Write-Verbose "Folder dialog unavailable; falling back to repository root"
    }
    return $RepoRoot
}

function Invoke-NativePowerShellAudit {
    param([string]$ScanPath)

    Write-Host "[INFO] Python未導入のWindows環境のため、Windows標準PowerShellネイティブ監査エンジンで実行します..." -ForegroundColor Yellow
    $runId = "run_" + (Get-Date -Format "yyyyMMdd_HHmmss_fffffff")
    $runDir = Join-Path $OutputDir $runId
    $findingsDir = Join-Path $runDir "findings"
    New-Item -ItemType Directory -Force -Path $findingsDir | Out-Null

    $findings = @()
    $seq = 1
    $scope = @{ selected_files = 0; scanned_files = 0; candidate_files = 0; symlinks = 0; read_errors = 0; oversize_files = 0; enumeration_errors = 0; file_limit_reached = $false }
    $hostChecks = @{ requested = [bool]$doHost; firewall = "not_requested"; ports = "not_requested" }

    # 1. Windows ファイアウォール検査 (読み取り専用)
    try {
        if (-not $doHost) { throw "host audit not consented" }
        $fwOut = (netsh advfirewall show allprofiles 2>$null) -join "`n"
        if ($LASTEXITCODE -ne 0 -or $fwOut -notmatch "State\s+(ON|OFF)|状態\s+(オン|オフ)") { throw "unreadable firewall status" }
        $hostChecks.firewall = "completed"
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
    } catch {
        if ($doHost) { $hostChecks.firewall = "failed" }
        Write-Verbose "Firewall check failed or was not requested; see host_audit"
    }

    # 2. 危険な外部開放ポート検査 (読み取り専用 netstat)
    $riskyPorts = @{
        21 = "FTP (平文ファイル転送)"; 23 = "Telnet (平文リモート操作)"; 445 = "SMB (ファイル共有・ランサムウェア経路)"
        1433 = "SQL Server"; 3306 = "MySQL"; 3389 = "RDP (リモートデスクトップ)"; 6379 = "Redis"
    }
    try {
        if (-not $doHost) { throw "host audit not consented" }
        $netLines = netstat -an 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $netLines) { throw "unreadable ports" }
        $hostChecks.ports = "completed"
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
    } catch {
        if ($doHost) { $hostChecks.ports = "failed" }
        Write-Verbose "Netstat check failed or was not requested; see host_audit"
    }

    # Enumerate one directory at a time: do not traverse junctions/reparse points.
    function Get-AuditFiles {
        param([string]$PathToInspect)
        try { $entry = Get-Item -LiteralPath $PathToInspect -ErrorAction Stop }
        catch { $scope.enumeration_errors++; return }
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { $scope.symlinks++; return }
        if (-not $entry.PSIsContainer) {
            if ($entry.Name -in @("white_hacker_runner.py", "Run_Windows_Audit.ps1")) { return }
            if ($entry.Extension -in @(".py",".ts",".tsx",".js",".jsx",".json",".yaml",".yml",".cs",".config",".ps1",".bat",".env",".php",".sql")) {
                $scope.candidate_files++
                if ($scope.selected_files -lt 300) { $scope.selected_files++; $entry }
                else { $scope.file_limit_reached = $true }
            }
            return
        }
        try { $children = @(Get-ChildItem -LiteralPath $PathToInspect -Force -ErrorAction Stop | Sort-Object Name) }
        catch { $scope.enumeration_errors++; return }
        foreach ($child in $children) {
            if ($child.PSIsContainer -and $child.Name -in @("node_modules", ".git", ".next", "dist", "build", "bin", "obj", "strix_runs")) { continue }
            Get-AuditFiles -PathToInspect $child.FullName
        }
    }

    # 3. 対象フォルダ内のソースコード・設定ファイル検査
    $files = @()
    $files = @(Get-AuditFiles -PathToInspect $ScanPath)

    foreach ($f in $files) {
        # 1行ファイルでも必ず配列として扱う（文字列のまま添字参照すると1文字目になり見逃す）
        if ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) { $scope.symlinks++; continue }
        if ($f.Length -gt 2000000) { $scope.oversize_files++; continue }
        try { $lines = @(Get-Content -LiteralPath $f.FullName -Encoding UTF8 -ErrorAction Stop); $scope.scanned_files++ }
        catch { $scope.read_errors++; continue }
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

    # The fallback is a smaller candidate-only engine. It does not implement
    # the Python six-domain rubric; do not present a comparable numerical score.
    $status = if ($scope.scanned_files -eq 0 -and $scope.enumeration_errors -eq 0 -and $scope.symlinks -eq 0 -and $scope.oversize_files -eq 0 -and $scope.read_errors -eq 0) { "unsupported" } else { "partial" }
    $finalScore = "N/A"
    $grade = "N/A"
    $capReason = "状態: $status / PowerShell候補検出のみ。点数は算出不可。公開可否は判定しません。"
    foreach ($item in $findings) {
        $item.code_snippet = "[SOURCE REDACTED]"
        $item | Add-Member -NotePropertyName verification_status -NotePropertyValue "PATTERN_MATCH_UNVERIFIED" -Force
    }
    $htmlPath = Join-Path $runDir "report.html"
    $summaryPath = Join-Path $runDir "summary.md"

    $rowsHtml = ""
    foreach ($item in $findings) {
        # Encode all dynamic text before inserting it into HTML.
        $item = $item.PSObject.Copy()
        foreach ($prop in @("id", "severity", "title", "file_path", "role", "what_happens", "remediation", "patch_example")) {
            $item.$prop = [System.Net.WebUtility]::HtmlEncode([string]$item.$prop)
        }
        $rowsHtml += "<div style='background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px;margin-bottom:14px;'>"
        $rowsHtml += "<h3 style='margin:0 0 8px 0;color:#f8fafc;'>[$($item.id)] [$($item.severity)] $($item.title)</h3><p>PATTERN_MATCH_UNVERIFIED / 要手動確認</p>"
        $rowsHtml += "<p style='color:#94a3b8;font-size:13px;margin:0 0 8px 0;'>場所: <code>$($item.file_path):$($item.line_number)</code> ｜ 担当: $($item.role)</p>"
        $rowsHtml += "<p><strong>リスク内容（専門用語なし解説）:</strong> $($item.what_happens)</p>"
        $rowsHtml += "<p style='background:#1e1b4b;border-left:4px solid #818cf8;padding:10px;border-radius:6px;color:#e0e7ff;'><strong>💼 なぜ経営に関わるか・想定される損失:</strong> パスワードやデータの漏洩・ランサムウェア感染により、①外部専門調査（フォレンジック）費用や不正利用課金、②個人情報保護法上の報告・通知対応、③取引先からの契約停止・営業停止損失につながる経営リスクです。</p>"
        $rowsHtml += "<p><strong>是正方法:</strong> $($item.remediation)</p>"
        $rowsHtml += "<pre style='background:#020617;padding:10px;border-radius:6px;color:#38bdf8;'><code>$($item.patch_example)</code></pre></div>"
    }
    if (-not $rowsHtml) {
        $rowsHtml = "<div style='background:#064e3b;padding:18px;border-radius:10px;'>✅ 今回の検査範囲では、重大なセキュリティホールは検出されませんでした。</div>"
    }

    $safeScanPath = [System.Net.WebUtility]::HtmlEncode($ScanPath)
    $safeScope = [System.Net.WebUtility]::HtmlEncode(($scope | ConvertTo-Json -Compress))
    $htmlContent = @"
<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>Windows セキュリティ監査レポート ($finalScore/100点)</title></head>
<body style="font-family:sans-serif;background:#0f172a;color:#f8fafc;padding:32px;line-height:1.6;">
<div style="max-width:960px;margin:0 auto;">
  <div style="background:#1e293b;border-left:8px solid #38bdf8;padding:24px;border-radius:12px;margin-bottom:24px;display:flex;justify-content:space-between;align-items:center;">
    <div>
      <h1 style="margin:0 0 8px 0;">🛡️ 簡易セキュリティ監査レポート (Windows PowerShell簡易版)</h1><p style="color:#fbbf24;margin:0 0 8px 0;">⚠️ 静的パターン検査の参考値です。一致なし＝安全ではなく、一致項目も手動確認が必要です。Python版とは検査範囲・点数が一致しません（Python版を推奨）。</p>
      <p style="margin:0;color:#cbd5e1;">検査対象: <code>$safeScanPath</code> ｜ 検査済みファイル数: $($scope.scanned_files) 件 ｜ $capReason</p><pre>$safeScope</pre><p>ホスト検査は読み取りコマンドの候補検出のみ。到達可能性・認可・HTTP応答・DB権限は未検証です。</p>
    </div>
    <div style="text-align:center;background:#020617;padding:16px 28px;border-radius:12px;border:2px solid #38bdf8;">
      <div style="font-size:42px;font-weight:800;color:#38bdf8;">$finalScore<span style="font-size:18px;color:#94a3b8;">/100</span></div>
      <div style="font-size:18px;font-weight:700;">Grade $grade</div>
    </div>
  </div>
  <div style="background:#1e1b4b;border:1px solid #818cf8;padding:18px;border-radius:12px;margin-bottom:24px;">
    <h2 style="margin:0 0 8px 0;font-size:18px;color:#a5b4fc;">💼 経営者・非IT部門向け解説：なぜ情報漏洩リスクが経営に関わり、どんな損失につながるのか？</h2>
    <p style="margin:0;font-size:14px;color:#e0e7ff;">セキュリティの弱点は放置すると、<strong>①API不正利用課金やランサムウェア感染による営業停止・調査費用（数百万円〜）、②個人情報保護法上の行政報告・顧客通知義務、③取引先からの契約解除・信用失墜</strong>に直結します。</p>
  </div>
  <h2>📋 検出されたセキュリティホールと是正計画 ($($findings.Count) 件)</h2>
  $rowsHtml
</div></body></html>
"@
    Set-Content -Path $htmlPath -Value $htmlContent -Encoding UTF8
    Set-Content -Path $summaryPath -Value "# 包括セキュリティ監査レポート`n- 総合得点: **$finalScore / 100点 (Grade $grade)**`n- 検出件数: $($findings.Count) 件`n- 経営影響: 情報漏洩やランサムウェア感染による調査費用・法的報告義務・取引停止リスクを防ぐため、早期是正を推奨します。`n- HTMLレポート: $htmlPath" -Encoding UTF8
    Add-Content -Path $summaryPath -Value "`n- 状態: $status / 採点不可 / 安全性・公開可否は判定しません。`n- 検査範囲: $($scope | ConvertTo-Json -Compress)`n- 検証状態: PATTERN_MATCH_UNVERIFIED。動的認可・HTTP・DB権限は未検証。" -Encoding UTF8
    @{ status = $status; overall_score = $null; overall_grade = "N/A"; target = $ScanPath; files_scanned = $scope.scanned_files; scan_scope = $scope; host_audit = $hostChecks; limitations = @("limited_native_patterns", "dynamic_checks_not_run", "no_comparable_numeric_score") } | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $runDir "run.json") -Encoding UTF8
    ConvertTo-Json -InputObject @($findings) -Depth 8 | Set-Content (Join-Path $runDir "vulnerabilities.json") -Encoding UTF8
    @{ scorecard = @{ raw_score = $null; final_score = $null; grade = "N/A"; audit_coverage_percent = $null; verdict = "NOT_EVALUATED"; domain_scores = @() } } | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $runDir "audit_scorecard.json") -Encoding UTF8
    "# 追加検査のご案内`n状態: $status。点数は算出不可。Python版での静的点検と、対象に応じた動的検証が必要です。公開可否は判定しません。" | Set-Content (Join-Path $runDir "maintenance_proposal.md") -Encoding UTF8

    Write-Host ""
    Write-Host "[OK] Windows監査レポートを生成しました: $htmlPath" -ForegroundColor Green
    Write-Host "  🏆 総合セキュリティ得点(参考値): $finalScore / 100 点 (Grade $grade) / 検査ファイル数: $($files.Count) / パターン一致: $($findings.Count) 件" -ForegroundColor Cyan
    if (-not $NoOpen) { Start-Process $htmlPath }
}

$pyCmd = if ($ForceNative) { $null } else { Find-WorkingPython }
$doHost = $IncludeHost.IsPresent

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

if ($TargetPath -match '^[\\/]{2}|^[A-Za-z][A-Za-z0-9+.-]*://') {
    Write-Host "URL and network shares are unsupported. Select a local folder." -ForegroundColor Red
    exit 2
}

if (-not $NonInteractive -and -not $doHost) {
    Write-Host ""
    Write-Host "このPC/サーバー自体の設定(Firewall・外部開放ポート)も診断しますか？" -ForegroundColor Yellow
    Write-Host "※ 端末の管理者から書面(または電磁的記録)での事前同意がある場合のみ yes を入力してください。" -ForegroundColor Gray
    $ans = Read-Host "yes / no (デフォルト: no)"
    if ($ans -eq "yes") { $doHost = $true }
}

if ($pyCmd) {
    Write-Host "[INFO] Pythonエンジン ($pyCmd) で静的パターン監査を実行します..." -ForegroundColor Green
    $scanArgs = @("scan", "--target", "$TargetPath", "--mode", $Mode)
    if ($doHost) { $scanArgs += "--include-host-audit" }
    if (-not $NoOpen) { $scanArgs += "--open" }
    if ($pyCmd -eq "py") { & py -3 $RunnerPy @scanArgs } else { & $pyCmd $RunnerPy @scanArgs }
    exit $LASTEXITCODE
} else {
    Invoke-NativePowerShellAudit -ScanPath $TargetPath
    exit 3
}
