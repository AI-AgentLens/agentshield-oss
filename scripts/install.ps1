# AgentShield installer for Windows (#4717).
#
#   irm https://aiagentlens.com/releases/latest/install.ps1 | iex
#
# Per-user, no administrator rights. It downloads the newest release zip for
# this machine, checks its SHA-256 against the release's checksums.txt,
# installs agentshield.exe to %LOCALAPPDATA%\Programs\AgentShield, puts that
# folder on the user PATH, installs the Claude Code hook, and ends by checking
# that AgentShield recognises a known-dangerous command. Logging in to AI Agent
# Lens is the next step it prints, because it waits for a browser.
#
# Windows PowerShell 5.1 compatible and ASCII only: 5.1 reads a script without
# a byte-order mark as the ANSI code page. It never calls `exit`, which under
# `iex` would close the user's window; a failure throws instead.
#
# AGENTSHIELD_RELEASE_BASE overrides the download location (a mirror, or a
# test server); the layout must match: <base>/latest and <base>/<version>/.
# AGENTSHIELD_VERSION installs that release (for example v0.2.2615) instead of
# the newest, so a machine gets a build that has already been checked on
# Windows: each release is a new, unsigned binary to antivirus.

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'  # 5.1's progress bar slows downloads tenfold
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $base = if ($env:AGENTSHIELD_RELEASE_BASE) { $env:AGENTSHIELD_RELEASE_BASE.TrimEnd('/') } else { 'https://aiagentlens.com/releases' }

    function Get-Text([string]$url) {
        # 5.1 returns bytes, not a string, for a non-text content type.
        $content = (Invoke-WebRequest -UseBasicParsing -Uri $url).Content
        if ($content -is [byte[]]) { return [Text.Encoding]::UTF8.GetString($content) }
        return [string]$content
    }

    $machine = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $arch = switch ($machine) {
        'AMD64' { 'amd64' }
        'ARM64' { 'arm64' }
        default { throw "AgentShield has no Windows build for processor architecture '$machine'." }
    }

    if ($env:AGENTSHIELD_VERSION) {
        $version = $env:AGENTSHIELD_VERSION.Trim()
        if ($version -match '^[0-9]') { $version = "v$version" }
        if ($version -notmatch '^v[0-9A-Za-z.-]+$') { throw "AGENTSHIELD_VERSION '$($env:AGENTSHIELD_VERSION)' is not a release version such as v0.2.2615." }
    } else {
        $version = (Get-Text "$base/latest" | ConvertFrom-Json).version
        if ($version -notmatch '^v[0-9A-Za-z.-]+$') { throw "Could not read the latest AgentShield version from $base/latest." }
    }
    $zipName = "agentshield_$($version.Substring(1))_windows_$arch.zip"
    Write-Host "AgentShield $version for windows/$arch"

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("agentshield-install-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $zip = Join-Path $tmp $zipName
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$base/$version/$zipName" -OutFile $zip
        }
        catch {
            throw "Could not download $zipName for $version ($($_.Exception.Message)). Nothing was installed."
        }

        $want = $null
        foreach ($line in (Get-Text "$base/$version/checksums.txt") -split "`r?`n") {
            $fields = $line.Trim() -split '\s+'
            if ($fields.Count -eq 2 -and $fields[1] -eq $zipName) { $want = $fields[0].ToLowerInvariant() }
        }
        $got = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLowerInvariant()
        if (-not $want) { throw "checksums.txt for $version does not list $zipName." }
        if ($got -ne $want) { throw "Checksum mismatch for ${zipName}: expected $want, got $got. Nothing was installed." }
        Write-Host "  downloaded and verified (SHA-256 $($got.Substring(0, 12))...)"

        Expand-Archive -Path $zip -DestinationPath (Join-Path $tmp 'x') -Force
        $dest = Join-Path $env:LOCALAPPDATA 'Programs\AgentShield'
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        $exe = Join-Path $dest 'agentshield.exe'
        Get-ChildItem -Path $dest -Filter 'agentshield.exe.old-*' -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
        if (Test-Path $exe) {
            # Windows will not overwrite a running exe (the heartbeat daemon
            # runs this one), but it will rename it. The old copy is removed
            # by the next install, once nothing runs it.
            Rename-Item -Path $exe -NewName ('agentshield.exe.old-' + [Guid]::NewGuid().ToString('N'))
        }
        Copy-Item -Path (Join-Path $tmp 'x\agentshield.exe') -Destination $exe -Force
        Write-Host "  installed $exe"

        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (-not $userPath) { $userPath = '' }
        if (($userPath -split ';') -notcontains $dest) {
            [Environment]::SetEnvironmentVariable('Path', (($userPath.TrimEnd(';') + ';' + $dest).TrimStart(';')), 'User')
            Write-Host "  added $dest to your PATH (new terminals pick it up)"
        }
        if (($env:Path -split ';') -notcontains $dest) { $env:Path = "$env:Path;$dest" }

        # Native commands: read $LASTEXITCODE rather than let 5.1 turn stderr
        # into a terminating error, and capture output whole (piping a native
        # command into Select-Object -First stops it early).
        $ErrorActionPreference = 'Continue'
        $null = & $exe version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "agentshield.exe would not run (exit $LASTEXITCODE). Windows security (Smart App Control or antivirus) may have blocked it."
        }

        $setup = & $exe setup claude-code 2>&1 | Out-String
        $settings = Join-Path $env:USERPROFILE '.claude\settings.json'
        if (-not ((Test-Path $settings) -and ((Get-Content -Raw -Path $settings) -match 'agentshield'))) {
            Write-Host $setup
            throw "The Claude Code hook was not installed: $settings has no AgentShield entry."
        }
        foreach ($l in $setup -split "`r?`n") {
            if ($l -cmatch '^\s*Mode:') { Write-Host ("  " + $l.Trim()) }
        }
        Write-Host "  Claude Code hook installed in $settings"

        $canary = Join-Path $tmp 'canary.sh'
        [IO.File]::WriteAllText($canary, "rm -rf /`n")
        $verdict = (& $exe check --shell-file $canary --format json 2>$null | Out-String) | ConvertFrom-Json
        if ($verdict.decision -ne 'BLOCK' -and $verdict.original_decision -ne 'BLOCK') {
            throw "Self-test failed: AgentShield decided '$($verdict.decision)' for a known-dangerous command."
        }
        Write-Host "  self-test passed: 'rm -rf /' is recognised as BLOCK ($($verdict.rules[0]))"
        $ErrorActionPreference = 'Stop'

        Write-Host ""
        Write-Host "Next: connect this machine to AI Agent Lens:"
        Write-Host "  agentshield login"
        Write-Host "Restart Claude Code (and Claude Desktop) so they load the hook."
    }
    finally {
        Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
    }
}
