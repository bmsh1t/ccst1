# Optional PowerShell helper; credentials come from the process environment.
$script:FOFA_PRIMARY_EMAIL = $env:FOFA_EMAIL
$script:FOFA_PRIMARY_KEY = $env:FOFA_KEY
$script:FOFA_BACKUP_EMAIL = $env:FOFA_EMAIL_BACKUP
$script:FOFA_BACKUP_KEY = $env:FOFA_KEY_BACKUP
$script:FOFA_BACKUP2_EMAIL = $env:FOFA_EMAIL_BACKUP2
$script:FOFA_BACKUP2_KEY = $env:FOFA_KEY_BACKUP2
$script:FOFA_EXHAUSTED = @()

function Invoke-FofaSearch {
  param(
    [Parameter(Mandatory=$true)][string]$Query,
    [int]$Size = 100,
    [string]$Fields = "host,ip,port,title,server"
  )
  $q64 = [Uri]::EscapeDataString([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Query)))
  $encodedFields = [Uri]::EscapeDataString($Fields)
  $all = @("primary","backup","backup2")
  $tryOrder = @($all | Where-Object { $script:FOFA_EXHAUSTED -notcontains $_ }) + @($all | Where-Object { $script:FOFA_EXHAUSTED -contains $_ })
  foreach ($acc in $tryOrder) {
    if ($acc -eq "primary") {
      if (-not $script:FOFA_PRIMARY_KEY) { continue }
      $uri = "https://fofa.info/api/v1/search/all?email=$([Uri]::EscapeDataString([string]$script:FOFA_PRIMARY_EMAIL))&key=$([Uri]::EscapeDataString([string]$script:FOFA_PRIMARY_KEY))&qbase64=$q64&size=$Size&fields=$encodedFields"
    } elseif ($acc -eq "backup") {
      if (-not $script:FOFA_BACKUP_KEY) { continue }
      $uri = "https://fofa.info/api/v1/search/all?email=$([Uri]::EscapeDataString([string]$script:FOFA_BACKUP_EMAIL))&key=$([Uri]::EscapeDataString([string]$script:FOFA_BACKUP_KEY))&qbase64=$q64&size=$Size&fields=$encodedFields"
    } else {
      if (-not $script:FOFA_BACKUP2_KEY) { continue }
      $uri = "https://fofa.info/api/v1/search/all?email=$([Uri]::EscapeDataString([string]$script:FOFA_BACKUP2_EMAIL))&key=$([Uri]::EscapeDataString([string]$script:FOFA_BACKUP2_KEY))&qbase64=$q64&size=$Size&fields=$encodedFields"
    }
    try {
      $r = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 30
      $j = $r.Content | ConvertFrom-Json
      if ($j.error -eq $true) {
        $em = [string]$j.errmsg
        if ($em -match "820041|频繁|上限|F点" -or $r.StatusCode -eq 429) {
          if ($script:FOFA_EXHAUSTED -notcontains $acc) { $script:FOFA_EXHAUSTED += $acc }
          continue
        }
      }
      return [pscustomobject]@{ account=$acc; data=$j; query=$Query }
    } catch {
      $msg = $_.Exception.Message
      if ($msg -match "429|Too Many") {
        if ($script:FOFA_EXHAUSTED -notcontains $acc) { $script:FOFA_EXHAUSTED += $acc }
        continue
      }
      if ($acc -eq "backup2") { throw "FOFA request failed for backup2" }
    }
  }
  throw "FOFA all accounts failed/rate-limited"
}
