# Offline rAthena negative-login lab; PowerShell 5.1+ and Docker Desktop.
# No published ports. Unique throwaway containers; never touches ValkiRO.
param(
 [Parameter(Mandatory=$true)][string]$SqlDirectory,
 [Parameter(Mandatory=$true)][string]$WorkDirectory,
 [int]$ClientVersionHint = 20211103,
 [string]$RathenaImageId = 'sha256:d9f594008680a167e7048c1d48287d2cf9751ef3d4baf40043e707fe43e3fd32',
 [string]$MysqlImageId = 'sha256:a81d043930e51745522bd5c430961cf8286f0a23f0a9a2a6e0108f7ea71b0902',
 [string]$PythonImageId = 'sha256:7984cf56ceaddebe4fefeb75d64000b9f45d8b77b11a09b24524da6cdc3af0c8'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not (Test-Path $SqlDirectory -PathType Container)) { throw 'SQL source directory is missing' }
foreach ($file in @('main.sql','logs.sql')) {
  if (-not (Test-Path (Join-Path $SqlDirectory $file) -PathType Leaf)) {
    throw ('Official SQL source missing ' + $file)
  }
}
foreach ($id in @($RathenaImageId,$MysqlImageId,$PythonImageId)) {
  if ($id -notmatch '^sha256:[0-9a-f]{64}$') { throw 'Require exact Docker sha256 image IDs' }
  $actual = & docker image inspect $id --format '{{.Id}}' 2>$null
  if ($LASTEXITCODE -ne 0 -or $actual -ne $id) { throw 'Pinned image missing from local Docker cache' }
}
if (-not (Test-Path $WorkDirectory -PathType Container)) { throw 'WorkDirectory parent must exist' }
$prefix = [guid]::NewGuid().ToString('N').Substring(0,12)
$db = 'athena-m6-db-' + $prefix
$login = 'athena-m6-login-' + $prefix
$lab = Join-Path (Resolve-Path $WorkDirectory).Path ('m6-' + $prefix)
New-Item -ItemType Directory -Path $lab -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path (Join-Path $lab 'reports'),(Join-Path $lab 'workspace') | Out-Null
$pw = 'atltest_' + [guid]::NewGuid().ToString('N').Substring(0,20)
$dbCreated = $false
$loginCreated = $false
try {
  $suite = @{
    schema_version='1'; suite_id='real-rathena-negative-login'
    tests=@(@{id='unknown-account';kind='rathena-login';host='127.0.0.1';
              port=6900;timeout_ms=3500;client_version=$ClientVersionHint;
              expect='account-rejected'})
  }
  $suite | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 (Join-Path $lab 'suite.json')
  $dbArgs = @('run','--rm','-d','--pull','never','--name',$db,'--network','none',
              '--memory','700m','--cpus','1','--pids-limit','128',
              '-e',"MYSQL_ROOT_PASSWORD=$pw",'-e','MYSQL_DATABASE=ragnarok',
              '-e','MYSQL_USER=ragnarok','-e','MYSQL_PASSWORD=ragnarok',
              $MysqlImageId,'--skip-mysqlx')
  & docker @dbArgs *> (Join-Path $lab 'db-launch.log')
  if ($LASTEXITCODE -ne 0) { throw 'Disposable DB launch failed' }
  $dbCreated = $true
  $ready = $false
  for ($i=0; $i -lt 30; $i++) {
    & docker exec --env "MYSQL_PWD=ragnarok" $db mysqladmin ping -h 127.0.0.1 -uragnarok --silent *> $null
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 2
  }
  if (-not $ready) { throw 'Disposable database not ready' }
  & docker exec $db mkdir -p /tmp/athena-sql *> $null
  if ($LASTEXITCODE -ne 0) { throw 'Cannot create SQL directory in disposable DB' }
  & docker cp ($SqlDirectory + '\.') ($db + ':/tmp/athena-sql') *> (Join-Path $lab 'sql-copy.log')
  if ($LASTEXITCODE -ne 0) { throw 'Unable to copy official SQL into disposable DB' }
  $sqlscript = @'
set -eu
cd /tmp/athena-sql
count=0
for first in main.sql logs.sql; do
  if [ -f "$first" ]; then
    mysql --protocol=tcp -h 127.0.0.1 -uragnarok ragnarok < "$first" > /tmp/athena-out 2>/tmp/athena-err
    count=$((count+1))
  fi
done
for file in *.sql; do
  [ -f "$file" ] || continue
  case "$file" in main.sql|logs.sql) continue ;; esac
  mysql --protocol=tcp -h 127.0.0.1 -uragnarok ragnarok < "$file" > /tmp/athena-out 2>/tmp/athena-err
  count=$((count+1))
done
echo "OFFICIAL_SQL_FILES_IMPORTED=$count"
'@
  $sqlscript | Set-Content -Encoding Ascii (Join-Path $lab 'import.sh')
  & docker cp (Join-Path $lab 'import.sh') ($db + ':/tmp/import.sh') *> $null
  if ($LASTEXITCODE -ne 0) { throw 'SQL importer copy failed' }
  & docker exec --env "MYSQL_PWD=ragnarok" $db sh /tmp/import.sh *> (Join-Path $lab 'sql-import.log')
  if ($LASTEXITCODE -ne 0) { throw 'Disposable SQL import failed' }
  $loginArgs = @('run','--rm','-d','--pull','never','--name',$login,
                 '--network',('container:' + $db),'--read-only',
                 '--tmpfs','/tmp:rw,nosuid,size=64m',
                 '--tmpfs','/rathena/log:rw,nosuid,size=16m',
                 '--pids-limit','96','--memory','700m','--cpus','1',
                 '--entrypoint','/rathena/login-server',$RathenaImageId)
  & docker @loginArgs *> (Join-Path $lab 'login-launch.log')
  if ($LASTEXITCODE -ne 0) { throw 'Disposable login server failed to start' }
  $loginCreated = $true
  $up = $false
  for ($i=0; $i -lt 25; $i++) {
    $logs = & docker logs $login 2>&1
    if (@($logs | Select-String 'login-server is.*ready|listening on the port 6900').Count -gt 0) {
      $up = $true
      break
    }
    Start-Sleep -Seconds 2
  }
  if (-not $up) { throw 'Disposable login-server did not announce readiness' }
  $pyArgs = @('run','--rm','--pull','never',
              '--network',('container:' + $db),'--read-only',
              '--tmpfs','/tmp:rw,nosuid,size=32m',
              '--pids-limit','64','--memory','256m',
              '-v',($repo + ':/source:ro'),'-v',($lab + ':/lab'),
              '-e','PYTHONPATH=/source/src','-w','/source',$PythonImageId,
              'python','-B','-m','athenatestlab','run',
              '--manifest','/lab/suite.json','--workspace','/lab/workspace',
              '--output','/lab/reports/rejection','--allow-login-probe')
  & docker @pyArgs *> (Join-Path $lab 'probe-cli.log')
  $probeCode = $LASTEXITCODE
  $runFile = Join-Path $lab 'reports\rejection\run.json'
  if (-not (Test-Path $runFile)) { throw 'No report from actual login protocol test' }
  $report = Get-Content $runFile -Raw | ConvertFrom-Json
  $result = @($report.tests)[0]
  if ($probeCode -ne 0 -or $report.summary.failed -ne 0 -or
      $report.summary.passed -ne 1 -or
      $result.observation -ne 'account-rejection-confirmed' -or
      $result.reply_opcode -ne '0x083e' -or $result.error_code -ne 0) {
    throw 'Real rAthena protocol negative test did not pass'
  }
  Write-Output 'REAL_RATHENA_NEGATIVE_PACKET=PASS'
  Write-Output 'EXPECTED_OPCODE=0x083e ERROR_CODE=0'
  Write-Output 'FULL_RAGNAROK_LOGIN=NOT_TESTED'
  Write-Output ('REPORT_DIR=' + (Join-Path $lab 'reports\rejection'))
} finally {
  # An --rm container may already have exited. Never let cleanup mask the first failure.
  foreach ($candidate in @($login, $db)) {
    try {
      $stillRunning = @(& docker ps --filter ('name=^/' + $candidate + '$') --format '{{.ID}}')
      if ($stillRunning.Count -gt 0) {
        & docker stop --time 8 $candidate *> $null
        if ($LASTEXITCODE -ne 0) { Write-Output 'LAB_CLEANUP_WARNING=container_stop_failed' }
      }
    } catch {
      Write-Output 'LAB_CLEANUP_WARNING=container_stop_unavailable'
    }
  }
  $pw = ''
  Write-Output 'DISPOSABLE_LAB_TEARDOWN_ATTEMPTED=YES'
}
