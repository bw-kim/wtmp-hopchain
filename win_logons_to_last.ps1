# 윈도우 로그온 기록을 hopviewer 가 읽는 last 형식(--time-format iso)으로 뽑기
#   관리자 PowerShell 에서:  powershell -ExecutionPolicy Bypass -File .\win_logons_to_last.ps1 -Out B_last.txt
#   보안 로그 4624(로그온) 와 4634/4647(로그오프)을 로그온 ID 로 짝지어 세션 한 줄로 만든다.
#   출력 예:  deploy  type10  10.10.1.10  2026-10-03T09:05:30+09:00 - 2026-10-03T11:20:05+09:00  (02:14)
param(
  [string]$Out = "$env:COMPUTERNAME`_last.txt",
  # 2=콘솔 10=원격데스크톱(RDP) 11=캐시된 자격증명. SSH(OpenSSH 서버)·sftp 로 들어온 것도 보려면 3,8 추가
  [string[]]$LogonTypes = @('2', '10', '11'),   # -File 로 실행하면 "2,10" 이 글자 하나로 오므로 아래에서 쉼표로 나눔
  [string]$Path = ''          # 다른 PC 에서 복사해 온 Security.evtx 를 읽을 때 경로
)
$types = @($LogonTypes -split ',' | Where-Object { $_ -ne '' } | ForEach-Object { [int]$_ })
$filter = @{ Id = 4624, 4634, 4647 }
if ($Path) { $filter.Path = $Path } else { $filter.LogName = 'Security' }
$fmt = 'yyyy-MM-ddTHH:mm:sszzz'
$open = @{}
$lines = New-Object System.Collections.Generic.List[string]
$dur = { param($ts) '({0}{1:00}:{2:00})' -f $(if ($ts.Days) { "$($ts.Days)+" } else { '' }), $ts.Hours, $ts.Minutes }
$row = { param($s, $endText) '{0,-14} type{1,-4} {2,-16} {3} {4}' -f $s.User, $s.Type, $s.Ip, $s.Start.ToString($fmt), $endText }

Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | Sort-Object TimeCreated | ForEach-Object {
  $d = @{}
  foreach ($n in ([xml]$_.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
  $id = $d.TargetLogonId
  if ($_.Id -eq 4624) {
    if ($types -contains [int]$d.LogonType) {
      $ip = if ($d.IpAddress -and $d.IpAddress -ne '-') { $d.IpAddress -replace '^::ffff:', '' } else { 'local' }
      $open[$id] = [pscustomobject]@{ User = $d.TargetUserName; Type = $d.LogonType; Ip = $ip; Start = $_.TimeCreated }
    }
  } elseif ($open.ContainsKey($id)) {
    $s = $open[$id]; $open.Remove($id)
    $lines.Add((& $row $s ('- ' + $_.TimeCreated.ToString($fmt) + '  ' + (& $dur ($_.TimeCreated - $s.Start)))))
  }
}
# 로그오프 기록이 없는 세션 (아직 접속 중이거나 기록이 빠짐)
foreach ($s in $open.Values) { $lines.Add((& $row $s '  still logged in')) }

# last 처럼 최근 것이 위로
$lines | Sort-Object { [datetime]::Parse(($_ -split '\s+')[3]) } -Descending | Set-Content -Path $Out -Encoding UTF8
"세션 $($lines.Count)개 -> $Out"
