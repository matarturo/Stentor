<#
.AUTOR
  Arturo E. Mata - JØKSR (arturo.mata@gmail.com)
.SCRIPT
  Stentor
.VERSION
  1.0.0
.SYNOPSIS
  Triage forense en sitio (solo lectura): usuarios, conexiones de red, indicios de control remoto.
.USAGE
  Ejecutar como Administrador, idealmente desde USB/unidad externa:
  powershell -ExecutionPolicy Bypass -File .\Stentor.ps1 -Dias 60 -Salida C:\Caso01
#>
#Requires -RunAsAdministrator
param(
  [int]$Dias = 60,
  [string]$Salida = "",
  # OFF por defecto: genera consultas DNS PTR DESDE el equipo investigado (deja rastro en la red). Usar solo si se acepta eso.
  [switch]$ResolverInversa
)

# ---------------------------------------------------------------- Cabecera Informativa
Clear-Host
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " [?] STENTOR - Triage Forense en Sitio (Blue Team / DFIR)" -ForegroundColor Green
Write-Host " [+] Versión : 1.0.0" -ForegroundColor Yellow
Write-Host " [+] Autor   : Arturo E. Mata - JØKSR" -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

$sello = Get-Date -Format 'yyyyMMdd_HHmmss'
$base  = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if (-not $Salida) {
  $Salida = Join-Path $base ("Triage_{0}_{1}" -f $env:COMPUTERNAME, $sello)
} elseif ([System.IO.Path]::GetPathRoot($Salida) -eq $Salida) {
  # Raiz de unidad (ej. E:\): crear subcarpeta con equipo y fecha
  $Salida = Join-Path $Salida ("Triage_{0}_{1}" -f $env:COMPUTERNAME, $sello)
} else {
  # C:\Triage_Prueba  ->  C:\Triage_Prueba_20261031_081500  (nunca se mezclan corridas)
  $Salida = "{0}_{1}" -f $Salida.TrimEnd('\','/'), $sello
}
$desde = (Get-Date).AddDays(-$Dias)
New-Item -ItemType Directory -Path $Salida, "$Salida\evtx", "$Salida\live", "$Salida\artefactos" -Force | Out-Null
Start-Transcript -Path "$Salida\transcript.txt" | Out-Null

# ---------------------------------------------------------------- helpers
$LT = @{ '2'='Interactivo (local)'; '3'='Red (SMB/WinRM/etc.)'; '4'='Batch'; '5'='Servicio'; '7'='Desbloqueo';
         '8'='NetworkCleartext'; '9'='NewCredentials (runas /netonly)'; '10'='RemoteInteractive (RDP)'; '11'='CachedInteractive' }

function ConvertTo-EvObj($e) {
  $x = [xml]$e.ToXml()
  $h = [ordered]@{ Hora = $e.TimeCreated; Id = $e.Id; Log = $e.LogName; Resumen = ($e.Message -split "`r?`n")[0] }
  foreach ($d in @($x.Event.EventData.Data)) { if ($d.Name) { $h[$d.Name] = $d.'#text' } }
  if ($x.Event.UserData) { foreach ($n in $x.Event.UserData.FirstChild.ChildNodes) { $h[$n.Name] = $n.InnerText } }
  [pscustomobject]$h
}

function Export-Ev($Nombre, $Filtro, $Max = 0) {
  try {
    $p = @{ FilterHashtable = $Filtro; ErrorAction = 'Stop' }
    if ($Max) { $p.MaxEvents = $Max }
    $r = @(Get-WinEvent @p | ForEach-Object { ConvertTo-EvObj $_ })
  } catch {
    if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { Write-Host "[=] $Nombre : sin eventos en la ventana" }
    else { Write-Host "[-] $Nombre : ERROR/log no disponible: $($_.Exception.Message)" }
    return @()
  }
  $r | Export-Csv "$Salida\$Nombre.csv" -NoTypeInformation -Encoding UTF8
  Write-Host "[+] $Nombre : $($r.Count) eventos"
  return $r
}

function Resumen($titulo, $datos) {
  Add-Content "$Salida\RESUMEN.txt" ("`r`n===== $titulo =====`r`n" + ($datos | Out-String -Width 250)) -Encoding UTF8
}

# ---------------------------------------------------------------- 0. Contexto y cobertura
"Equipo: $env:COMPUTERNAME | Zona horaria: $((Get-TimeZone).Id) | Inicio: $(Get-Date -Format o) | Ventana: $Dias dias" |
  Set-Content "$Salida\RESUMEN.txt" -Encoding UTF8
Get-Date -Format o | Set-Content "$Salida\live\hora_local_equipo.txt"
auditpol /get /category:* | Out-File "$Salida\live\auditpol.txt"

$cobertura = foreach ($n in 'Security','System','Application','Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
                           'Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-DNS-Client/Operational') {
  try {
    $li = Get-WinEvent -ListLog $n -ErrorAction Stop
    $old = $null
    if ($li.RecordCount) { $old = (Get-WinEvent -LogName $n -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue).TimeCreated }
    [pscustomobject]@{ Log=$n; Habilitado=$li.IsEnabled; Registros=$li.RecordCount; EventoMasAntiguo=$old; TamanoMaxMB=[math]::Round($li.MaximumSizeInBytes/1MB,1) }
  } catch { [pscustomobject]@{ Log=$n; Habilitado='No existe'; Registros=0; EventoMasAntiguo=$null; TamanoMaxMB=0 } }
}
$cobertura | Export-Csv "$Salida\00_cobertura_logs.csv" -NoTypeInformation
Resumen 'COBERTURA DE LOGS (cuanto historial hay realmente)' $cobertura

# ---------------------------------------------------------------- 1. Copia de EVTX originales
$logs = 'Security','System','Application','Windows PowerShell',
 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational',
 'Microsoft-Windows-WinRM/Operational','Microsoft-Windows-PowerShell/Operational',
 'Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-DNS-Client/Operational',
 'Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-NetworkProfile/Operational',
 'Microsoft-Windows-WLAN-AutoConfig/Operational','Microsoft-Windows-TaskScheduler/Operational',
 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall','Microsoft-Windows-SMBServer/Security',
 'Microsoft-Windows-WMI-Activity/Operational','Microsoft-Windows-Bits-Client/Operational'
foreach ($l in $logs) {
  $dest = "$Salida\evtx\" + ($l -replace '[/ ]','_') + '.evtx'
  wevtutil epl "$l" "$dest" /ow:true 2>$null
  if ((Test-Path $dest) -and (Get-Item $dest).Length -lt 70000) { } # se conserva igual: puede estar vacio pero existe
}

# ---------------------------------------------------------------- 2. USUARIOS
$f = { param($id,$log='Security') @{ LogName=$log; Id=$id; StartTime=$desde } }
$l4624 = Export-Ev '01_logons_exitosos_4624' (& $f 4624)
Export-Ev '02_logons_fallidos_4625' (& $f 4625) | Out-Null
Export-Ev '03_credenciales_explicitas_4648' (& $f 4648) | Out-Null
Export-Ev '04_logoff_4634_4647' @{ LogName='Security'; Id=4634,4647; StartTime=$desde } | Out-Null
Export-Ev '05_privilegios_especiales_4672' (& $f 4672) | Out-Null
Export-Ev '06_validacion_NTLM_4776' (& $f 4776) | Out-Null

if ($l4624.Count) {
  $res = $l4624 | Where-Object { $_.TargetUserName -notmatch '\$$|^(DWM|UMFD)-|^SYSTEM$|^LOCAL SERVICE$|^NETWORK SERVICE$' } |
    Group-Object TargetDomainName, TargetUserName, LogonType, IpAddress |
    ForEach-Object {
      $p = $_.Group[0]
      [pscustomobject]@{ Veces=$_.Count; Dominio=$p.TargetDomainName; Usuario=$p.TargetUserName; Tipo="$($p.LogonType) - $($LT[[string]$p.LogonType])";
                         IPOrigen=$p.IpAddress; Primera=($_.Group | Measure-Object Hora -Minimum).Minimum; Ultima=($_.Group | Measure-Object Hora -Maximum).Maximum }
    } | Sort-Object Veces -Descending
  $res | Export-Csv "$Salida\01b_RESUMEN_usuarios_logon.csv" -NoTypeInformation
  Resumen 'USUARIOS AUTENTICADOS (excluye cuentas de maquina/servicio)' ($res | Format-Table -AutoSize)
  Resumen 'LOGONS DE RED O RDP DESDE IP EXTERNA AL EQUIPO (tipos 3,10 con IP)' (
    $res | Where-Object { $_.Tipo -match '^(3|10) ' -and $_.IPOrigen -and $_.IPOrigen -notin '-','::1','127.0.0.1' } | Format-Table -AutoSize)
}

# ---------------------------------------------------------------- 3. CONTROL REMOTO: RDP / WinRM / herramientas
Export-Ev '10_RDP_LocalSessionManager' @{ LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=21,22,23,24,25,39,40; StartTime=$desde } | Out-Null
Export-Ev '11_RDP_RemoteConnectionManager_1149' @{ LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149; StartTime=$desde } | Out-Null
Export-Ev '12_RDP_reconexion_4778_4779' @{ LogName='Security'; Id=4778,4779; StartTime=$desde } | Out-Null
Export-Ev '13_WinRM' @{ LogName='Microsoft-Windows-WinRM/Operational'; Id=6,91,168,169; StartTime=$desde } | Out-Null
$ps4104 = @(Export-Ev '14_PowerShell_4104_scriptblock' @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4103,4104; StartTime=$desde } 5000)
# Ruido: modulos internos de Windows (cmdletization) y este mismo script. Un bloque grande llega partido en varios eventos
# con el mismo ScriptBlockId: si un fragmento es ruido, se descartan todos los de ese Id.
$ruidoPS  = '__cmdletization_|Export-ModuleMember|Triage forense en sitio|Triage-EventosWindows'
$idsRuido = @($ps4104 | Where-Object { $_.ScriptBlockText -match $ruidoPS } | ForEach-Object { $_.ScriptBlockId } | Sort-Object -Unique)
$ps4104f  = @($ps4104 | Where-Object { $_.Id -eq 4104 -and $_.ScriptBlockText -notmatch $ruidoPS -and $_.ScriptBlockId -notin $idsRuido })
$ps4104f | Export-Csv "$Salida\14b_PowerShell_4104_FILTRADO.csv" -NoTypeInformation -Encoding UTF8
$sospPS = 'DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|Start-BitsTransfer|FromBase64String|EncodedCommand|-enc\s|Invoke-Expression|\biex\b|Net\.Sockets|TcpClient|Enter-PSSession|New-PSSession|Invoke-Command|Add-MpPreference|Set-MpPreference|mimikatz|AmsiUtils|ntdsutil|vssadmin'
Resumen "POWERSHELL 4104: $($ps4104.Count) eventos brutos -> $($ps4104f.Count) tras quitar ruido (modulos de Windows y este script)" (
  $ps4104f | Select-Object -First 25 Hora, @{n='Texto';e={ $t = ($_.ScriptBlockText -replace '\s+',' '); $t.Substring(0,[math]::Min(160,$t.Length)) }} | Format-Table -AutoSize)
Resumen 'POWERSHELL 4104 CON PATRONES SOSPECHOSOS (descarga, codificado, remoto, tocar Defender)' (
  $ps4104f | Where-Object { $_.ScriptBlockText -match $sospPS } |
  Select-Object Hora, @{n='Texto';e={ $t = ($_.ScriptBlockText -replace '\s+',' '); $t.Substring(0,[math]::Min(200,$t.Length)) }} | Format-Table -AutoSize)

$patron = 'anydesk|teamviewer|rustdesk|screenconnect|connectwise|splashtop|vnc|logmein|ammyy|supremo|radmin|dameware|mesh|atera|quickassist|ngrok|chrome remote|rdpwrap|ultraviewer|zoho assist|netsupport|remoteutilities|aeroadmin|psexec|paexec|winexe|cloudflared|tailscale|zerotier|plink|putty|vpn|wireguard|wintun|openvpn|hamachi|softether|openconnect|forticlient|globalprotect|anyconnect|torbrowser|\btor\.exe|proxifier|frpc|chisel|sshuttle|v2ray|shadowsocks|netbird|twingate'
$vpnAdap = 'vpn|wireguard|wintun|tap-windows|openvpn|zerotier|hamachi|fortinet|anyconnect|globalprotect|nord|proton|mullvad|tailscale'
$svc = Export-Ev '15_servicios_instalados_7045_System' @{ LogName='System'; Id=7045; StartTime=$desde }
$svc4697 = Export-Ev '15b_servicios_instalados_4697' (& $f 4697)
Export-Ev '16_tareas_programadas_4698_4702' @{ LogName='Security'; Id=4698,4699,4700,4701,4702; StartTime=$desde } | Out-Null
Export-Ev '17_cuentas_y_grupos' @{ LogName='Security'; Id=4720,4722,4723,4724,4725,4726,4728,4732,4756; StartTime=$desde } | Out-Null
Export-Ev '18_logs_borrados_1102_104' @{ LogName='Security'; Id=1102; StartTime=$desde } | Out-Null
Export-Ev '18b_logs_borrados_104' @{ LogName='System'; Id=104; StartTime=$desde } | Out-Null
Export-Ev '19_cambios_firewall_4946_4948' @{ LogName='Security'; Id=4946,4947,4948,4950; StartTime=$desde } | Out-Null
Export-Ev '20_Defender_detecciones' @{ LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117,5001,5007,5010; StartTime=$desde } | Out-Null
$p4688 = Export-Ev '21_procesos_creados_4688' (& $f 4688) 20000
if ($p4688.Count) {
  Resumen 'PROCESOS CREADOS QUE COINCIDEN CON HERRAMIENTAS REMOTAS' ($p4688 | Where-Object { $_.NewProcessName -match $patron } |
    Select-Object Hora, SubjectUserName, NewProcessName, CommandLine | Format-Table -AutoSize)
}
$sospSvc = @($svc) + @($svc4697) | Where-Object { ($_.ImagePath + $_.ServiceFileName + $_.ServiceName) -match $patron }
if ($sospSvc) { Resumen 'SERVICIOS INSTALADOS QUE COINCIDEN CON HERRAMIENTAS REMOTAS' ($sospSvc | Format-List) }

# ---------------------------------------------------------------- 4. RED (solo existe si habia auditoria/Sysmon)
$n5156 = Export-Ev '30_conexiones_WFP_5156_salientes' (& $f 5156) 50000
if ($n5156.Count) {
  $pub = $n5156 | Where-Object { $_.Direction -eq '%%14593' -and $_.DestAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|ff0|224\.|239\.)' } |
    Group-Object Application, DestAddress, DestPort |
    ForEach-Object { $p=$_.Group[0]; [pscustomobject]@{ Veces=$_.Count; Aplicacion=$p.Application; Destino=$p.DestAddress; Puerto=$p.DestPort; Proto=$p.Protocol } } |
    Sort-Object Veces -Descending
  $pub | Export-Csv "$Salida\30b_RESUMEN_destinos_publicos.csv" -NoTypeInformation
  Resumen 'DESTINOS PUBLICOS (5156)' ($pub | Select-Object -First 60 | Format-Table -AutoSize)
}
Export-Ev '31_Sysmon_proceso_red_dns' @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=1,3,22; StartTime=$desde } 50000 | Out-Null
$dns = Export-Ev '32_DNS_cliente_3008' @{ LogName='Microsoft-Windows-DNS-Client/Operational'; Id=3008; StartTime=$desde } 50000
if ($dns.Count) { Resumen 'DOMINIOS CONSULTADOS (DNS Client 3008)' ($dns | Group-Object QueryName | Sort-Object Count -Descending | Select-Object -First 80 Count, Name | Format-Table -AutoSize) }
Export-Ev '33_perfiles_de_red' @{ LogName='Microsoft-Windows-NetworkProfile/Operational'; Id=10000,10001,4004; StartTime=$desde } | Out-Null
Export-Ev '34_WiFi' @{ LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'; Id=8001,8002,8003,11000; StartTime=$desde } | Out-Null

# ---------------------------------------------------------------- 5. ESTADO EN VIVO (volatil: se pierde al apagar)
$L = "$Salida\live"
Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
  $pr = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  [pscustomobject]@{ Local="$($_.LocalAddress):$($_.LocalPort)"; Remoto="$($_.RemoteAddress):$($_.RemotePort)"; Estado=$_.State; Inicio=$(if ($_.CreationTime) { $_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss') }); PID=$_.OwningProcess; Proceso=$pr.ProcessName; Ruta=$pr.Path }
} | Export-Csv "$L\tcp_conexiones.csv" -NoTypeInformation
Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Export-Csv "$L\udp_endpoints.csv" -NoTypeInformation
Get-DnsClientCache | Export-Csv "$L\dns_cache.csv" -NoTypeInformation
Get-Process | Select-Object Id, ProcessName, Path, StartTime, @{n='Hash';e={ if ($_.Path) { (Get-FileHash $_.Path -ErrorAction SilentlyContinue).Hash } }} |
  Export-Csv "$L\procesos.csv" -NoTypeInformation
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine | Export-Csv "$L\procesos_cmdline.csv" -NoTypeInformation
Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName | Export-Csv "$L\servicios.csv" -NoTypeInformation
Get-ScheduledTask | Select-Object TaskPath, TaskName, State, @{n='Accion';e={ ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ' }} |
  Export-Csv "$L\tareas_programadas.csv" -NoTypeInformation
if (Get-Command qwinsta.exe -ErrorAction SilentlyContinue) { qwinsta 2>&1 | Out-File "$L\sesiones_qwinsta.txt" }
else { "qwinsta no disponible (Windows Home?). Sesiones via CIM:" | Out-File "$L\sesiones_qwinsta.txt" }
Get-CimInstance Win32_LogonSession | Select-Object LogonId, LogonType, StartTime, AuthenticationPackage |
  Export-Csv "$L\sesiones_logon_cim.csv" -NoTypeInformation
Get-CimInstance Win32_LoggedOnUser | Select-Object @{n='Usuario';e={$_.Antecedent.Name}}, @{n='Dominio';e={$_.Antecedent.Domain}}, @{n='LogonId';e={$_.Dependent.LogonId}} |
  Export-Csv "$L\sesiones_usuarios_cim.csv" -NoTypeInformation
ipconfig /all | Out-File "$L\ipconfig.txt"; arp -a | Out-File "$L\arp.txt"; route print | Out-File "$L\route.txt"
netsh winhttp show proxy | Out-File "$L\proxy_winhttp.txt"
Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Out-File "$L\hosts.txt"
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue |
  Select-Object DisplayName, Profile, @{n='Programa';e={($_ | Get-NetFirewallApplicationFilter).Program}}, @{n='Puerto';e={($_ | Get-NetFirewallPortFilter).LocalPort}} |
  Export-Csv "$L\firewall_reglas_entrada_permitidas.csv" -NoTypeInformation
Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Out-File "$L\administradores_locales.txt"
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | Export-Csv "$L\usuarios_locales.csv" -NoTypeInformation
$rdpOn = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections
"RDP habilitado: $(if ($rdpOn -eq 0) {'SI'} else {'NO'})" | Out-File "$L\rdp_estado.txt"
Get-ItemProperty 'Registry::HKEY_USERS\*\Software\Microsoft\Terminal Server Client\Servers\*' -ErrorAction SilentlyContinue |
  Out-File "$L\rdp_salientes_mstsc_historial.txt"
$sw = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
$sw | Export-Csv "$L\software_instalado.csv" -NoTypeInformation
Resumen 'SOFTWARE DE ACCESO REMOTO / VPN / TUNELES INSTALADO' ($sw | Where-Object { $_.DisplayName -match $patron } | Format-Table -AutoSize)
Resumen 'PROCESOS DE ACCESO REMOTO / VPN / TUNELES EN EJECUCION AHORA' (
  Get-CimInstance Win32_Process | Where-Object { $_.Name -match $patron -or $_.CommandLine -match $patron } | Select-Object ProcessId, Name, CommandLine | Format-Table -AutoSize)

# ---------------------------------------------------------------- 5b. Servicios VPN/remotos, adaptadores, SITIOS (conexiones publicas) y puertos en escucha
$svcMatch = Get-CimInstance Win32_Service | Where-Object { ($_.Name + ' ' + $_.DisplayName + ' ' + $_.PathName) -match $patron } |
  Select-Object Name, DisplayName, State, StartMode, PathName
$svcMatch | Export-Csv "$L\servicios_remotos_vpn.csv" -NoTypeInformation
Resumen 'SERVICIOS DE ACCESO REMOTO / VPN / TUNELES' ($svcMatch | Format-Table -AutoSize)

$ad = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Status, MacAddress
$ad | Export-Csv "$L\adaptadores_red.csv" -NoTypeInformation
Resumen 'ADAPTADORES DE RED VIRTUALES / VPN' ($ad | Where-Object { $_.InterfaceDescription -match $vpnAdap } | Format-Table -AutoSize)

# Nombre de cada IP segun la cache DNS local (no genera trafico). Con -ResolverInversa tambien consulta PTR.
$privado = '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|::1?$|fe80|ff0|224\.|239\.)'
$mapaDns = @{}
Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Type -in 1,28 -and $_.Data } |
  ForEach-Object { if (-not $mapaDns.ContainsKey($_.Data)) { $mapaDns[$_.Data] = $_.Entry } }

$pubCon = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
  Where-Object { $_.RemoteAddress -notmatch $privado } |
  ForEach-Object {
    $pr  = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    $nom  = $mapaDns[$_.RemoteAddress]
    $ini  = if ($_.CreationTime) { $_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
    $pini = try { $pr.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } catch { '' }
    if (-not $nom -and $ResolverInversa) {
      try { $nom = (Resolve-DnsName $_.RemoteAddress -Type PTR -QuickTimeout -ErrorAction Stop | Select-Object -First 1).NameHost } catch { }
    }
    [pscustomobject]@{ Inicio=$ini; Proceso=$pr.ProcessName; PID=$_.OwningProcess; Remoto="$($_.RemoteAddress):$($_.RemotePort)"; IP=$_.RemoteAddress
                       Puerto=$_.RemotePort; NombreDNS=$nom; ProcesoInicio=$pini; Local="$($_.LocalAddress):$($_.LocalPort)"; Ruta=$pr.Path }
  } | Sort-Object Proceso, Inicio)
$pubCon | Export-Csv "$L\conexiones_publicas.csv" -NoTypeInformation -Encoding UTF8
("Captura (hora local del equipo): {0}`r`nInicio = hora en que Windows creo la conexion (solo conexiones activas al momento de la captura)`r`n" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) +
  ($pubCon | Format-Table Inicio, Proceso, Remoto, PID, NombreDNS -AutoSize | Out-String -Width 250) | Set-Content "$L\conexiones_publicas.txt" -Encoding UTF8
$pubCon | Where-Object { $_.NombreDNS } | ForEach-Object { $_.NombreDNS } | Sort-Object -Unique | Set-Content "$L\sitios_conectados_ahora.txt" -Encoding UTF8
Get-DnsClientCache -ErrorAction SilentlyContinue | ForEach-Object { $_.Entry } | Sort-Object -Unique | Set-Content "$L\dominios_cache_dns.txt" -Encoding UTF8

Resumen "CONEXIONES ESTABLECIDAS A IPs PUBLICAS (captura: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Inicio = hora de creacion de la conexion)" ($pubCon | Format-Table Inicio, Proceso, Remoto, PID, NombreDNS -AutoSize)
Resumen 'CONEXIONES PUBLICAS AGRUPADAS POR PROCESO' ($pubCon | Group-Object Proceso | Sort-Object Count -Descending |
  Select-Object @{n='Conexiones';e={$_.Count}}, @{n='Proceso';e={$_.Name}}, @{n='IPsDistintas';e={ @($_.Group | ForEach-Object { $_.IP } | Sort-Object -Unique).Count }})
Resumen 'CONEXIONES PUBLICAS DE PROCESOS EN RUTAS INUSUALES (Users/Temp/ProgramData/Downloads/Public)' (
  $pubCon | Where-Object { $_.Ruta -match '\\(Users|Temp|ProgramData|Downloads|Public)\\' } | Format-Table Inicio, Proceso, Remoto, NombreDNS, Ruta -AutoSize)
Resumen 'DOMINIOS EN CACHE DNS (sitios resueltos recientemente; lista completa en live\dominios_cache_dns.txt)' (
  Get-DnsClientCache -ErrorAction SilentlyContinue | ForEach-Object { $_.Entry } | Sort-Object -Unique | Select-Object -First 80)

$escucha = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1$)' } |
  ForEach-Object {
    $pr = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [pscustomobject]@{ Proceso=$pr.ProcessName; PID=$_.OwningProcess; Local="$($_.LocalAddress):$($_.LocalPort)"; Puerto=$_.LocalPort; Ruta=$pr.Path }
  } | Sort-Object Puerto)
$escucha | Export-Csv "$L\puertos_escucha.csv" -NoTypeInformation
$puertosRem = @(22,23,3389,5938,5985,5986,7070) + (5900..5905) + (21115..21119)
Resumen 'PUERTOS EN ESCUCHA ACCESIBLES DESDE FUERA DE ESTE EQUIPO' ($escucha | Format-Table Proceso, Local, PID -AutoSize)
Resumen 'PUERTOS TIPICOS DE ACCESO REMOTO EN ESCUCHA (SSH/Telnet/RDP/VNC/TeamViewer/WinRM/AnyDesk/RustDesk)' (
  $escucha | Where-Object { $_.Puerto -in $puertosRem } | Format-Table Proceso, Local, PID -AutoSize)

# ---------------------------------------------------------------- 5c. ANTIVIRUS / EDR (reportes y eventos)
$AVd = "$Salida\antivirus"
New-Item $AVd -ItemType Directory -Force | Out-Null
$avPat = 'kaspersky|symantec|norton|mcafee|trend micro|sophos|eset|bitdefender|avast|\bavg\b|malwarebytes|crowdstrike|sentinel|cylance|carbon black|cortex|cisco secure|fortiedr|withsecure|f-secure|panda|defender'
$avs = @()
try {
  $avs = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
    $h = '{0:X6}' -f [int]$_.productState
    [pscustomobject]@{ Producto=$_.displayName; Activo=(@('10','11') -contains $h.Substring(2,2)); FirmasAlDia=($h.Substring(4,2) -eq '00'); Ejecutable=$_.pathToSignedProductExe; Actualizado=$_.timestamp }
  })
} catch { "SecurityCenter2 no disponible (Windows Server?)" | Set-Content "$AVd\nota_securitycenter.txt" }
$avs | Export-Csv "$AVd\antivirus_registrados.csv" -NoTypeInformation
Resumen 'ANTIVIRUS REGISTRADOS EN WINDOWS (Security Center)' ($avs | Format-Table -AutoSize)

# Microsoft Defender (aunque este pasivo): estado, detecciones y EXCLUSIONES (los atacantes suelen agregarlas)
if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
  try { Get-MpComputerStatus -ErrorAction Stop | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureLastUpdated |
          Export-Csv "$AVd\defender_estado.csv" -NoTypeInformation } catch { }
  try { Get-MpThreatDetection -ErrorAction Stop | Export-Csv "$AVd\defender_detecciones.csv" -NoTypeInformation } catch { }
  try { Get-MpThreat -ErrorAction Stop | Export-Csv "$AVd\defender_amenazas.csv" -NoTypeInformation } catch { }
  try {
    $mp = Get-MpPreference -ErrorAction Stop
    [pscustomobject]@{ Rutas=($mp.ExclusionPath -join '; '); Procesos=($mp.ExclusionProcess -join '; '); Extensiones=($mp.ExclusionExtension -join '; ') } |
      Export-Csv "$AVd\defender_exclusiones.csv" -NoTypeInformation
  } catch { }
  Copy-Item "$env:ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log" $AVd -ErrorAction SilentlyContinue
}

# Registros de eventos propios del antivirus/EDR (exportados completos en .evtx)
Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
  Where-Object { $_.RecordCount -gt 0 -and $_.LogName -match $avPat -and $_.LogName -notmatch 'Windows Defender' } |
  ForEach-Object { wevtutil epl $_.LogName ("$AVd\" + ($_.LogName -replace '[/ ]','_') + '.evtx') /ow:true 2>$null }

# Eventos de proveedores de AV dentro de Application y System
$evAV = @()
try {
  $evAV = @(Get-WinEvent -FilterHashtable @{ LogName='Application','System'; StartTime=$desde } -ErrorAction Stop |
    Where-Object { $_.ProviderName -match $avPat } | ForEach-Object { ConvertTo-EvObj $_ })
} catch { }
$evAV | Export-Csv "$AVd\eventos_AV_Application_System.csv" -NoTypeInformation -Encoding UTF8
Resumen "EVENTOS DE ANTIVIRUS EN Application/System: $($evAV.Count) en la ventana (ver antivirus\eventos_AV_Application_System.csv)" (
  $evAV | Group-Object Log, Id | Sort-Object Count -Descending | Select-Object -First 15 Count, Name)

# Logs/reportes en archivo dentro de ProgramData (solo texto, recientes). NO se copia nada de cuarentena a proposito.
$avDirs = @(Get-ChildItem $env:ProgramData -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $avPat })
Resumen 'CARPETAS DE ANTIVIRUS/EDR EN PROGRAMDATA' ($avDirs | Select-Object Name, LastWriteTime | Format-Table -AutoSize)
foreach ($d in $avDirs) {
  $dst = "$AVd\archivos\$($d.Name)"
  Get-ChildItem $d.FullName -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -match '^\.(log|txt|xml|csv|html|json|trace)$' -and $_.LastWriteTime -ge $desde -and $_.Length -lt 50MB } |
    Select-Object -First 200 | ForEach-Object {
      New-Item $dst -ItemType Directory -Force | Out-Null
      $nm = $_.FullName.Substring($d.FullName.Length) -replace '[\\: ]','_'
      if ($nm.Length -gt 120) { $nm = $nm.Substring($nm.Length - 120) }
      try { Copy-Item $_.FullName "$dst\$nm" -ErrorAction Stop } catch { "No copiado: $($_.FullName)" | Add-Content "$AVd\copias_fallidas.txt" }
    }
}

# ---------------------------------------------------------------- 5d. CONECTIVIDAD Y EXPOSICION: EVIDENCIA HISTORICA (fecha y hora)
$HIST = "$Salida\historico"
New-Item $HIST -ItemType Directory -Force | Out-Null
$fmt = 'yyyy-MM-dd HH:mm:ss'
$linea = New-Object System.Collections.ArrayList
if (-not $privado) { $privado = '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|::1?$|fe80|ff0|224\.|239\.)' }
$pfBase = if ($patron) { $patron } else { 'anydesk|teamviewer|rustdesk|putty|vpn' }

function Add-Linea($hora, $fuente, $evento, $detalle) {
  if ($hora -is [datetime]) { [void]$linea.Add([pscustomobject]@{ Hora = $hora; Fuente = $fuente; Evento = $evento; Detalle = $detalle }) }
}
function Get-EvObjs($filtro, $max = 0) {
  try {
    $p = @{ FilterHashtable = $filtro; ErrorAction = 'Stop' }
    if ($max) { $p.MaxEvents = $max }
    @(Get-WinEvent @p | ForEach-Object { ConvertTo-EvObj $_ })
  } catch { @() }
}
function Get-Prop($o, $rx) {
  $x = $o.PSObject.Properties | Where-Object { $_.Name -match $rx -and $_.Value } | Select-Object -First 1
  if ($x) { $x.Value }
}
function ConvertFrom-SystemTime($b) {
  if ($null -eq $b -or $b.Length -lt 16) { return $null }
  try {
    New-Object DateTime -ArgumentList @([int][BitConverter]::ToUInt16($b, 0), [int][BitConverter]::ToUInt16($b, 2), [int][BitConverter]::ToUInt16($b, 6),
                                        [int][BitConverter]::ToUInt16($b, 8), [int][BitConverter]::ToUInt16($b, 10), [int][BitConverter]::ToUInt16($b, 12))
  } catch { $null }
}
function Get-IpClase([string]$ip) {
  if     ($ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)') { 'Privada (NAT probable)' }
  elseif ($ip -match '^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.')     { 'CGNAT 100.64/10 (NAT del proveedor)' }
  elseif ($ip -match '^169\.254\.')                                   { 'APIPA (sin DHCP)' }
  elseif ($ip -match '^127\.' -or $ip -eq '::1')                      { 'Loopback' }
  elseif ($ip -match '^fe80')                                         { 'IPv6 enlace local' }
  elseif ($ip -match '^f[cd]')                                        { 'IPv6 ULA (privada)' }
  elseif ($ip -match ':')                                             { 'IPv6 GLOBAL (posible exposicion directa)' }
  else                                                                { 'PUBLICA directa (posible exposicion directa)' }
}
function Test-PuertoEnLista($puerto, $lista) {
  if (-not $lista) { return $false }
  foreach ($t in ($lista -split ',')) {
    $t = $t.Trim()
    if ($t -eq [string]$puerto) { return $true }
    if ($t -match '^(\d+)-(\d+)$' -and [int]$puerto -ge [int]$Matches[1] -and [int]$puerto -le [int]$Matches[2]) { return $true }
  }
  return $false
}

# ---- (A) Redes a las que se conecto el equipo: PRIMERA y ULTIMA conexion (registro; va mucho mas atras que los logs)
$redes = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles' -ErrorAction SilentlyContinue | ForEach-Object {
  $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
  [pscustomobject]@{
    Red             = $p.ProfileName
    Tipo            = $(switch ([int]$p.NameType) { 6 { 'Cableada' } 23 { 'VPN' } 71 { 'Inalambrica' } 243 { 'Banda ancha movil' } default { "Otro($($p.NameType))" } })
    Categoria       = $(switch ([int]$p.Category) { 0 { 'Publica' } 1 { 'Privada' } 2 { 'Dominio' } default { "Otra($($p.Category))" } })
    PrimeraConexion = ConvertFrom-SystemTime $p.DateCreated
    UltimaConexion  = ConvertFrom-SystemTime $p.DateLastConnected
  }
})
$redesTxt = $redes | Sort-Object PrimeraConexion | Select-Object Red, Tipo, Categoria,
  @{ n = 'PrimeraConexion'; e = { if ($_.PrimeraConexion) { $_.PrimeraConexion.ToString($fmt) } } },
  @{ n = 'UltimaConexion';  e = { if ($_.UltimaConexion)  { $_.UltimaConexion.ToString($fmt) } } }
$redesTxt | Export-Csv "$HIST\redes_conocidas.csv" -NoTypeInformation -Encoding UTF8
foreach ($r in $redes) {
  Add-Linea $r.PrimeraConexion 'Registro NetworkList' 'PRIMERA conexion a esta red' "$($r.Red) [$($r.Tipo), $($r.Categoria)]"
  Add-Linea $r.UltimaConexion  'Registro NetworkList' 'Ultima conexion a esta red'  "$($r.Red) [$($r.Tipo), $($r.Categoria)]"
}

# ---- (B) Eventos de conectividad que Windows registra por defecto
foreach ($e in (Get-EvObjs @{ LogName = 'Microsoft-Windows-NetworkProfile/Operational'; Id = 10000, 10001; StartTime = $desde })) {
  $cat = switch ("$($e.Category)") { '0' { 'Publica' } '1' { 'Privada' } '2' { 'Dominio' } default { $e.Category } }
  $d = (@($e.Name, $e.Description, $cat) | Where-Object { $_ }) -join ' | '
  Add-Linea $e.Hora 'NetworkProfile' $(if ($e.Id -eq 10000) { 'Red conectada' } else { 'Red desconectada' }) $(if ($d) { $d } else { $e.Resumen })
}
foreach ($e in (Get-EvObjs @{ LogName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'; Id = 8001, 8003; StartTime = $desde })) {
  $d = (@($e.SSID, $e.ProfileName) | Where-Object { $_ } | Select-Object -Unique) -join ' / '
  Add-Linea $e.Hora 'WLAN-AutoConfig' $(if ($e.Id -eq 8001) { 'Conectado a Wi-Fi' } else { 'Desconectado de Wi-Fi' }) $(if ($d) { $d } else { $e.Resumen })
}
# BITS (descargas en segundo plano; incluye la URL) y Windows Update (descargas = hubo internet ese dia)
$bits = Get-EvObjs @{ LogName = 'Microsoft-Windows-Bits-Client/Operational'; Id = 59, 60, 61; StartTime = $desde } 5000
$bits | Export-Csv "$HIST\bits_transferencias.csv" -NoTypeInformation -Encoding UTF8
foreach ($e in ($bits | Where-Object { $_.Id -eq 59 } | Select-Object -First 300)) {
  $u = Get-Prop $e 'url'
  Add-Linea $e.Hora 'BITS (descargas)' 'Transferencia iniciada' $(if ($u) { $u } else { $e.Resumen })
}
$wu = Get-EvObjs @{ LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'; Id = 44, 31, 19, 20; StartTime = $desde } 2000
$wu | Export-Csv "$HIST\windows_update_eventos.csv" -NoTypeInformation -Encoding UTF8
foreach ($e in ($wu | Where-Object { $_.Id -in 44, 31 } | Select-Object -First 300)) {
  Add-Linea $e.Hora 'Windows Update' $(if ($e.Id -eq 44) { 'Inicio de descarga de actualizacion' } else { 'Fallo de descarga de actualizacion' }) $e.Resumen
}
# Cambios en reglas del firewall (log operativo, activo por defecto): quien abrio la puerta y cuando
$fw = Get-EvObjs @{ LogName = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; Id = 2003, 2004, 2005, 2006, 2033; StartTime = $desde } 3000
$fw | Export-Csv "$HIST\firewall_cambios_reglas.csv" -NoTypeInformation -Encoding UTF8
foreach ($e in $fw) {
  $txt = switch ($e.Id) { 2004 { 'Regla AGREGADA' } 2005 { 'Regla MODIFICADA' } 2006 { 'Regla ELIMINADA' } 2033 { 'TODAS las reglas eliminadas' } default { 'Cambio de configuracion de perfil' } }
  $dir = switch ("$($e.Direction)") { '1' { 'entrada' } '2' { 'salida' } default { '' } }
  $d = (@($e.RuleName, $e.ApplicationPath, $(if ($dir) { "direccion=$dir" }), $(if ($e.LocalPorts) { "puertos=$($e.LocalPorts)" }),
          $(if ($e.Action) { "accion=$($e.Action)" }), $(if ($e.ModifyingApplication) { "por=$($e.ModifyingApplication)" })) | Where-Object { $_ }) -join ' | '
  Add-Linea $e.Hora 'Firewall (reglas)' $txt $(if ($d) { $d } else { $e.Resumen })
}

# ---- (C) Accesos de red/RDP y fallidos desde IP PUBLICA (exposicion real, con primera y ultima vez)
$lg = Get-EvObjs @{ LogName = 'Security'; Id = 4624, 4625; StartTime = $desde } 30000
$remPub = @($lg | Where-Object { ($_.Id -eq 4624 -and $_.LogonType -in '3', '10') -or $_.Id -eq 4625 } |
                  Where-Object { $_.IpAddress -and $_.IpAddress -ne '-' -and $_.IpAddress -notmatch $privado })
$resExt = @($remPub | Group-Object { '{0}|{1}|{2}' -f $_.IpAddress, $_.Id, $_.LogonType } | ForEach-Object {
  $a = @($_.Group | Sort-Object Hora)
  [pscustomobject]@{ IP = $a[0].IpAddress; Evento = $(if ($a[0].Id -eq 4624) { 'Logon EXITOSO' } else { 'Logon FALLIDO' }); Tipo = $a[0].LogonType
                     Usuarios = (@($a | ForEach-Object { $_.TargetUserName } | Sort-Object -Unique) -join ', '); Veces = $a.Count; Primero = $a[0].Hora; Ultimo = $a[-1].Hora }
} | Sort-Object Primero)
$resExt | Select-Object IP, Evento, Tipo, Usuarios, Veces, @{ n = 'Primero'; e = { $_.Primero.ToString($fmt) } }, @{ n = 'Ultimo'; e = { $_.Ultimo.ToString($fmt) } } |
  Export-Csv "$HIST\accesos_desde_ip_publica.csv" -NoTypeInformation -Encoding UTF8
foreach ($x in $resExt) {
  Add-Linea $x.Primero 'Security 4624/4625' "$($x.Evento) desde IP publica (PRIMERO)" "IP $($x.IP), tipo $($x.Tipo), usuarios: $($x.Usuarios), veces: $($x.Veces)"
  if ($x.Veces -gt 1) { Add-Linea $x.Ultimo 'Security 4624/4625' "$($x.Evento) desde IP publica (ULTIMO)" "IP $($x.IP), tipo $($x.Tipo)" }
}

# ---- (D) Programas de red/acceso remoto: primera y ultima ejecucion aproximadas (Prefetch)
$pfPat = "$pfBase|chrome|msedge|firefox|brave|opera|iexplore|curl|wget|bitsadmin|certutil|ssh|mstsc|powershell"
$pf = @(Get-ChildItem "$env:SystemRoot\Prefetch\*.pf" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $pfPat } | Sort-Object Name)
$pf | Select-Object @{ n = 'Programa'; e = { $_.Name -replace '-[0-9A-F]{8}\.pf$', '' } },
  @{ n = 'PrimeraEjecucionAprox'; e = { $_.CreationTime.ToString($fmt) } }, @{ n = 'UltimaEjecucion'; e = { $_.LastWriteTime.ToString($fmt) } } |
  Export-Csv "$HIST\programas_red_prefetch.csv" -NoTypeInformation -Encoding UTF8
foreach ($f in $pf) {
  $prog = $f.Name -replace '-[0-9A-F]{8}\.pf$', ''
  Add-Linea $f.CreationTime  'Prefetch' 'Primera ejecucion aprox.' $prog
  Add-Linea $f.LastWriteTime 'Prefetch' 'Ultima ejecucion'         $prog
}

# ---- (E) Exposicion directa: direcciones IP del equipo y puertos accesibles
$ips = @(Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.AddressState -eq 'Preferred' } | ForEach-Object {
  [pscustomobject]@{ Interfaz = $_.InterfaceAlias; IP = $_.IPAddress; Clase = (Get-IpClase $_.IPAddress); Origen = $_.PrefixOrigin }
})
$ips | Export-Csv "$HIST\direcciones_ip_exposicion.csv" -NoTypeInformation -Encoding UTF8
$perfiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity)
$perfiles | Export-Csv "$HIST\perfiles_de_red_activos.csv" -NoTypeInformation -Encoding UTF8
$reglasIn = @(Import-Csv "$L\firewall_reglas_entrada_permitidas.csv" -ErrorAction SilentlyContinue)
$expo = @($escucha | Where-Object { $_.Local -match '^(0\.0\.0\.0|::):\d+$' } | ForEach-Object {
  $s = $_
  $reg = $reglasIn | Where-Object { ($_.Programa -and $s.Ruta -and $_.Programa -ieq $s.Ruta) -or (Test-PuertoEnLista $s.Puerto $_.Puerto) } | Select-Object -First 1
  [pscustomobject]@{ Proceso = $s.Proceso; Local = $s.Local; PID = $s.PID
                     ReglaDeEntrada = $(if ($reg) { $reg.DisplayName } else { '(ninguna especifica)' }); PerfilesRegla = $(if ($reg) { $reg.Profile }) }
})
$expo | Export-Csv "$HIST\puertos_accesibles_y_regla.csv" -NoTypeInformation -Encoding UTF8

# ---- (F) Linea de tiempo consolidada y resumen
$ord = @($linea | Sort-Object Hora)
$ord | Select-Object @{ n = 'Hora'; e = { $_.Hora.ToString($fmt) } }, Fuente, Evento, Detalle |
  Export-Csv "$HIST\LINEA_TIEMPO_conectividad.csv" -NoTypeInformation -Encoding UTF8

$porFuente = @($ord | Group-Object Fuente | ForEach-Object {
  [pscustomobject]@{ Fuente = $_.Name; Registros = $_.Count
                     MasAntiguo = ($_.Group | Measure-Object Hora -Minimum).Minimum.ToString($fmt)
                     MasReciente = ($_.Group | Measure-Object Hora -Maximum).Maximum.ToString($fmt) }
} | Sort-Object MasAntiguo)
$textoAviso = if ($ord.Count) {
  "Evidencia de conexion MAS ANTIGUA disponible: $($ord[0].Hora.ToString($fmt))  [$($ord[0].Fuente): $($ord[0].Evento)]`r`n" +
  "Evidencia MAS RECIENTE: $($ord[-1].Hora.ToString($fmt))  [$($ord[-1].Fuente): $($ord[-1].Evento)]`r`n" +
  "Zona horaria del equipo: $([System.TimeZoneInfo]::Local.Id). Ventana de eventos: ultimos $Dias dias (el registro de redes NetworkList no tiene esa ventana).`r`n" +
  "AVISO: 'mas antigua' es la evidencia mas antigua DISPONIBLE, no necesariamente la primera conexion real. Conectarse a una RED no prueba acceso a INTERNET.`r`n" +
  "Para trafico por aplicacion con fechas (unos 30-60 dias) analizar artefactos\SRUM\SRUDB.dat con SrumECmd (ver README)."
} else { 'No se encontro evidencia historica de conectividad en las fuentes consultadas.' }
Resumen 'CONECTIVIDAD A INTERNET Y EXPOSICION: DESDE CUANDO (evidencia historica)' $textoAviso
Resumen 'EVIDENCIA POR FUENTE: LO MAS ANTIGUO Y LO MAS RECIENTE' ($porFuente | Format-Table -AutoSize)
Resumen 'REDES A LAS QUE SE CONECTO EL EQUIPO (primera y ultima conexion)' ($redesTxt | Format-Table -AutoSize)
Resumen 'DIRECCIONES IP DEL EQUIPO Y CLASE (IP publica o IPv6 global = exposicion directa posible)' ($ips | Format-Table -AutoSize)
Resumen 'PERFILES DE RED ACTIVOS (Categoria Publica/Privada y conectividad detectada por Windows)' ($perfiles | Format-Table -AutoSize)
Resumen 'ACCESOS DE RED/RDP Y LOGONS FALLIDOS DESDE IP PUBLICA (primera y ultima vez)' (
  $resExt | Select-Object IP, Evento, Tipo, Usuarios, Veces, @{ n = 'Primero'; e = { $_.Primero.ToString($fmt) } }, @{ n = 'Ultimo'; e = { $_.Ultimo.ToString($fmt) } } | Format-Table -AutoSize)
Resumen 'PUERTOS ACCESIBLES DESDE LA RED (todas las interfaces) Y REGLA DE ENTRADA QUE LOS PERMITE (heuristica)' ($expo | Select-Object -First 40 | Format-Table -AutoSize)
Resumen 'CAMBIOS DE REGLAS DEL FIREWALL CON FECHA (agregadas, modificadas, eliminadas)' (
  $ord | Where-Object { $_.Fuente -eq 'Firewall (reglas)' } | Select-Object -First 40 @{ n = 'Hora'; e = { $_.Hora.ToString($fmt) } }, Evento, Detalle | Format-Table -AutoSize -Wrap)
Resumen 'HITOS DE LA LINEA DE TIEMPO (sin BITS/Windows Update/Prefetch; completa en historico\LINEA_TIEMPO_conectividad.csv)' (
  $ord | Where-Object { $_.Fuente -notin 'BITS (descargas)', 'Windows Update', 'Prefetch' } | Select-Object -First 60 @{ n = 'Hora'; e = { $_.Hora.ToString($fmt) } }, Fuente, Evento, Detalle | Format-Table -AutoSize -Wrap)


# ---------------------------------------------------------------- 6. ARTEFACTOS FUERA DE EVENT LOG
$A = "$Salida\artefactos"
# SRUM: uso de red por aplicacion, ~30-60 dias (clave para "hubo trafico a internet y quien lo genero")
New-Item "$A\SRUM" -ItemType Directory -Force | Out-Null
esentutl.exe /y "$env:SystemRoot\System32\sru\SRUDB.dat" /vss /d "$A\SRUM\SRUDB.dat" 2>&1 | Out-File "$A\SRUM\esentutl_log.txt"
reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM" "$A\SRUM\SRUM_registry.reg" /y 2>$null | Out-Null
# Historial de navegadores (copiar, NO abrir en el equipo; analizar despues con DB Browser for SQLite / Hindsight)
foreach ($u in Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue) {
  $rutas = @(
    "$($u.FullName)\AppData\Local\Google\Chrome\User Data\*\History",
    "$($u.FullName)\AppData\Local\Microsoft\Edge\User Data\*\History",
    "$($u.FullName)\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite")
  foreach ($r in $rutas) {
    Get-ChildItem $r -ErrorAction SilentlyContinue | ForEach-Object {
      $d = "$A\Navegadores\$($u.Name)\" + ($_.FullName -replace '[:\\ ]','_')
      New-Item (Split-Path $d) -ItemType Directory -Force | Out-Null
      try { Copy-Item $_.FullName $d -ErrorAction Stop } catch { "No se pudo copiar (bloqueado?): $($_.FullName)" | Add-Content "$A\copias_fallidas.txt" }
    }
  }
}
# Logs propios de herramientas de acceso remoto
$remotos = @{
  AnyDesk    = @("$env:ProgramData\AnyDesk\*.trace","$env:ProgramData\AnyDesk\*.txt","C:\Users\*\AppData\Roaming\AnyDesk\*.trace","C:\Users\*\AppData\Roaming\AnyDesk\*.txt")
  TeamViewer = @("C:\Program Files*\TeamViewer\*.log","C:\Program Files*\TeamViewer\*.txt","C:\Users\*\AppData\Roaming\TeamViewer\*.log","C:\Users\*\AppData\Roaming\TeamViewer\*.txt")
  RustDesk   = @("C:\Users\*\AppData\Roaming\RustDesk\log\*","$env:windir\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\log\*")
  ScreenConnect = @("C:\Program Files*\ScreenConnect*\*.log","C:\ProgramData\ScreenConnect*\*.log")
  QuickAssist= @("C:\Users\*\AppData\Local\Packages\MicrosoftCorporationII.QuickAssist*\LocalState\*")
}
foreach ($k in $remotos.Keys) {
  foreach ($p in $remotos[$k]) {
    Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
      $d = "$A\HerramientasRemotas\$k"; New-Item $d -ItemType Directory -Force | Out-Null
      try { Copy-Item $_.FullName ("$d\" + ($_.FullName -replace '[:\\ ]','_')) -ErrorAction Stop } catch {}
    }
  }
}
# Evidencia de ejecucion
Get-ChildItem "$env:SystemRoot\Prefetch\*.pf" -ErrorAction SilentlyContinue | Select-Object Name, CreationTime, LastWriteTime |
  Sort-Object LastWriteTime -Descending | Export-Csv "$A\prefetch_lista.csv" -NoTypeInformation
if (Test-Path "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log") { Copy-Item "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" $A -ErrorAction SilentlyContinue }
reg save HKLM\SYSTEM "$A\SYSTEM.hiv" /y 2>$null | Out-Null
reg save HKLM\SOFTWARE "$A\SOFTWARE.hiv" /y 2>$null | Out-Null   # ShimCache / BAM / instalaciones
Copy-Item "$env:SystemRoot\appcompat\Programs\Amcache.hve" "$A\Amcache.hve" -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- 7. Manifiesto con hashes (cadena de custodia)
Write-Host "`n[OK] Recoleccion terminada. Calculando hashes..."
Stop-Transcript | Out-Null
Get-ChildItem $Salida -Recurse -File | Where-Object { $_.Name -ne 'MANIFIESTO_SHA256.csv' } |
  Get-FileHash -Algorithm SHA256 -ErrorAction SilentlyContinue | Select-Object Hash, Path | Export-Csv "$Salida\MANIFIESTO_SHA256.csv" -NoTypeInformation

# Mensaje final destacado y pausa obligatoria para evitar el cierre abrupto del .exe
Write-Host "`n=================================================================" -ForegroundColor Green
Write-Host "[+] PROCESO DE TRIAJE FINALIZADO CON EXITO." -ForegroundColor Green
Write-Host "[+] Resultados guardados en la ruta:" -ForegroundColor Yellow
Write-Host "    $Salida" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "`nPuede revisar el archivo RESUMEN.txt en esa carpeta."
Write-Host "Presione cualquier tecla para salir..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
