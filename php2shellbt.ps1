<#
.SYNOPSIS
  php2shellbt.ps1 - Exposure checker for CVE-2026-109618 / CVE-2026-109619.
  / Comprobador de exposicion a CVE-2026-109618 / CVE-2026-109619.

.DESCRIPTION
  English:
  PowerShell version of the passive check from php2shellbt.py.

  SECURITY VALIDATION: this script does NOT perform any attack against the
  target. It only sends read-only GET requests and reads the X-Powered-By
  header to determine the remote PHP version and compare it with the patch
  table (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).

  It sends no multipart bodies, does not inject session identifiers, does
  not crash the PHP engine and does not exhaust the remote server's memory.
  The active checks of the original Python script (crash-probe with bodies
  up to 20 MiB, session.upload_progress probes, handler-mismatch with
  serialized objects and the session injection + LFI chain) were
  deliberately excluded because they can affect the target software or
  verify an RCE. Here only the version is validated.

  Espanol:
  Version PowerShell de la comprobacion pasiva de php2shellbt.py.

  VALIDACION DE SEGURIDAD: este script NO realiza ningun ataque contra el
  objetivo. Solo emite peticiones GET de solo lectura y lee la cabecera
  X-Powered-By para determinar la version remota de PHP y compararla con la
  tabla de versiones parcheadas (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).

  No envia cuerpos multipart, no inyecta identificadores de sesion, no
  provoca fallos del motor PHP y no agota memoria del servidor remoto.
  Las comprobaciones activas del script Python original (crash-probe con
  cuerpos de hasta 20 MiB, sondas de session.upload_progress,
  handler-mismatch con objetos serializados y la cadena de inyeccion de
  sesion + LFI) se han excluido deliberadamente porque pueden afectar al
  software objetivo o verificar un RCE. Aqui solo se valida la version.

  Patch table per branch (identical to the original script):
    8.2.x -> 8.2.35   |   8.3.x -> 8.3.36
    8.4.x -> 8.4.27   |   8.5.x -> 8.5.12

.PARAMETER Target
  Single domain or URL to validate (skips the menu).
  / Dominio o URL unica que validar (omite el menu).

.PARAMETER TargetsFile
  .txt file with one domain/URL per line (skips the menu). Empty lines and
  lines starting with # are ignored.
  / Archivo .txt con un dominio/URL por linea (omite el menu). Las lineas
  vacias y las que empiezan por # se ignoran.

.PARAMETER Language
  UI language: 'en' (English, default) or 'es' (Espanol).
  / Idioma de la interfaz: 'en' (ingles, por defecto) o 'es' (espanol).

.PARAMETER TimeoutSec
  Timeout per request in seconds (default 10).
  / Tiempo de espera por peticion en segundos (por defecto 10).

.EXAMPLE
  .\php2shellbt.ps1
  Opens the interactive menu (English by default).
  / Abre el menu interactivo (ingles por defecto).

.EXAMPLE
  .\php2shellbt.ps1 -Target https://example.com

.EXAMPLE
  .\php2shellbt.ps1 -TargetsFile .\targets.txt

.EXAMPLE
  .\php2shellbt.ps1 -Language es -Target https://example.com

.NOTES
  Exit code: 1 if any vulnerable version is confirmed, 0 otherwise
  (usable in automation or CI/CD).
  / Codigo de salida: 1 si se confirma alguna version vulnerable, 0 en
  cualquier otro caso (utilizable en automatizacion o CI/CD).
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Target,

    [Parameter(Position = 1)]
    [string]$TargetsFile,

    [Parameter()]
    [ValidateSet('en', 'es')]
    [string]$Language = 'en',

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$TimeoutSec = 10
)

$Script:ProgressBackup = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'

# ── Idioma / Language ─────────────────────────────────────────────────────────

$Script:Lang = $Language
$Script:LanguageNames = @{ en = 'English'; es = 'Espanol' }

$Script:Strings = @{
    en = @{
        BannerPassive    = '  Passive mode: only reads the remote PHP version (X-Powered-By).'
        BannerNoAttack   = '  Sends no payloads and causes no failures on the server.'
        BannerTarget     = '  Target : {0}'
        MenuOpt1         = '  1) Validate a single domain'
        MenuOpt2         = '  2) Validate from a .txt file (one domain/URL per line, in this directory)'
        MenuOpt3         = '  3) Language / Idioma: {0}'
        MenuOpt4         = '  4) Exit'
        MenuPrompt       = 'Select an option'
        MenuInvalid      = 'Invalid option: {0}'
        LanguageSwitched = 'Language set to {0}.'
        MenuExit         = 'Exiting.'
        DomainPrompt     = 'Domain or URL (e.g. example.com or https://example.com)'
        EmptyDomain      = 'No domain entered.'
        FilePrompt       = 'File name (Enter = targets.txt)'
        Checking         = 'Checking {0} ...'
        TargetHeader     = 'TARGET {0}/{1}: {2}'
        HttpsRetry       = 'No response over HTTPS; retrying with {0}'
        ConnFailed       = 'Connection failed: {0}'
        NoXpb            = 'X-Powered-By header not present or does not expose the PHP version (HTTP {0}).'
        NoXpb2           = 'The site may not use PHP or the header is hidden - result inconclusive.'
        VersionDetected  = 'PHP version detected: {0}'
        FixedMsg         = 'PHP {0} is a patched release (>= {1}). Not affected.'
        VulnMsg          = 'VULNERABLE - PHP {0} is in the affected range for CVE-2026-109618 / CVE-2026-109619.'
        VulnPatchedIn    = '  Patched release for its branch: {0}'
        Vuln109618       = '  CVE-2026-109618: session.upload_progress use-after-free / OOM.'
        Vuln109619       = '  CVE-2026-109619: var_destroy use-after-free via unserialize().'
        EolMsg           = 'VULNERABLE - PHP {0} is inside the affected range (5.4.0 - 8.5.11) and its branch is end-of-life (EOL): no patch will ever be released for it.'
        EolFix           = '  Only possible definitive remediation: upgrade to a supported branch (8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+ or later).'
        MitTitle         = '  Temporary mitigations (NOT definitive; PHP core devs state the only real fix is patching):'
        MitIni           = '    - php.ini: session.upload_progress.enabled = Off and session.use_strict_mode = 1'
        MitWaf           = '    - Block multipart POSTs with PHP code in filename fields (WAF / mod_rewrite / nginx rules)'
        MitAccess        = '    - Restrict internet access to PHP systems that cannot be updated immediately'
        BpTitle          = '  Backport sources for EOL branches (upgrade when possible):'
        BpVendor         = '    - Distribution/LTS vendor packages (Debian LTS, Ubuntu Pro): usually the safest option'
        BpSury           = '    - Sury packages, PHP 5.6-8.5 (Debian/Ubuntu): https://packages.sury.org/'
        BpRemi           = '    - Remi Repo, PHP 5.6-8.5 (RHEL/Fedora): https://rpms.remirepo.net/'
        BpUpstream       = '    - Official php-src minimal source backports (7.4/8.0/8.1, compile yourself): https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619'
        BpCommunity      = '    - Community source backports 5.4-7.3 (unofficial, review before use): https://github.com/vperetti/php-cve-2026-109618-109619-backports'
        BpDisclaimer     = '  Third-party packages are unofficial: verify origin and signatures before applying.'
        BpRescanNote     = '  Note: a backported PHP keeps reporting the old version in X-Powered-By, so this checker will keep flagging it; verify the patch with your package manager.'
        NewerMsg         = 'PHP {0} is newer than the affected branches (last affected: 8.5.x < 8.5.12).'
        UnknownMsg       = 'PHP branch {0} is not in the known patch table - cannot determine.'
        SummaryTitle     = '==================== SUMMARY ===================='
        TagVulnerable    = 'VULNERABLE'
        TagFixed         = 'NOT AFFECTED'
        TagEol           = 'VULNERABLE (EOL)'
        TagInconclusive  = 'INCONCLUSIVE'
        TagUnknown       = 'UNKNOWN'
        TagError         = 'ERROR'
        AlertMsg         = 'ALERT: {0} target(s) with a VULNERABLE PHP version. Upgrade PHP immediately.'
        PatchesMsg       = 'Patches: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or later of each branch).'
        OfficialPatch    = '  Official release announcement: {0}'
        OfficialTag      = '  Official source tag: {0}'
        OfficialCveA     = '  CVE-2026-109618 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2026-109618'
        OfficialCveB     = '  CVE-2026-109619 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2026-109619'
        OfficialAdvisory = '  PHP security advisories: https://github.com/php/php-src/security/advisories'
        OfficialSupported = '  PHP supported versions: https://www.php.net/supported-versions.php'
        OfficialIndex    = 'Official PHP releases: https://www.php.net/releases/'
        NoVulnMsg        = 'No vulnerable PHP version confirmed via X-Powered-By header.'
        FileNotFound     = 'File not found: {0}'
        FileEmpty        = 'File {0} is empty or contains only comments.'
        TargetsLoaded    = 'Loaded {0} target(s) from {1}'
        BothParams       = 'Specify only one of -Target or -TargetsFile, not both.'
    }
    es = @{
        BannerPassive    = '  Modo pasivo: solo lee la version remota de PHP (X-Powered-By).'
        BannerNoAttack   = '  No envia payloads ni provoca fallos en el servidor.'
        BannerTarget     = '  Objetivo : {0}'
        MenuOpt1         = '  1) Validar un solo dominio'
        MenuOpt2         = '  2) Validar desde un archivo .txt (un dominio/URL por linea, en este directorio)'
        MenuOpt3         = '  3) Language / Idioma: {0}'
        MenuOpt4         = '  4) Salir'
        MenuPrompt       = 'Selecciona una opcion'
        MenuInvalid      = 'Opcion no valida: {0}'
        LanguageSwitched = 'Idioma cambiado a {0}.'
        MenuExit         = 'Saliendo.'
        DomainPrompt     = 'Dominio o URL (ej. example.com o https://example.com)'
        EmptyDomain      = 'No se ha introducido ningun dominio.'
        FilePrompt       = 'Nombre del archivo (Intro = targets.txt)'
        Checking         = 'Comprobando {0} ...'
        TargetHeader     = 'OBJETIVO {0}/{1}: {2}'
        HttpsRetry       = 'Sin respuesta por HTTPS; reintentando con {0}'
        ConnFailed       = 'Fallo de conexion: {0}'
        NoXpb            = 'La cabecera X-Powered-By no esta presente o no expone la version de PHP (HTTP {0}).'
        NoXpb2           = 'El sitio puede no usar PHP o la cabecera esta oculta - resultado inconcluyente.'
        VersionDetected  = 'Version de PHP detectada: {0}'
        FixedMsg         = 'PHP {0} es una version parcheada (>= {1}). No afectada.'
        VulnMsg          = 'VULNERABLE - PHP {0} esta en el rango afectado por CVE-2026-109618 / CVE-2026-109619.'
        VulnPatchedIn    = '  Version parcheada de su rama: {0}'
        Vuln109618       = '  CVE-2026-109618: use-after-free / OOM de session.upload_progress.'
        Vuln109619       = '  CVE-2026-109619: use-after-free de var_destroy via unserialize().'
        EolMsg           = 'VULNERABLE - PHP {0} esta dentro del rango afectado (5.4.0 - 8.5.11) y su rama esta al final de su vida util (EOL): no recibira ningun parche nunca.'
        EolFix           = '  Unica remediacion definitiva posible: actualizar a una rama con soporte (8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+ o superior).'
        MitTitle         = '  Mitigaciones temporales (NO definitivas; los desarrolladores del nucleo de PHP indican que la unica solucion real es parchear):'
        MitIni           = '    - php.ini: session.upload_progress.enabled = Off y session.use_strict_mode = 1'
        MitWaf           = '    - Bloquear POST multipart con codigo PHP en campos de nombre de fichero (reglas WAF / mod_rewrite / nginx)'
        MitAccess        = '    - Restringir el acceso a internet a los sistemas PHP que no puedan actualizarse de inmediato'
        BpTitle          = '  Fuentes de backports para ramas EOL (actualiza cuando sea posible):'
        BpVendor         = '    - Paquetes del distribuidor/LTS (Debian LTS, Ubuntu Pro): normalmente la opcion mas segura'
        BpSury           = '    - Paquetes Sury, PHP 5.6-8.5 (Debian/Ubuntu): https://packages.sury.org/'
        BpRemi           = '    - Remi Repo, PHP 5.6-8.5 (RHEL/Fedora): https://rpms.remirepo.net/'
        BpUpstream       = '    - Backports oficiales de codigo fuente de php-src (7.4/8.0/8.1, compilar por tu cuenta): https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619'
        BpCommunity      = '    - Backports comunitarios de codigo fuente 5.4-7.3 (no oficiales, revisar antes de usar): https://github.com/vperetti/php-cve-2026-109618-109619-backports'
        BpDisclaimer     = '  Los paquetes de terceros no son oficiales: verifica su origen y firmas antes de aplicarlos.'
        BpRescanNote     = '  Nota: un PHP con backport sigue reportando la version antigua en X-Powered-By, por lo que este comprobador seguira marcandolo; verifica el parche con tu gestor de paquetes.'
        NewerMsg         = 'PHP {0} es posterior a las ramas afectadas (ultimas afectadas: 8.5.x < 8.5.12).'
        UnknownMsg       = 'Rama PHP {0} fuera de la tabla de parches conocida - no se puede determinar.'
        SummaryTitle     = '==================== RESUMEN ===================='
        TagVulnerable    = 'VULNERABLE'
        TagFixed         = 'NO AFECTADA'
        TagEol           = 'VULNERABLE (EOL)'
        TagInconclusive  = 'INCONCLUYENTE'
        TagUnknown       = 'DESCONOCIDA'
        TagError         = 'ERROR'
        AlertMsg         = 'ALERTA: {0} objetivo(s) con version de PHP VULNERABLE. Actualizar PHP de inmediato.'
        PatchesMsg       = 'Parches: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (o superior de cada rama).'
        OfficialPatch    = '  Anuncio oficial de la version: {0}'
        OfficialTag      = '  Tag oficial del codigo fuente: {0}'
        OfficialCveA     = '  CVE-2026-109618 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2026-109618'
        OfficialCveB     = '  CVE-2026-109619 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2026-109619'
        OfficialAdvisory = '  Avisos de seguridad de PHP: https://github.com/php/php-src/security/advisories'
        OfficialSupported = '  Versiones de PHP con soporte: https://www.php.net/supported-versions.php'
        OfficialIndex    = 'Versiones oficiales de PHP: https://www.php.net/releases/'
        NoVulnMsg        = 'Ninguna version vulnerable confirmada por cabecera X-Powered-By.'
        FileNotFound     = 'No se encuentra el archivo: {0}'
        FileEmpty        = 'El archivo {0} esta vacio o solo contiene comentarios.'
        TargetsLoaded    = 'Cargados {0} objetivo(s) desde {1}'
        BothParams       = 'Indica solo uno de -Target o -TargetsFile, no ambos.'
    }
}

function Get-Str {
    # Devuelve el texto del idioma activo (fallback a ingles).
    # Returns the text for the active language (falls back to English).
    param([string]$Key)
    if ($Script:Strings[$Script:Lang].ContainsKey($Key)) {
        return $Script:Strings[$Script:Lang][$Key]
    }
    return $Script:Strings['en'][$Key]
}

# ── Constantes / Constants ────────────────────────────────────────────────────

# Tabla de versiones parcheadas por rama (CVE-2026-109618 / CVE-2026-109619)
# Patch table per branch (CVE-2026-109618 / CVE-2026-109619)
$Script:FixedVersions = @{
    '8.2' = 35
    '8.3' = 36
    '8.4' = 27
    '8.5' = 12
}

$Script:EolBranches = @('5.4','5.5','5.6','7.0','7.1','7.2','7.3','7.4','8.0','8.1')
$Script:VersionRegex = 'PHP/(\d+)\.(\d+)\.(\d+)'
$Script:UserAgent = 'Mozilla/5.0 php2shell-checker/1.0'

# El script Python original desactiva la verificacion de certificados
# (ssl.CERT_NONE). Aqui se replica para permitir escanear hosts con
# certificados autofirmados o caducados.
# The original Python script disables certificate validation
# (ssl.CERT_NONE). This replicates it to allow scanning hosts with
# self-signed or expired certificates.
if ($PSVersionTable.PSVersion.Major -lt 6) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls
    # La asignacion directa de un scriptblock rompe el handshake TLS en PS 5.x,
    # por lo que el delegado se compila con Add-Type.
    # Assigning a scriptblock directly breaks the TLS handshake on PS 5.x,
    # so the delegate is compiled with Add-Type.
    try {
        Add-Type -TypeDefinition @'
using System.Net.Security;
public class Php2ShellRelaxedCertPolicy {
    public static RemoteCertificateValidationCallback GetCallback() {
        return (sender, certificate, chain, sslPolicyErrors) => true;
    }
}
'@ -ErrorAction Stop
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [Php2ShellRelaxedCertPolicy]::GetCallback()
    }
    catch {
        # Si la compilacion falla, se mantiene la validacion de certificados por defecto.
        # If compilation fails, default certificate validation remains active.
    }
}

# ── Colored output / Salida con color ─────────────────────────────────────────

function Write-Ok   { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Err  { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }
function Write-Info { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }

# ── HTTP (solo GET, solo lectura / GET only, read-only) ───────────────────────

function Get-HeaderValue {
    param($Headers, [string]$Name)
    if (-not $Headers) { return '' }
    foreach ($key in @($Headers.Keys)) {
        if ([string]$key -ieq $Name) {
            $value = $Headers[$key]
            if ($value -is [array]) { return ($value -join ', ') }
            return [string]$value
        }
    }
    return ''
}

function Get-HttpResponse {
    # Devuelve un objeto { StatusCode, Headers, Error }.
    # Error = $null si hubo respuesta HTTP (incluidos 4xx/5xx).
    # Returns an object { StatusCode, Headers, Error }.
    # Error = $null if an HTTP response was received (including 4xx/5xx).
    param([string]$Url, [int]$Timeout)

    $requestParams = @{
        Uri             = $Url
        Method          = 'Get'
        TimeoutSec      = $Timeout
        UserAgent       = $Script:UserAgent
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
    }
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $requestParams.SkipCertificateCheck = $true
    }
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $requestParams.SkipHttpErrorCheck = $true
    }

    try {
        $response = Invoke-WebRequest @requestParams
        return [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            Headers    = $response.Headers
            Error      = $null
        }
    }
    catch {
        $response = $_.Exception.Response

        # PowerShell 5.x: los codigos 4xx/5xx llegan como HttpWebResponse.
        # (comparacion por nombre de tipo: System.Net.Http no siempre esta
        # cargado en 5.x y el literal de tipo lanzaria TypeNotFound)
        # PowerShell 5.x: 4xx/5xx codes arrive as HttpWebResponse.
        # (type-name comparison: System.Net.Http is not always loaded
        # in 5.x and the type literal would throw TypeNotFound)
        if ($response -and $response.GetType().FullName -eq 'System.Net.HttpWebResponse') {
            return [pscustomobject]@{
                StatusCode = [int]$response.StatusCode
                Headers    = $response.Headers
                Error      = $null
            }
        }

        # PowerShell 6: los codigos 4xx/5xx llegan como HttpResponseMessage
        # PowerShell 6: 4xx/5xx codes arrive as HttpResponseMessage
        if ($response -and $response.GetType().Name -eq 'HttpResponseMessage') {
            $flatHeaders = @{}
            foreach ($entry in $response.Headers.GetEnumerator()) {
                $flatHeaders[$entry.Key] = (@($entry.Value) -join ', ')
            }
            return [pscustomobject]@{
                StatusCode = [int]$response.StatusCode
                Headers    = $flatHeaders
                Error      = $null
            }
        }

        return [pscustomobject]@{
            StatusCode = 0
            Headers    = $null
            Error      = $_.Exception.Message
        }
    }
}

# ── Verdict logic / Logica de veredicto ───────────────────────────────────────

function ConvertTo-TargetUrl {
    param([string]$RawTarget)
    $url = $RawTarget.Trim().TrimEnd('/')
    if ($url -notmatch '^(http|https)://') {
        $url = "https://$url"
    }
    return $url
}

function Invoke-TargetCheck {
    # CVE-2026-109619 / CVE-2026-109618 - PHP version fingerprint.
    # Unica comprobacion: peticion GET pasiva + cabecera X-Powered-By.
    # Single check: passive GET request + X-Powered-By header.
    param(
        [string]$Url,
        [int]$Timeout,
        [bool]$AllowHttpFallback = $false
    )

    Write-Info ((Get-Str 'Checking') -f $Url)

    $response = Get-HttpResponse -Url $Url -Timeout $Timeout

    if ($response.Error -and $AllowHttpFallback -and $Url -match '^https://') {
        $httpUrl = $Url -replace '^https://', 'http://'
        Write-Info ((Get-Str 'HttpsRetry') -f $httpUrl)
        $response = Get-HttpResponse -Url $httpUrl -Timeout $Timeout
        if (-not $response.Error) { $Url = $httpUrl }
    }

    if ($response.Error) {
        Write-Err ((Get-Str 'ConnFailed') -f $response.Error)
        return [pscustomobject]@{
            Target = $Url; Status = 'ERROR'; Version = ''; Detail = $response.Error
        }
    }

    $poweredBy = Get-HeaderValue -Headers $response.Headers -Name 'X-Powered-By'

    if (-not $poweredBy -or $poweredBy -notmatch $Script:VersionRegex) {
        Write-Warn ((Get-Str 'NoXpb') -f $response.StatusCode)
        Write-Warn (Get-Str 'NoXpb2')
        return [pscustomobject]@{
            Target = $Url; Status = 'INCONCLUSIVE'; Version = ''
            Detail = 'X-Powered-By without PHP version'
        }
    }

    $major = [int]$Matches[1]
    $minor = [int]$Matches[2]
    $patch = [int]$Matches[3]
    $version = "$major.$minor.$patch"
    Write-Info ((Get-Str 'VersionDetected') -f $version)

    $branch = "$major.$minor"
    if ($Script:FixedVersions.ContainsKey($branch)) {
        $fixedPatch = [int]$Script:FixedVersions[$branch]
        if ($patch -ge $fixedPatch) {
            Write-Info ((Get-Str 'FixedMsg') -f $version, "$branch.$fixedPatch")
            return [pscustomobject]@{
                Target = $Url; Status = 'FIXED'; Version = $version
                Detail = "Patched: $branch.$fixedPatch"
            }
        }
        else {
            Write-Ok ((Get-Str 'VulnMsg') -f $version)
            Write-Ok ((Get-Str 'VulnPatchedIn') -f "$branch.$fixedPatch")
            Write-Ok (Get-Str 'Vuln109618')
            Write-Ok (Get-Str 'Vuln109619')
            $patchVersion = "$branch.$fixedPatch"
            Write-Info ((Get-Str 'OfficialPatch') -f "https://www.php.net/releases/$patchVersion.php")
            Write-Info ((Get-Str 'OfficialTag') -f "https://github.com/php/php-src/releases/tag/php-$patchVersion")
            Write-Info (Get-Str 'OfficialCveA')
            Write-Info (Get-Str 'OfficialCveB')
            Write-Info (Get-Str 'OfficialAdvisory')
            return [pscustomobject]@{
                Target = $Url; Status = 'VULNERABLE'; Version = $version
                Detail = "Affected up to $branch.$($fixedPatch - 1); patch in $branch.$fixedPatch"
            }
        }
    }

    if ($Script:EolBranches -contains $branch) {
        Write-Ok ((Get-Str 'EolMsg') -f $version)
        Write-Ok (Get-Str 'EolFix')
        Write-Info (Get-Str 'OfficialSupported')
        Write-Info (Get-Str 'OfficialCveA')
        Write-Info (Get-Str 'OfficialCveB')
        Write-Warn (Get-Str 'MitTitle')
        Write-Warn (Get-Str 'MitIni')
        Write-Warn (Get-Str 'MitWaf')
        Write-Warn (Get-Str 'MitAccess')
        Write-Warn (Get-Str 'BpTitle')
        Write-Warn (Get-Str 'BpVendor')
        Write-Warn (Get-Str 'BpSury')
        Write-Warn (Get-Str 'BpRemi')
        Write-Warn (Get-Str 'BpUpstream')
        Write-Warn (Get-Str 'BpCommunity')
        Write-Warn (Get-Str 'BpDisclaimer')
        Write-Warn (Get-Str 'BpRescanNote')
        return [pscustomobject]@{
            Target = $Url; Status = 'EOL'; Version = $version
            Detail = 'EOL branch inside the affected range - upgrade required'
        }
    }

    if ($major -gt 8 -or $branch -eq '8.6') {
        Write-Info ((Get-Str 'NewerMsg') -f $version)
        return [pscustomobject]@{
            Target = $Url; Status = 'FIXED'; Version = $version
            Detail = 'Newer than the affected branches'
        }
    }

    Write-Warn ((Get-Str 'UnknownMsg') -f $version)
    return [pscustomobject]@{
        Target = $Url; Status = 'UNKNOWN'; Version = $version
        Detail = 'Branch outside the patch table'
    }
}

# ── Presentation / Presentacion ────────────────────────────────────────────────

function Show-Banner {
    param([string]$TargetDescription)
    Write-Host ''
    Write-Host '==============================================================' -ForegroundColor Cyan
    Write-Host '        php2shell vulnerability checker (PowerShell)         ' -ForegroundColor Cyan
    Write-Host '        CVE-2026-109618  -  CVE-2026-109619                  ' -ForegroundColor Cyan
    Write-Host '==============================================================' -ForegroundColor Cyan
    Write-Host (Get-Str 'BannerPassive')
    Write-Host (Get-Str 'BannerNoAttack')
    Write-Host ((Get-Str 'BannerTarget') -f $TargetDescription) -ForegroundColor White
}

function Show-Summary {
    param($Results)

    Write-Host ''
    Write-Host (Get-Str 'SummaryTitle') -ForegroundColor White
    foreach ($result in $Results) {
        switch ($result.Status) {
            'VULNERABLE'   { $tag = Get-Str 'TagVulnerable';   $color = 'Red'    }
            'FIXED'        { $tag = Get-Str 'TagFixed';         $color = 'Green'  }
            'EOL'          { $tag = Get-Str 'TagEol';           $color = 'Red'    }
            'INCONCLUSIVE' { $tag = Get-Str 'TagInconclusive';  $color = 'Yellow' }
            'UNKNOWN'      { $tag = Get-Str 'TagUnknown';       $color = 'Yellow' }
            default        { $tag = Get-Str 'TagError';         $color = 'Red'    }
        }
        $versionText = if ($result.Version) { "PHP $($result.Version)" } else { '-' }
        Write-Host ("  {0,-17}  {1,-14}  {2}" -f $tag, $versionText, $result.Target) -ForegroundColor $color
    }
    Write-Host ''

    $vulnerableCount = @($Results | Where-Object { $_.Status -eq 'VULNERABLE' -or $_.Status -eq 'EOL' }).Count
    if ($vulnerableCount -gt 0) {
        Write-Host ('  ' + ((Get-Str 'AlertMsg') -f $vulnerableCount)) -ForegroundColor Red
        Write-Host ('  ' + (Get-Str 'PatchesMsg')) -ForegroundColor Red
        Write-Host ('  ' + (Get-Str 'OfficialIndex')) -ForegroundColor Red
    }
    else {
        Write-Host ('  ' + (Get-Str 'NoVulnMsg')) -ForegroundColor Green
    }
    Write-Host ''
    return $vulnerableCount
}

# ── Target loading / Carga de objetivos ───────────────────────────────────────

function Read-TargetsFromFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Err ((Get-Str 'FileNotFound') -f $Path)
        return $null
    }
    $targets = @()
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        $trimmed = $line.Trim()
        if ($trimmed -and -not $trimmed.StartsWith('#')) {
            $targets += $trimmed.TrimEnd('/')
        }
    }
    if ($targets.Count -eq 0) {
        Write-Err ((Get-Str 'FileEmpty') -f $Path)
        return $null
    }
    return $targets
}

function Invoke-Scan {
    param([string[]]$TargetList)
    $results = @()
    $index = 0
    foreach ($rawTarget in $TargetList) {
        $index++
        if ($TargetList.Count -gt 1) {
            Write-Host ''
            Write-Host ('  ' + ('=' * 60)) -ForegroundColor Cyan
            Write-Host (('  ' + (Get-Str 'TargetHeader')) -f $index, $TargetList.Count, $rawTarget) -ForegroundColor White
            Write-Host ('  ' + ('=' * 60)) -ForegroundColor Cyan
        }
        else {
            Show-Banner -TargetDescription $rawTarget
        }

        $url = ConvertTo-TargetUrl -RawTarget $rawTarget
        $allowFallback = ($rawTarget -notmatch '^(http|https)://')
        $results += Invoke-TargetCheck -Url $url -Timeout $TimeoutSec -AllowHttpFallback:$allowFallback
    }
    return [pscustomobject]@{ Results = $results }
}

# ── Interactive menu / Menu interactivo ───────────────────────────────────────

function Show-Menu {
    Write-Host ''
    Write-Host '====== MENU php2shellbt ======' -ForegroundColor Cyan
    Write-Host (Get-Str 'MenuOpt1')
    Write-Host (Get-Str 'MenuOpt2')
    Write-Host ((Get-Str 'MenuOpt3') -f $Script:LanguageNames[$Script:Lang])
    Write-Host (Get-Str 'MenuOpt4')
}

function Invoke-MenuLoop {
    $anyVulnerable = $false

    while ($true) {
        Show-Menu
        $choice = (Read-Host (Get-Str 'MenuPrompt')).Trim()

        switch ($choice) {
            '1' {
                $input = (Read-Host (Get-Str 'DomainPrompt')).Trim()
                if (-not $input) { Write-Warn (Get-Str 'EmptyDomain'); break }
                $scan = Invoke-Scan -TargetList @($input)
                $vulnCount = Show-Summary -Results $scan.Results
                if ($vulnCount -gt 0) { $anyVulnerable = $true }
            }
            '2' {
                $fileName = (Read-Host (Get-Str 'FilePrompt')).Trim()
                if (-not $fileName) { $fileName = 'targets.txt' }
                $resolvedPath = if ([System.IO.Path]::IsPathRooted($fileName)) { $fileName }
                                else { Join-Path (Get-Location) $fileName }
                $targets = Read-TargetsFromFile -Path $resolvedPath
                if ($targets) {
                    Write-Info ((Get-Str 'TargetsLoaded') -f $targets.Count, $resolvedPath)
                    $scan = Invoke-Scan -TargetList $targets
                    $vulnCount = Show-Summary -Results $scan.Results
                    if ($vulnCount -gt 0) { $anyVulnerable = $true }
                }
            }
            '3' {
                if ($Script:Lang -eq 'en') { $Script:Lang = 'es' } else { $Script:Lang = 'en' }
                Write-Info ((Get-Str 'LanguageSwitched') -f $Script:LanguageNames[$Script:Lang])
            }
            '4' {
                Write-Info (Get-Str 'MenuExit')
                return $anyVulnerable
            }
            default {
                Write-Warn ((Get-Str 'MenuInvalid') -f $choice)
            }
        }
    }
}

# ── Entry point / Punto de entrada ────────────────────────────────────────────

$script:AnyVulnerable = $false

if ($Target -and $TargetsFile) {
    Write-Err (Get-Str 'BothParams')
    exit 2
}

if ($Target) {
    $scan = Invoke-Scan -TargetList @($Target)
    $vulnCount = Show-Summary -Results $scan.Results
    if ($vulnCount -gt 0) { $script:AnyVulnerable = $true }
}
elseif ($TargetsFile) {
    $resolvedPath = if ([System.IO.Path]::IsPathRooted($TargetsFile)) { $TargetsFile }
                    else { Join-Path (Get-Location) $TargetsFile }
    $targets = Read-TargetsFromFile -Path $resolvedPath
    if ($targets) {
        $scan = Invoke-Scan -TargetList $targets
        $vulnCount = Show-Summary -Results $scan.Results
        if ($vulnCount -gt 0) { $script:AnyVulnerable = $true }
    }
    else {
        exit 2
    }
}
else {
    $script:AnyVulnerable = Invoke-MenuLoop
}

$ProgressPreference = $Script:ProgressBackup
if ($script:AnyVulnerable) { exit 1 } else { exit 0 }
