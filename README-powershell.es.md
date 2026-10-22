# php2shellbt (PowerShell)

**Comprobador pasivo de exposicion a CVE-2026-109618 / CVE-2026-109619 (php2shell).**

> Idioma: Español | [English](README-powershell.md)

Version en PowerShell de la comprobacion pasiva de `php2shellbt.py`. Determina si un
servidor web ejecuta una version de PHP dentro del rango afectado leyendo la cabecera
de respuesta `X-Powered-By` — con **cero ataques contra el objetivo**.

---

## Fork del proyecto original

Este es un **fork en PowerShell** de [php2shellbt](https://github.com/pentestershell/php2shellbt)
de [pentestershell (BTshell)](https://github.com/pentestershell) — un escáner en
Python 3 para la cadena de vulnerabilidades php2shell (CVE-2026-109618 /
CVE-2026-109619). El `php2shellbt.py` original y su `README.md` viven en este mismo
repositorio.

**Diferencias respecto al upstream:**

- Reescrito en PowerShell (`.ps1`), probado en Windows PowerShell 5.1 y PowerShell 7+
- Menú interactivo: valida un solo dominio o una lista desde un archivo `.txt`
- Interfaz bilingüe: inglés (por defecto) y español, conmutable en tiempo de ejecución
- **Solo pasivo por diseño**: se eliminaron las comprobaciones activas del escáner
  Python original (crash-probe, sondas upload_progress, handler mismatch, inyección
  de sesion + LFI). Consulta [Validación de seguridad](#validación-de-seguridad--qué-no-hace-este-script)
  para ver la lista completa y su justificación.
- Muestra mitigaciones temporales y fuentes de backports de confianza para ramas EOL

La lógica de detección (tabla de parches, rangos afectados) es idéntica a la original.
El crédito de la investigación de las vulnerabilidades pertenece a los autores
originales; las plantillas Nuclei que inspiraron la herramienta original están
disponibles en [Ademking/php2shell-nuclei-templates](https://github.com/Ademking/php2shell-nuclei-templates).

---

## Validación de seguridad — qué NO hace este script

Este script realiza **únicamente peticiones GET pasivas de solo lectura**. No envía
payloads, no provoca fallos del motor PHP, no agota la memoria del servidor y jamás
verifica un RCE.

Las siguientes comprobaciones del escáner Python original fueron **excluidas
deliberadamente** porque pueden afectar al software objetivo:

| Comprobación excluida | Motivo de exclusión |
|---|---|
| Crash-probe (cuerpos multipart malformados de hasta 20 MiB) | Denegación de servicio: tumba el worker de PHP |
| Sondas session.upload_progress con PHPSESSID manipulado | Payload intrusivo que dispara el motor |
| Handler mismatch (inyección de objetos serializados) | Payload intrusivo que dispara el deserializador |
| Cadena de inyección de sesión + LFI (`<?php ... ?>` en filenames) | Verificación de RCE — un ataque real |

Lo que queda es la única comprobación segura: leer `X-Powered-By` y comparar la
versión con la tabla de parches.

---

## Requisitos

- Windows PowerShell 5.1, o PowerShell 7+ (`pwsh`)
- Sin módulos, sin paquetes NuGet, sin dependencias de internet — un único archivo `.ps1`

```powershell
.\php2shellbt.ps1
```

Si tu política de ejecución bloquea los scripts, ejecútalo una vez con:

```powershell
powershell -ExecutionPolicy Bypass -File .\php2shellbt.ps1
```

---

## Uso

### Menú interactivo (por defecto)

```text
====== MENU php2shellbt ======
  1) Validar un solo dominio
  2) Validar desde un archivo .txt (un dominio/URL por linea, en este directorio)
  3) Language / Idioma: English
  4) Salir
```

- **Opción 1** pide un dominio o URL. Los dominios sin esquema (`ejemplo.com`) se
  reintentan por `http://` si `https://` falla.
- **Opción 2** lee un archivo `.txt` del directorio actual (nombre por defecto
  `targets.txt`). Un objetivo por línea; se ignoran las líneas vacías y los
  comentarios con `#`.
- **Opción 3** alterna el idioma de la interfaz entre inglés y español al instante.

### Modo por parámetros (omite el menú)

```powershell
# Un solo objetivo
.\php2shellbt.ps1 -Target https://ejemplo.com

# Varios objetivos desde un archivo
.\php2shellbt.ps1 -TargetsFile .\targets.txt

# Salida en español, timeout personalizado
.\php2shellbt.ps1 -Language es -TargetsFile .\targets.txt -TimeoutSec 30
```

### Parámetros

| Parámetro | Por defecto | Descripción |
|---|---|---|
| `-Target` | — | Dominio o URL única a validar |
| `-TargetsFile` | — | Archivo `.txt` con un dominio/URL por línea (comentarios `#` permitidos) |
| `-Language` | `en` | Idioma de la interfaz: `en` (inglés) o `es` (español) |
| `-TimeoutSec` | `10` | Tiempo de espera por petición HTTP en segundos |

---

## Veredictos

| Etiqueta | Significado |
|---|---|
| `VULNERABLE` | La versión de PHP está en el rango afectado de una rama que sí tiene parche |
| `VULNERABLE (EOL)` | La versión está en el rango afectado (5.4.0 – 8.5.11) pero su rama está al final de su vida útil — nunca recibirá parche |
| `NO AFECTADA` | Versión parcheada, o rama posterior a las afectadas |
| `INCONCLUYENTE` | Sin cabecera `X-Powered-By` que exponga una versión de PHP |
| `DESCONOCIDA` | Rama fuera de la tabla de parches conocida |
| `ERROR` | Fallo de conexión |

### Códigos de salida

| Código | Significado |
|---|---|
| `0` | Ninguna versión vulnerable confirmada |
| `1` | Al menos un objetivo confirmado como vulnerable (incluidas ramas EOL en rango) |
| `2` | Invocación incorrecta (p. ej. `-Target` y `-TargetsFile` a la vez, o archivo ilegible) |

El código de salida `1` permite usar el script en pipelines de CI/CD.

---

## Tabla de parches

| Rama | Rango afectado | Parcheada en |
|---|---|---|
| 8.2.x | 8.2.0 – 8.2.34 | **8.2.35** |
| 8.3.x | 8.3.0 – 8.3.35 | **8.3.36** |
| 8.4.x | 8.4.0 – 8.4.26 | **8.4.27** |
| 8.5.x | 8.5.0 – 8.5.11 | **8.5.12** |
| 5.4 – 8.1 | todas las versiones | EOL — sin parche oficial; actualiza o usa un backport |

Al detectar una vulnerabilidad el script imprime enlaces oficiales: el anuncio de la
versión en php.net, el tag de código fuente en GitHub del repositorio `php-src`, las
entradas NVD de ambos CVE y la página de avisos de seguridad de PHP.

---

## Ramas EOL: mitigaciones temporales y backports

Para las ramas al final de su vida útil (5.4 – 8.1) no existe parche oficial. El
script muestra:

**Mitigaciones temporales (NO definitivas)** — los desarrolladores del núcleo de PHP
indican que la única solución real es parchear/actualizar:

- `session.upload_progress.enabled = Off` y `session.use_strict_mode = 1` en `php.ini`
- Bloquear POST multipart con código PHP en campos de nombre de fichero (reglas WAF / mod_rewrite / nginx)
- Restringir el acceso a internet a los sistemas PHP que no puedan actualizarse de inmediato

**Fuentes de backports, ordenadas por confianza:**

1. Paquetes del distribuidor/LTS (Debian LTS, Ubuntu Pro) — normalmente la opción más segura
2. [Paquetes Sury](https://packages.sury.org/) — PHP 5.6–8.5 en Debian/Ubuntu
3. [Remi Repo](https://rpms.remirepo.net/) — PHP 5.6–8.5 en RHEL/Fedora
4. [Backports oficiales de código fuente de php-src](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619) — 7.4/8.0/8.1, compilar por tu cuenta
5. [Backports comunitarios](https://github.com/vperetti/php-cve-2026-109618-109619-backports) — 5.4–7.3, no oficiales; revisar antes de usar

Los paquetes de terceros no son oficiales: verifica su origen y firmas antes de aplicarlos.

> **Advertencia al re-escanear:** un PHP con backport sigue reportando la versión
> antigua en `X-Powered-By`, por lo que este comprobador seguirá marcándolo como
> vulnerable. Verifica el parche con tu gestor de paquetes (`dpkg` / `rpm` /
> `apt changelog`), no volviendo a escanear.

---

## Ejemplo de sesión

```text
==============================================================
        php2shell vulnerability checker (PowerShell)
        CVE-2026-109618  -  CVE-2026-109619
==============================================================
  Modo pasivo: solo lee la version remota de PHP (X-Powered-By).
  No envia payloads ni provoca fallos en el servidor.
  Objetivo : www.ejemplo.com
[*] Comprobando https://www.ejemplo.com ...
[*] Version de PHP detectada: 7.3.33
[+] VULNERABLE - PHP 7.3.33 esta dentro del rango afectado (5.4.0 - 8.5.11) y
    su rama esta al final de su vida util (EOL): no recibira ningun parche nunca.
[+]   Unica remediacion definitiva posible: actualizar a una rama con soporte (...).
[*]   Versiones de PHP con soporte: https://www.php.net/supported-versions.php
[*]   CVE-2026-109618 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2026-109618
[*]   CVE-2026-109619 (NVD): https://nvd.nist.gov/vuln/detail/CVE-2026-109619
[!]   Mitigaciones temporales (NO definitivas): ...
[!]   Fuentes de backports para ramas EOL: ...

==================== RESUMEN ====================
  VULNERABLE (EOL)   PHP 7.3.33      https://www.ejemplo.com

  ALERTA: 1 objetivo(s) con version de PHP VULNERABLE. Actualizar PHP de inmediato.
  Parches: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (o superior de cada rama).
  Versiones oficiales de PHP: https://www.php.net/releases/
```

---

## Cómo funciona la comprobación

1. Envía una única petición `GET` al objetivo.
2. Lee la cabecera de respuesta `X-Powered-By` y extrae `PHP/x.y.z`.
3. Compara la versión con la tabla de parches y muestra el veredicto.

**Limitaciones:**

- Si el servidor oculta `X-Powered-By` (es habitual desactivar esa exposición), el
  resultado es `INCONCLUYENTE` — eso **no** significa que el host esté a salvo.
- El script confirma que la **versión** está en el rango afectado. La explotabilidad
  real depende además de la configuración del servidor (`session.upload_progress`,
  presencia de LFI, serializadores, etc.). En una rama EOL o sin parche, actualizar es
  la única recomendación sensata en cualquier caso.
- La validación de certificados está desactivada (igual que el escáner Python
  original) para permitir escanear hosts con certificados autofirmados. Esto afecta
  a todo el proceso de PowerShell.

---

## Aviso legal

> Esta herramienta realiza comprobaciones pasivas de versión de solo lectura y está
> pensada **únicamente para evaluaciones de seguridad autorizadas e inventario de
> activos**. Escanear sistemas de los que no eres propietario o no tienes permiso
> explícito puede violar sus condiciones de servicio o la legislación local. Los
> autores no asumen ninguna responsabilidad por su uso indebido.

---

## Licencia

MIT © 2026 pentestershell (BTshell)
