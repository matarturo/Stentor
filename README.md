# Stentor

[![Platform Windows](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/en-us/windows)
[![PowerShell 5.1+](https://img.shields.io/badge/powershell-5.1%2B-blueviolet.svg)](https://learn.microsoft.com/powershell/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![Status: Beta](https://img.shields.io/badge/status-beta-orange.svg)]()

**Stentor** es una herramienta de **triaje forense en vivo** para equipos Windows. Recolecta, en una sola ejecución y sin instalar nada, la evidencia más útil para responder preguntas como:

- ¿Quién inició sesión en el equipo, cuándo y desde dónde?
- ¿Hubo conexiones a internet? ¿A qué sitios y con qué programa?
- ¿Hay indicios de **control remoto** (RDP, herramientas de acceso remoto, VPN o túneles, persistencia)?

Está pensada para equipos de respuesta a incidentes, analistas SOC y personal de TI que necesitan un primer panorama rápido y ordenado, con un manifiesto de hashes para la cadena de custodia.

> **Esto es triaje, no adquisición forense completa.** Se ejecuta sobre el sistema en vivo y, como cualquier herramienta de este tipo, deja huella en él (ver [Huella en el sistema](#-huella-en-el-sistema-y-buenas-prácticas)). No reemplaza la imagen de disco ni la captura de memoria cuando el caso las requiera.

> ⚠️ **Autorización.** Recolecta datos personales (historial de navegación de todos los usuarios, cuentas, conexiones). Úsala solo con autorización formal del propietario del equipo y conforme a la normativa y las políticas de tu organización.

---

## Elige cómo usarla

| | **Binario `Stentor.exe`** | **Script `Stentor.ps1`** |
|---|---|---|
| **Para** | Administradores y soporte TI | Blue Team, Red Team, analistas DFIR |
| **Ventaja** | Descargar y ejecutar; pide elevación (UAC) solo; no requiere cambiar la política de ejecución | Código legible y auditable; adaptable; se puede firmar |
| **Inconvenientes** | Más propenso a bloqueos de antivirus/EDR; para modificarlo hay que recompilar | Requiere consola de administrador y `-ExecutionPolicy Bypass` (o script firmado) |
| **Requisito en el equipo** | Windows PowerShell 5.1 (el binario lo usa internamente) | Windows PowerShell 5.1 |

### Contenido del repositorio

```text
Stentor/
├── Stentor.ps1   <-- Script (usuarios avanzados)
├── README.md
├── LICENSE
└── SHA256SUMS.txt              <-- Hashes de cada versión publicada

Releases/
└── Stentor.exe           <-- Binario (TI y soporte), junto con SHA256SUMS.txt
```

---

## 📥 Descarga y Métodos de Ejecución

Elige el método de despliegue según el perfil del analista y los requerimientos del entorno:

| Característica | Binario `Stentor.exe` | Script `Stentor.ps1` |
| :--- | :--- | :--- |
| **Perfil destinado** | Administradores y soporte TI | Blue Team, Red Team, analistas DFIR |
| **Ventajas** | Descargar y ejecutar; pide elevación (UAC) automáticamente; no requiere alterar `ExecutionPolicy`. | Código 100% legible y auditable; personalizable y adaptable. |
| **Inconvenientes** | Más propenso a alertas heurísticas de Antivirus/EDR (requiere recompilar para cambios). | Requiere consola de Administrador manual y `ExecutionPolicy Bypass`. |
| **Requisito en el host** | Windows PowerShell 5.1 (usado internamente). | Windows PowerShell 5.1. |

---

## 🚀 Inicio rápido

### Opción 1: Binario (TI y soporte)

1. Descarga el ZIP de la última versión desde la página de **Releases** (contiene `Stentor.exe` y `SHA256SUMS.txt`).
2. **Verifica el hash** antes de ejecutar:
   ```powershell
   Get-FileHash .\Stentor.exe -Algorithm SHA256
   ```
   Debe coincidir con el valor de `SHA256SUMS.txt`.
3. Conecta una **unidad externa** (idealmente cifrada) con varios GB libres. No guardes la evidencia en el disco del equipo investigado.
4. Abre **CMD o PowerShell como Administrador**.
5. Ejecuta, indicando siempre la carpeta de salida:
   ```cmd
   Stentor.exe -Dias 30 -Salida E:\Evidencias_PC01
   ```
6. Al terminar, abre `RESUMEN.txt` dentro de la carpeta generada.

> **Si el antivirus lo bloquea:** no lo desactives en el equipo investigado. Pide al equipo de seguridad que autorice el archivo por su hash (SHA-256). Es un comportamiento esperable en binarios generados con PS2EXE y en herramientas que leen artefactos del sistema.

### Opción 2: Script (usuarios avanzados)

Abre **PowerShell como Administrador** (preferiblemente con el script en una unidad externa, ej. `C:\`):

```powershell
Unblock-File .\Stentor.ps1
powershell -ExecutionPolicy Bypass -File .\Stentor.ps1 -Dias 60 -Salida C:\Caso01
```

Ejecútalo con `powershell.exe` (Windows PowerShell 5.1). PowerShell 7 no está probado.

**Personalización.** Las listas de detección son variables dentro del script:

| Variable | Qué controla |
|---|---|
| `$patron` | Nombres de herramientas de acceso remoto, VPN y túneles que se buscan en procesos, servicios y software instalado |
| `$vpnAdap` | Descripciones de adaptadores de red virtuales o VPN |
| `$avPat` | Fabricantes de antivirus/EDR cuyos logs y eventos se recolectan |
| `$ruidoPS` / `$sospPS` | Qué se descarta como ruido y qué se marca como sospechoso en los eventos 4104 de PowerShell |
| `$privado` | Rangos de IP que se consideran no públicos |
| `$logs` | Lista de registros `.evtx` que se exportan |
| `$remotos` | Rutas donde buscar los logs propios de herramientas de acceso remoto |

---

## ⚙️ Parámetros

| Parámetro | Tipo | Por defecto | Descripción |
|---|---|---|---|
| `-Dias` | int | `30` | Ventana hacia atrás para filtrar eventos y archivos recientes |
| `-Salida` | string | Carpeta junto al script (o carpeta actual) | Destino de la evidencia. **La fecha y hora se agregan siempre**: `E:\Caso01` genera `E:\Caso01_20261031_081500`. Si indicas la raíz de una unidad (`E:\`), crea `E:\Triage_NOMBREPC_20261031_081500` |
| `-ResolverInversa` | switch | Desactivado | Consulta DNS inverso (PTR) de las IP remotas **desde el equipo investigado**. Genera tráfico DNS y deja rastro en la red; úsalo solo si lo aceptas |

El tiempo de ejecución depende sobre todo del tamaño de los logs: unos pocos minutos en un equipo ligero, bastante más en uno con mucho historial. Usa `-Dias 7` para una primera prueba rápida.

---

## 🔎 Qué recolecta

1. **Contexto y cobertura:** zona horaria, política de auditoría (`auditpol`) y cuánto historial tiene realmente cada log (`00_cobertura_logs.csv`).
2. **Copia de los `.evtx` originales** (Security, System, Application, PowerShell, RDP, WinRM, Defender, Firewall, Task Scheduler, Sysmon si existe, entre otros).
3. **Cuentas y accesos:** inicios de sesión exitosos (4624) y fallidos (4625), credenciales explícitas, privilegios especiales, tipo de logon y origen; resumen por usuario, tipo e IP.
4. **Control remoto y persistencia:** sesiones RDP y WinRM, servicios y tareas programadas nuevos, cuentas y grupos modificados, logs borrados, cambios de firewall, y herramientas de acceso remoto, VPN y túneles (instaladas, en ejecución o como servicios), con sus puertos en escucha.
5. **PowerShell (eventos 4104):** exportación completa y versión filtrada sin el ruido del propio sistema y de la herramienta, con una sección de patrones sospechosos (descargas, comandos codificados, ejecución remota, cambios en Defender).
6. **Red en vivo:** conexiones TCP/UDP, caché DNS, procesos con su línea de comandos, puertos en escucha, reglas de firewall de entrada permitidas, adaptadores de red, y **conexiones públicas con hora de inicio**, proceso, destino y nombre según la caché DNS.
7. **Conectividad histórica y exposición:** Además del estado en vivo, Stentor consolida evidencia **histórica** de conectividad (carpeta `historico\`):
primera y última conexión a cada red, eventos de red y Wi-Fi, descargas BITS y Windows Update, cambios en
reglas del firewall, accesos desde IP pública y ejecución de navegadores y herramientas remotas, en una
línea de tiempo (`LINEA_TIEMPO_conectividad.csv`) con fecha y hora. `RESUMEN.txt` indica la evidencia más
antigua y la más reciente disponibles.
- "Más antigua" es la más antigua **disponible**, no necesariamente la primera conexión real.
- Conectarse a una red no prueba acceso a internet; la exposición mostrada es **potencial**.
- Para tráfico por aplicación con fechas, analiza `artefactos\SRUM\SRUDB.dat` con SrumECmd.
8. **Antivirus y EDR:** productos registrados en Windows Security Center, detecciones y **exclusiones** de Defender, eventos y logs de texto de otros fabricantes.
9. **Artefactos:**
   - Base **SRUM** (`SRUDB.dat`), copiada mediante instantánea VSS, para el análisis de uso de red por aplicación.
   - **Historiales de navegador** (Chrome, Edge, Firefox) de todos los usuarios, copiados para analizarlos fuera del equipo.
   - Logs propios de AnyDesk, TeamViewer, RustDesk, ScreenConnect y Quick Assist, si existen.
   - Hives `SYSTEM` y `SOFTWARE`, `Amcache.hve` y el listado de archivos Prefetch (nombres y fechas, no los archivos).
10. **Cadena de custodia:** `MANIFIESTO_SHA256.csv` con el SHA-256 de todo lo recolectado.

### Qué NO hace

- No captura memoria RAM ni crea una imagen de disco.
- No copia los hives `SAM`, `SECURITY` ni `NTUSER.DAT`, ni la MFT (solo `SYSTEM`, `SOFTWARE` y `Amcache.hve`).
- No copia archivos de cuarentena del antivirus: de las carpetas del antivirus solo toma logs de texto recientes y excluye las rutas de cuarentena, para no exponer malware activo.
- **No analiza el contenido** de SRUM, de los historiales de navegador, de Amcache ni de los hives copiados: los recolecta para analizarlos con herramientas externas (por ejemplo SrumECmd, AmcacheParser, Hindsight, DB Browser for SQLite, Registry Explorer). Tampoco copia los archivos Prefetch: solo usa sus nombres y fechas.
- No cambia la configuración del sistema: no activa auditoría ni habilita logs. Las huellas inevitables de la ejecución se describen en [Huella en el sistema](#-huella-en-el-sistema-y-buenas-prácticas).
- No confirma por sí sola que el equipo estuviera expuesto a internet ni cuándo se conectó por primera vez: aporta evidencia y una línea de tiempo, y la exposición real depende de elementos externos (router, NAT, firewall perimetral).
---

## 📂 Estructura de la salida

```text
Triage_NOMBREPC_20261031_120000/
Stentor_NOMBREPC_20261031_120000/
├── RESUMEN.txt                      <-- Empieza aquí (ahora abre con "Desde cuándo")
├── transcript.txt                   <-- Transcripción de la consola (errores y avisos)
├── MANIFIESTO_SHA256.csv            <-- Hashes SHA-256 de toda la evidencia
├── 00_cobertura_logs.csv            <-- Cuánto historial hay realmente en cada log
├── 01_logons_exitosos_4624.csv      <-- (los CSV de eventos solo se crean si hay eventos)
├── 01b_RESUMEN_usuarios_logon.csv
├── 14b_PowerShell_4104_FILTRADO.csv
├── ...
├── evtx/                            <-- Copias de los .evtx originales
├── live/                            <-- Estado volátil (foto del momento de la ejecución)
│   ├── conexiones_publicas.txt/.csv       (con hora de inicio de cada conexión activa)
│   ├── sitios_conectados_ahora.txt
│   ├── dominios_cache_dns.txt
│   ├── puertos_escucha.csv
│   ├── tcp_conexiones.csv, procesos.csv, servicios.csv, ...
├── historico/                       <-- NUEVO: evidencia histórica de conectividad y exposición
│   ├── LINEA_TIEMPO_conectividad.csv      (línea de tiempo consolidada con fecha y hora)
│   ├── redes_conocidas.csv                (primera y última conexión a cada red)
│   ├── accesos_desde_ip_publica.csv       (logons exitosos y fallidos, primera y última vez)
│   ├── direcciones_ip_exposicion.csv      (IP del equipo y clase: privada, pública, IPv6 global)
│   ├── perfiles_de_red_activos.csv
│   ├── puertos_accesibles_y_regla.csv     (puertos expuestos y regla de entrada asociada)
│   ├── firewall_cambios_reglas.csv
│   ├── bits_transferencias.csv, windows_update_eventos.csv
│   └── programas_red_prefetch.csv         (primera y última ejecución aproximada)
├── antivirus/                       <-- Estado de AV/EDR, Defender, exclusiones, logs
└── artefactos/                      <-- SRUM, navegadores, herramientas remotas, hives, AmcacheSRUM, navegadores, herramientas remotas, hives, Amcache
```

### Cómo leer los resultados

1. **`RESUMEN.txt`**: cobertura de logs, usuarios por tipo de logon e IP, software remoto/VPN, conexiones públicas, puertos en escucha, antivirus y PowerShell sospechoso.
2. **`00_cobertura_logs.csv`**: antes de concluir que "no hubo X", comprueba que el log cubre la fecha del incidente. El log Security es circular y por defecto pequeño.
3. **Tipos de logon relevantes:** `10` = RDP, `3` = red, `7` = desbloqueo, `11` = credenciales en caché.
4. **Columna `Inicio`** en las conexiones públicas: hora en que Windows creó la conexión. Solo existe para conexiones **activas en el momento de la captura**.
5. Las horas están en la **zona horaria del equipo** (indicada en la primera línea de `RESUMEN.txt`).

---

## 🛡️ Huella en el sistema y buenas prácticas

La herramienta **no modifica la configuración del sistema ni la evidencia original**, pero ejecutarla no es inocuo. Debes saber que:

- Escribe en la carpeta de salida (por eso debe estar en una unidad externa).
- Crea una **instantánea VSS temporal** para copiar SRUM.
- Genera sus propios rastros: eventos de PowerShell (4103/4104), Prefetch de `powershell.exe`, `reg.exe`, `esentutl.exe` y `wevtutil.exe`, y eventos 4688 si la auditoría de procesos está activa.
- Lee los ejecutables de todos los procesos (para calcular sus hashes) y los historiales de navegador, lo que puede actualizar fechas de último acceso.
- Con `-ResolverInversa`, genera consultas DNS desde el equipo.

Recomendaciones:

- Anota **hora de ejecución, operador, versión y hash** de la herramienta en tu informe, para que sus rastros no se confundan con actividad del incidente.
- Usa una unidad externa **cifrada** (por ejemplo BitLocker To Go): la salida contiene datos sensibles y no se cifra por sí misma.
- Calcula el hash de `MANIFIESTO_SHA256.csv` desde **otro equipo** y guárdalo aparte.
- Si el caso puede escalar a un proceso legal, captura memoria e imagen de disco **antes** de ejecutar el triaje.
- Complementa con fuentes externas al equipo: firewall, proxy, DNS y NetFlow.

---

## ⚠️ Limitaciones conocidas

- **Historial de red:** Windows no registra por defecto las conexiones a internet ni los sitios visitados. Sin auditoría de conexiones (evento 5156), Sysmon o el log DNS Client habilitados *antes* del incidente, solo habrá estado en vivo, SRUM e historial de navegador.
- **Retención de logs:** la evidencia llega hasta donde el log no se haya sobrescrito. El log de sesiones RDP, por ejemplo, puede cubrir apenas horas.
- **PowerShell 4104:** por defecto solo se registran los bloques que Windows considera sospechosos; la ausencia de eventos no prueba que no hubo actividad.
- **VPN y DNS cifrado:** con una VPN activa, los logs de red externos solo ven el túnel; y navegadores con DNS sobre HTTPS no aparecen en la caché DNS de Windows, por lo que algunas IP quedan sin nombre.
- **Antivirus de terceros:** gran parte de su historial (detecciones, cuarentena) está en bases propias que la herramienta no puede leer. Exporta los informes desde la consola del producto.
- **Ausencia de evidencia no es evidencia de ausencia.** Un resultado vacío solo significa que esa fuente no registró nada.
- **Sistemas antiguos:** Windows 7 y Server 2008 R2 no son compatibles (faltan módulos de red, `Get-NetTCPConnection` entre ellos).

---

## 📋 Requisitos y compatibilidad

| Elemento | Detalle |
|---|---|
| **Sistema operativo** | Windows 10 y 11 (cliente). Windows Server 2016 o superior. Server 2012 R2 requiere instalar WMF 5.1 y no está probado |
| **PowerShell** | Windows PowerShell **5.1** (`powershell.exe`). El script incluye alternativas para 5.0, sin probar. PowerShell 7 no está probado |
| **Permisos** | Administrador local |
| **Software adicional** | Ninguno. Usa herramientas nativas (`wevtutil`, `auditpol`, `esentutl`, `reg`) |
| **Red** | No necesita internet ni envía datos a ningún sitio |
| **Espacio** | Varios GB recomendados (logs, SRUM y hives pueden ocupar cientos de MB) |

<!-- TODO: indicar las versiones exactas de Windows en las que se ha probado -->

---

## 🧰 Solución de problemas

| Síntoma | Causa y solución |
|---|---|
| Líneas `[=] ... sin eventos` | Normal: no hay eventos de ese tipo en la ventana indicada |
| Línea `[-] ... ERROR/log no disponible` | El log no existe (p. ej. Sysmon no instalado) o no se pudo leer. Revisa `transcript.txt` |
| "La ejecución de scripts está deshabilitada" | Ejecuta con `-ExecutionPolicy Bypass` o usa el binario |
| El antivirus bloquea o elimina el `.exe` | No lo desactives en el equipo investigado. Solicita que se autorice por hash o usa el `.ps1` |
| "Se requiere ejecutar como administrador" | Abre la consola con **Ejecutar como administrador** |
| Falta `qwinsta` | Ocurre en Windows Home; la herramienta usa CIM como alternativa |
| Secciones de Defender vacías | Defender se desactiva cuando hay otro antivirus activo; es normal |
| Un CSV no existe | Los CSV de eventos solo se crean cuando hay eventos |

---

## 🔐 Verificación de las descargas

Cada release publica los hashes SHA-256 de `Stentor.exe` y `Stentor.ps1` en `SHA256SUMS.txt`. Verifica siempre antes de ejecutar:

```powershell
Get-FileHash .\Stentor.exe -Algorithm SHA256
```

El binario de cada release se compila a partir del `.ps1` incluido en la misma versión.

---

## 🤝 Contribuir y reportar problemas

Los *issues* y *pull requests* son bienvenidos. Para vulnerabilidades, evita publicar detalles en un *issue* abierto y contacta al mantenedor de forma privada. <!-- TODO: agregar contacto o SECURITY.md -->

## 📄 Licencia

Este proyecto se distribuye bajo la Licencia Apache 2.0. Consulta el archivo `LICENSE` para más detalles.

## Descargo de responsabilidad

La herramienta se ofrece "tal cual", sin garantías. El usuario es responsable de contar con la autorización necesaria y de interpretar los resultados dentro de una investigación más amplia.
