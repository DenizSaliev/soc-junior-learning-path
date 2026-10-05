#  Casos Prácticos de Triaje y Análisis Inicial: SOC Junior

##  Objetivo
El propósito de este laboratorio es desarrollar el criterio y la metodología analítica de un perfil **SOC Junior (Nivel 1)** ante alertas frecuentes de seguridad. Se evalúa la procedencia de los datos, el contraste de hipótesis para descartar falsos positivos y la justificación técnica necesaria para escalar un incidente hacia equipos de respuesta especializada (Tier 2 / DFIR).

##  Entorno de Laboratorio
* **Sistemas implicados:** Controlador de Dominio Windows Server (`WS-25-DC-1-DOM1`) y estación cliente Windows 11 (`WIN11-CLIENTE`).
* **Alcance:** Segmento virtual privado aislado (Host-Only). Pruebas y generación de eventos realizadas bajo autorización expresa con fines formativos.

---

##  Resumen Forense de Casos

| Caso / Escenario | Origen de Telemetría | Evidencia Primaria | Riesgo Potencial Evaluado | Criterio Clave de Descarte (FP) |
| :--- | :--- | :--- | :--- | :--- |
| **1. Intentos fallidos de login** | `Security.evtx` (Cliente / DC) | Event ID 4625 (`Substatus: 0xC000006A`) | Ataque de fuerza bruta / Password spraying | Dispositivo móvil o script con clave antigua en caché |
| **2. Usuario creado** | `Security.evtx` (DC) | Event ID 4720 (`TargetUserName`) | Persistencia o cuenta puente (*backdoor*) | Existencia de ticket aprobado de Recursos Humanos / TI |
| **3. Servicio sospechoso activo** | `System.evtx` (Endpoint) | Event ID 7045 (`ImagePath: \Users\Public`) | Persistencia con privilegios de sistema (`SYSTEM`) | Software de gestión o soporte desplegado legítimamente |
| **4. Puerto inesperado abierto** | Sockets de red (Host / Nmap) | TCP `0.0.0.0:4444` en `LISTENING` (PID) | Shell reversa a la escucha (*bind shell*) | Servicio de desarrollo local vinculado exclusivamente a `127.0.0.1` |
| **5. Conexión a dominio externo** | Cliente DNS / Proxy / Sockets| Registros DNS (`A`/`AAAA`), HTTP 200 saliente | Balizamiento C2 (*Command & Control*) / Exfiltración | Tráfico generado por navegador estándar hacia CDN/web conocida |

---

##  Análisis Detallado de Escenarios

### Caso 1: Intentos fallidos de login
* **Qué ha pasado:** Se han registrado múltiples intentos consecutivos de inicio de sesión con contraseña errónea contra una cuenta de dominio.
* **Dónde lo detecto:** En el Visor de Eventos del cliente (`WIN11-CLIENTE`), registro de **Seguridad**, bajo el **Event ID 4625** (y en el DC mediante el **Event ID 4740** si se dispara el bloqueo por política GPO).
* **Qué evidencia tengo:**
  * Marca temporal exacta de los intentos fallidos.
  * Cuenta objetivo: `TargetUserName: deniz.auditor`.
  * Estación origen: `WorkstationName: WIN11-CLIENTE`.
  * Diagnóstico de subestado: `Substatus: 0xC000006A` (contraseña incorrecta).
* **Qué riesgo podría tener:** Ataque de fuerza bruta en línea, prueba masiva de contraseñas o denegación de servicio interna por bloqueo sistemático de identidades legítimas.
* **Qué haría como primer análisis:** Analizar la frecuencia temporal de los registros (diferenciar cadencias en milisegundos de acciones manuales de un usuario), verificar si el empleado cambió su contraseña recientemente y mantiene aplicaciones desactualizadas en segundo plano, y contactar con el titular mediante un canal corporativo alternativo.
* **Cuándo lo escalaría:** Si la dirección IP origen es externa o no reconocida, si los ataques van dirigidos a cuentas privilegiadas (`Administrator`, `Domain Admins`), o si inmediatamente después de los fallos se genera un **Event ID 4624** (inicio exitoso) desde el mismo origen sin justificación del usuario.

> ![Evidencia Caso 1](./assets/escenario1_login_fallido.png)

---

### Caso 2: Usuario creado
* **Qué ha pasado:** Se ha registrado el alta de una nueva cuenta de usuario en el Directorio Activo de forma directa.
* **Dónde lo detecto:** En el registro de **Seguridad** del Controlador de Dominio (`WS-25-DC-1-DOM1`), mediante el **Event ID 4720** (*A user account was created*).
* **Qué evidencia tengo:**
  * Nombre de la cuenta creada: `TargetUserName: temp.support`.
  * Identidad responsable de la creación: `SubjectUserName: Administrador`.
  * Fecha, hora exacta y SID del nuevo objeto en el dominio.
* **Qué riesgo podría tener:** Establecimiento de persistencia secundaria tras el compromiso de credenciales administrativas o incumplimiento de procedimientos formales de gobierno de identidades.
* **Qué haría como primer análisis:** Contrastar el identificador del creador con el sistema de gestión de incidencias/solicitudes (ITSM) para verificar si existe un ticket autorizado de alta, y revisar de forma inmediata si se registraron eventos posteriores de inclusión en grupos administrativos (**Event IDs 4728 / 4732**).
* **Cuándo lo escalaría:** Si no existe registro administrativo que respalde la creación, si el evento ocurre fuera del horario operativo sin notificación previa, o si la cuenta nueva recibe privilegios de administración local o de dominio.

> ![Evidencia Caso 2](./assets/escenario2_usuario_creado.png)

---

### Caso 3: Servicio sospechoso activo
* **Qué ha pasado:** Se ha instalado un nuevo servicio en el sistema operativo cuya ruta binaria apunta a un directorio público no estándar].
* **Dónde lo detecto:** En el Visor de Eventos del endpoint (`WIN11-CLIENTE`), dentro del registro de **Sistema**, mediante el **Event ID 7045** (*A service was installed in the system*) originado por el *Service Control Manager*.
* **Qué evidencia tengo:**
  * Nombre del servicio: `Service Name: WinUpdateChecker`.
  * Ruta del ejecutable: `ImagePath: C:\Users\Public\update.exe`.
  * Nivel de privilegios del servicio: `LocalSystem`.
* **Qué riesgo podría tener:** Persistencia de malware con los máximos privilegios locales del sistema operativo, ejecución automática en el arranque o presencia de puertas traseras.
* **Qué haría como primer análisis:** Localizar el ejecutable en disco, calcular su hash SHA-256 (`Get-FileHash`), contrastarlo en plataformas de inteligencia de amenazas (VirusTotal) y verificar si cuenta con una firma digital corporativa válida.
* **Cuándo lo escalaría:** Si el binario carece de firma legítima, arroja coincidencias maliciosas en bases de firmas o se detecta que el proceso asociado intenta iniciar conexiones de red hacia el exterior.

> ![Evidencia Caso 3](./assets/escenario3_servicio_sospechoso.png)

---

### Caso 4: Puerto inesperado abierto
* **Qué ha pasado:** El host mantiene un puerto de red en estado de escucha (`LISTENING`) sin relación con las funciones normales del equipo.
* **Dónde lo detecto:** Mediante auditoría local de sockets con herramientas del sistema operativo (`netstat -ano`) o mediante escaneo defensivo de red con Nmap.
* **Qué evidencia tengo:**
  * Socket activo: `0.0.0.0:4444` (accesible en todas las interfaces de red).
  * Protocolo: `TCP`.
  * Proceso y contexto: Identificador de proceso `PID: 9272` correspondiente al intérprete de comandos en memoria.
* **Qué riesgo podría tener:** Exposición de una interfaz remota no autorizada (*listener* para shells interactivas), vector de explotación remota y ampliación de la superficie de ataque del puesto.
* **Qué haría como primer análisis:** Identificar el binario y la línea de comandos completa vinculada al PID mediante el Administrador de Tareas o PowerShell (`Get-Process -Id 9272`), determinar si el puerto recibe conexiones externas y verificar la directiva del firewall de host.
* **Cuándo lo escalaría:** Si el proceso corresponde a herramientas de administración remota no estándar, scripts no autorizados, o si se aprecian conexiones activas establecidas desde IPs no corporativas.

> ![Evidencia Caso 4](./assets/escenario4_puerto_abierto.png)

---

### Caso 5: Conexión a dominio externo
* **Qué ha pasado:** El sistema ha ejecutado una consulta de resolución de nombres y un establecimiento de canal HTTP saliente hacia un destino público externo.
* **Dónde lo detecto:** En el resolvedor local del sistema operativo (`Resolve-DnsName`, `Get-DnsClientCache`), en registros de proxy/firewall de salida perimetral o mediante telemetría de consultas DNS (Sysmon Event ID 22).
* **Qué evidencia tengo:**
  * Dominio consultado y registros resueltos: `example.com` (`A`: `172.66.147.243`, `104.20.23.154`).
  * Solicitud saliente: `curl.exe` recibiendo cabecera de confirmación `HTTP/1.1 200 OK`.
  * Marca de tiempo y equipo emisor (`WIN11-CLIENTE`).
* **Qué riesgo podría tener:** Tráfico de control de malware (*C2 beaconing*), descarga de módulos secundarios (*payload stagers*) o potencial fuga de información.
* **Qué haría como primer análisis:** Consultar la reputación, categorización y fecha de registro del dominio en plataformas OSINT (VirusTotal, Whois, AbuseIPDB), inspeccionar qué proceso inició la llamada a la red (diferenciar un navegador web de utilidades de consola o scripts) y revisar si existen patrones de reintento periódicos con intervalos fijos (*jitter*).
* **Cuándo lo escalaría:** Si el dominio muestra reputación maliciosa confirmada, si la comunicación es originada por binarios del sistema anómalos (como `powershell.exe` o `rundll32.exe`) sin interacción de usuario, o si se detecta transferencia sostenida de datos hacia el destino.

> ![Evidencia Caso 5](./assets/escenario5_conexion_externa.png)
