#  SOC Junior Learning Path: Triaje y Mentalidad Operativa

Este repositorio documenta el desarrollo de competencias prácticas y metodológicas para roles de **SOC Analyst (Tier 1 / Junior)**, centrándose en el análisis crítico, la correlación de telemetría y la toma de decisiones defensivas ante anomalías en sistemas corporativos.

---

##  Enfoque Metodológico
* **Diferenciación Operativa:** Transición desde el registro sin procesar (**Evento**) hasta la evaluación de riesgo (**Alerta**) y la confirmación de impacto (**Incidente**).
* **Triaje Estructurado:** Análisis de hipótesis, descarte de falsos positivos habituales (credenciales cacheadas, tareas de mantenimiento) y criterios técnicos de contención y escalado.
* **Telemetría Multifuente:** Correlación entre registros locales de Windows (`Security.evtx`, `System.evtx`), inspección de sockets activos y resolución/caché de DNS.

---

##  Contenido del Proyecto
* **[`soc-junior-first-cases.md`](./soc-junior-first-cases.md):** Documentación técnica de 5 casos prácticos analizados bajo un formato estándar de triaje (descripción, ubicación, evidencias, riesgo, primer análisis y condiciones de escalado).
* **`assets/`:** Capturas de pantalla con las evidencias técnicas obtenidas en el laboratorio.
