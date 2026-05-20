# REPORTE TÉCNICO - JAMELL ANANGONO
Estudiante: Jamell Anangono
Usuario: jamell
Hostname: copy-fail-vm

## Análisis del CVE-2026-31431 y mitigación
El exploit ataca el módulo algif_aead aprovechando una vulnerabilidad de corrupción en el page cache mediante la llamada de sistema splice. Esto permite que un usuario común manipule la memoria del sistema y ataque binarios con permisos setuid (como /usr/bin/su) para escalar privilegios y obtener una shell de root. Al remover el módulo con rmmod se aplica una mitigación temporal, mientras que el parche definitivo separa los SGL de transmisión (TX) y recepción (RX).
