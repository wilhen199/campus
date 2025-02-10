# Repositorio de Automatización de Red

Este repositorio contiene varios scripts de Python diseñados para la gestión y automatización de dispositivos de red, utilizando la biblioteca `netmiko`, `RegEx`, `pandas` y `concurrent futures`. Está estructurado en diferentes carpetas según los proyectos en los que se utilizan.

## Estructura del Repositorio

### 1. **Cuentas Locales**

Scripts para la gestión de cuentas locales en dispositivos de red de distintos fabricantes:

- **Cisco**: Script para regularización de cuentas locales en equipos Cisco.
- **Extreme**: Script para regularización de cuentas locales en equipos Extreme.
- **Huawei**: Script para regularización de cuentas locales en equipos Huawei.

### 2. **SNMP**

- **GET**: Scripts para hacer obtener community snmp configurado.
- **SET**: Scripts para configurar community snmpv2 `ch1kg0` en los equipos (en progreso).

### 3. **DNA**

- Script para obtener licenciamiento de equipos Cisco serie 9000
- Script para obtener uptime de equipos Cisco.
- Script para obtener si el equipo tiene configurado `netconf-yang`

## Requisitos

Para ejecutar los scripts, asegúrate de tener instalado Python y las siguientes bibliotecas:

```bash
pip install netmiko paramiko pandas re
```
