# REPOSITORIO DE AUTOMATIZACIÓN DE RED

Este repositorio contiene varios scripts de Python diseñados para la gestión y automatización de dispositivos de red, utilizando la biblioteca `netmiko`, `RegEx`, `pandas` y `concurrent futures`. Está estructurado en diferentes carpetas según los proyectos en los que se utilizan.

## Estructura del Repositorio

### 1. **Cuentas Locales**

Scripts para la gestión de cuentas locales en dispositivos de red de distintos fabricantes:

- **Cisco**: [manage_users_cisco.py](cuentas_locales/manage_users_cisco.py) - Script para regularización de cuentas locales en equipos Cisco.
- **Extreme**: [manage_users_extreme.py](cuentas_locales/manage_users_extreme.py) - Script para regularización de cuentas locales en equipos Extreme.
- **Huawei**: [manage_users_huawei.py](cuentas_locales/manage_users_huawei.py) - Script para regularización de cuentas locales en equipos Huawei.
- **Módulos**: [manage_users_modulos.py](cuentas_locales/manage_users_modulos.py) - Script para la gestión de usuarios en diferentes módulos.
- **HP**: [manage_users_v3_hp.py](cuentas_locales/manage_users_v3_hp.py) - Script para la gestión de usuarios en equipos HP.

### 2. **SNMP**

- **GET**:
  - [get_snmp_cisco.py](snmp/get_snmp_cisco.py) - Script para obtener community SNMP configurado en equipos Cisco.
  - [get_snmp_extreme.py](snmp/get_snmp_extreme.py) - Script para obtener community SNMP configurado en equipos Extreme.
- **SET**:
  - [set_snmp_cisco.py](snmp/set_snmp_cisco.py) - Script para configurar community SNMPv2 `ch1kg0` en equipos Cisco.

### 3. **DNA**

- [license.py](dna/license.py) - Script para obtener licenciamiento de equipos Cisco serie 9000.
- [uptime.py](dna/uptime.py) - Script para obtener el uptime de equipos Cisco.
- [netconf.py](dna/netconf.py) - Script para verificar si el equipo tiene configurado `netconf-yang`.
- [snmp-server-bfco.py](dna/snmp-server-bfco.py) - Script para configurar el servidor SNMP en equipos Cisco.

### 4. **TTO**

- [Trans_to_Ops.py](tto/Trans_to_Ops.py) - Script para la transición de operaciones en equipos Cisco.

## Configuración de un Entorno Virtual (venv) e Instalación de Dependencias

### Paso 1: Crear un Entorno Virtual

1. Abre una terminal en la raíz de tu proyecto.
2. Ejecuta el siguiente comando para crear un entorno virtual llamado `campus`:

```bash
python -m venv campus
```

### Paso 2: Activar el Entorno Virtual

##### En Windows

Ejecuta el siguiente comando para activar el entorno virtual:

```bash
.\venv\Scripts\activate
```

#### En macOS/Linux

Ejecuta el siguiente comando para activar el entorno virtual:

```bash
source venv/bin/activate
```

### Paso 3: Instalar Dependencias

1. Asegúrate de tener un archivo `requirements.txt` en la raíz de tu proyecto con las dependencias necesarias.

2. Con el entorno virtual activado, ejecuta el siguiente comando para instalar las dependencias:

```bash
pip install -r requirements.txt
```

### Paso 4: Carpetas adicionales

- Crea la carpeta `Files` dentro de la raíz o carpeta principal, en ella se almacenarán los archivos en formato `.xlsx` que leerá el script.
- Crea la carpeta `session_logs` dentro de raíz o carpeta principal, en ella se almacenarán logs de conexión sobre los dispositivos que se ejecuta el script.
- Crea la carpeta `Results` dentro de la raíz o carpeta principal, en ella se almacenarán los archivos exporatados de los scripts en formato `.xlsx`.
