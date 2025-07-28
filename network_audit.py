# Network Security Audit Framework (Consolidated Version)
# Framework de auditoría de seguridad de red enfocado en la simplicidad y la exportación a Metasploit.
# Autor: Administrador de Redes y Comunicaciones (Refactorizado por Gemini)

import os
import json
import subprocess
import time
import socket
import ipaddress
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse

# ================================
# CONFIGURACIÓN GLOBAL SIMPLIFICADA
# ================================

class Config:
    """Gestiona la configuración del escaneo desde audit_config.json."""
    def __init__(self, config_file="audit_config.json"):
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                self.data = json.load(f)
        else:
            self.data = self.create_default_config(config_file)
        
        self.create_directories()
    
    def create_default_config(self, config_file):
        """Crea un archivo de configuración por defecto si no existe."""
        print(f"🔧 No se encontró {config_file}. Creando configuración por defecto...")
        default_config = {
            "targets": {
                "ip_range": "192.168.1.0/24",
                "domain": "example.com"
            },
            "scan_options": {
                "top_ports": 1000,
                "stealth_scan": True,
                "service_detection": True,
                "os_detection": True,
                "aggressive_scan": False
            },
            "timing": {
                "timeout": 600 
            }
        }
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=4)
        print(f"✅ Configuración por defecto creada: {config_file}")
        return default_config
    
    def create_directories(self):
        """Crea el directorio de reportes simplificado."""
        os.makedirs("reports", exist_ok=True)
    
    def get(self, key, default=None):
        """Obtiene un valor de la configuración."""
        return self.data.get(key, default)

# ================================
# MÓDULO DE DESCUBRIMIENTO DE HOSTS
# ================================

class HostDiscovery:
    """Descubre hosts activos en el objetivo especificado usando Nmap."""
    def __init__(self, config):
        self.config = config
    
    def run_discovery(self, target):
        """Ejecuta 'nmap -sn' para descubrir hosts y devuelve una lista de IPs."""
        print(f"\n📡 Fase 1: Descubriendo hosts activos en '{target}'...")
        live_hosts = []
        cmd = ["nmap", "-sn", "-T4", target]
        
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, 
                timeout=self.config.get("timing", {}).get("timeout", 300), 
                check=True, encoding='utf-8'
            )
            
            # Extraer IPs de las líneas que reportan un host activo
            for line in result.stdout.splitlines():
                if "Nmap scan report for" in line:
                    # Captura la IP o el dominio y lo añade a la lista
                    ip = line.split("for")[-1].strip().split()[-1].strip("()")
                    live_hosts.append(ip)
            
            live_hosts = sorted(list(set(live_hosts))) # Eliminar duplicados
            if live_hosts:
                print(f"✅ {len(live_hosts)} host(s) activo(s) encontrado(s).")
            else:
                print("⚠️ No se encontraron hosts activos.")

        except FileNotFoundError:
            print("❌ Error: Nmap no está instalado o no se encuentra en el PATH.")
            return []
        except subprocess.TimeoutExpired:
            print("❌ El descubrimiento de hosts con Nmap ha tardado demasiado (timeout).")
        except subprocess.CalledProcessError as e:
            print(f"❌ Error durante el descubrimiento de hosts con Nmap: {e.stderr}")
        except Exception as e:
            print(f"❌ Error inesperado durante el descubrimiento: {str(e)}")

        return live_hosts

# ================================
# MÓDULO DE ESCANEO CONSOLIDADO
# ================================

class ConsolidatedScanner:
    """Realiza un escaneo Nmap en los hosts y genera un único archivo XML."""
    def __init__(self, config):
        self.config = config

    def scan_hosts(self, hosts):
        """Escanea una lista de hosts y guarda los resultados en 'reports/nmap_results.xml'."""
        if not hosts:
            return None

        print(f"\n🔍 Fase 2: Escaneando {len(hosts)} host(s) con Nmap...")
        scan_options = self.config.get("scan_options", {})
        xml_output_file = "reports/nmap_results.xml"
        
        nmap_cmd = ["nmap"]
        if scan_options.get("stealth_scan"): nmap_cmd.append("-sS")
        if scan_options.get("service_detection"): nmap_cmd.extend(["-sV", "-sC"])
        if scan_options.get("os_detection"): nmap_cmd.append("-O")
        if scan_options.get("aggressive_scan"): nmap_cmd.append("-A")
        
        if scan_options.get("top_ports"):
            nmap_cmd.extend(["--top-ports", str(scan_options.get("top_ports"))])
        else:
            nmap_cmd.extend(["-p", scan_options.get("port_range", "1-1000")])
        
        nmap_cmd.extend(["-T4", "-oX", xml_output_file])
        nmap_cmd.extend(hosts)
        
        print(f"   -> Ejecutando: {' '.join(nmap_cmd)}")
        try:
            subprocess.run(
                nmap_cmd, capture_output=True, text=True,
                timeout=self.config.get("timing", {}).get("timeout", 600),
                check=True, encoding='utf-8'
            )
            print(f"✅ Escaneo Nmap completado. Resultados para Metasploit en: {xml_output_file}")
            return xml_output_file
            
        except FileNotFoundError:
            print("❌ Error: Nmap no está instalado o no se encuentra en el PATH.")
        except subprocess.TimeoutExpired:
            print("❌ El escaneo Nmap ha tardado demasiado (timeout).")
        except subprocess.CalledProcessError as e:
            print(f"❌ Error en Nmap: {e.stderr}")
        except Exception as e:
            print(f"❌ Error inesperado durante el escaneo: {str(e)}")
        
        return None

# ================================
# MÓDULO DE REPORTE CONSOLIDADO
# ================================

class AuditReporter:
    """Genera un reporte de texto consolidado a partir del XML de Nmap."""
    def __init__(self, config):
        self.config = config

    def generate_text_report(self, xml_file, target):
        """Parsea el XML de Nmap y crea un reporte de texto legible."""
        if not xml_file or not os.path.exists(xml_file):
            print("⚠️ No se encontró el archivo XML de Nmap para generar el reporte de texto.")
            return

        print("\n📋 Fase 3: Generando reporte de texto consolidado...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_file = f"reports/consolidated_audit_report_{timestamp}.txt"
        
        report_content = f'''
========================================
  INFORME CONSOLIDADO DE AUDITORÍA DE RED
========================================

- Fecha del análisis: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- Objetivo escaneado: {target}
- Archivo de datos Nmap (para Metasploit): {xml_file}

'''
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            hosts_summary = []
            for host_node in root.findall("host"):
                ip_address = host_node.find("address").get("addr")
                
                host_details = f"\n----------------------------------------\n"
                host_details += f"[+] HOST: {ip_address}\n"
                
                # Sistema Operativo
                os_node = host_node.find("os")
                if os_node and os_node.find("osmatch"):
                    os_name = os_node.find("osmatch").get("name", "No detectado")
                    host_details += f"  - Sistema Operativo: {os_name}\n"

                # Puertos
                ports_node = host_node.find("ports")
                open_ports = []
                if ports_node:
                    for port_elem in ports_node.findall("port"):
                        if port_elem.find("state").get("state") == "open":
                            port_id = port_elem.get("portid")
                            service_elem = port_elem.find("service")
                            service_name = service_elem.get("name", "") if service_elem is not None else ""
                            product = service_elem.get("product", "") if service_elem is not None else ""
                            version = service_elem.get("version", "") if service_elem is not None else ""
                            
                            details = f"{product} {version}".strip()
                            port_line = f"    - Puerto {port_id}/tcp: {service_name}"
                            if details:
                                port_line += f" ({details})"
                            open_ports.append(port_line)
                
                if open_ports:
                    host_details += "\n  - Puertos y Servicios:\n"
                    host_details += "\n".join(open_ports) + "\n"
                else:
                    host_details += "\n  - No se encontraron puertos abiertos.\n"
                
                hosts_summary.append(host_details)

            if hosts_summary:
                report_content += "DETALLES POR HOST\n=================\n"
                report_content += "".join(hosts_summary)
            else:
                report_content += "No se encontraron hosts con puertos abiertos para reportar.\n"

            report_content += f'''
========================================
            FIN DEL REPORTE
========================================
'''
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            print(f"✅ Reporte de texto generado: {txt_file}")

        except ET.ParseError as e:
            print(f"❌ Error al parsear el archivo XML de Nmap: {e}")
        except Exception as e:
            print(f"❌ Error inesperado al generar el reporte de texto: {str(e)}")

# ================================
# ORQUESTADOR PRINCIPAL
# ================================

class NetworkSecurityAuditor:
    """Orquesta el flujo completo de la auditoría."""
    def __init__(self, target, config_file="audit_config.json"):
        print("\n🛡️  Iniciando Network Security Audit Framework v3.0 (Modo Consolidado) 🛡️")
        print("======================================================================")
        self.config = Config(config_file)
        self.target = target
        self.host_discovery = HostDiscovery(self.config)
        self.scanner = ConsolidatedScanner(self.config)
        self.reporter = AuditReporter(self.config)

    def run_audit(self):
        start_time = time.time()
        
        # 1. Descubrir hosts
        live_hosts = self.host_discovery.run_discovery(self.target)
        
        if not live_hosts:
            print("\n❌ Auditoría finalizada: No se encontraron hosts activos.")
            return
        
        # 2. Escanear hosts
        nmap_xml_file = self.scanner.scan_hosts(live_hosts)
        
        # 3. Generar reporte de texto
        if nmap_xml_file:
            self.reporter.generate_text_report(nmap_xml_file, self.target)
        
        # Resumen final
        duration = time.time() - start_time
        print("\n======================================================================")
        print(f"✅ AUDITORÍA COMPLETADA EN {duration:.2f} SEGUNDOS")
        print("======================================================================")
        if nmap_xml_file:
            print(f"   -> Para importar en Metasploit, usa el comando:")
            print(f"      db_import {os.path.join(os.getcwd(), nmap_xml_file)}")
            print(f"   -> El reporte de texto ha sido guardado en la carpeta 'reports'.")
        print("======================================================================\n")

# ================================
# PUNTO DE ENTRADA
# ================================

def main():
    """Función principal que maneja la interacción con el usuario."""
    # Crear config por defecto si no existe, para que el usuario pueda verla
    if not os.path.exists("audit_config.json"):
        Config()
        print("\n📝 Edita 'audit_config.json' para ajustar los parámetros del escaneo.")

    print("\nSeleccione el tipo de objetivo a escanear:")
    print("1. Un objetivo específico (IP, dominio o URL)")
    print("2. Un rango de red (definido en audit_config.json)")
    
    choice = input("Ingrese su opción (1 o 2): ")
    
    target = None
    if choice == '1':
        target = input("Ingrese la IP, dominio o URL a escanear: ")
    elif choice == '2':
        try:
            config = Config()
            target = config.get("targets", {}).get("ip_range")
            if not target:
                print("❌ No se ha definido 'ip_range' en audit_config.json")
                return
            print(f"🎯 Usando el rango de red de la configuración: {target}")
        except Exception as e:
            print(f"❌ Error al leer la configuración: {e}")
            return
    else:
        print("Opción no válida. Saliendo.")
        return

    if not target:
        print("No se ha definido un objetivo. Saliendo.")
        return

    try:
        auditor = NetworkSecurityAuditor(target=target)
        auditor.run_audit()
    except KeyboardInterrupt:
        print("\n\n⚠️  Auditoría interrumpida por el usuario.")
    except Exception as e:
        print(f"\n❌ Ocurrió un error crítico durante la auditoría: {str(e)}")

if __name__ == "__main__":
    main()
