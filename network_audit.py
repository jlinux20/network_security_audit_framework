# Network Security Audit Framework
# Framework de auditoría de seguridad de red enfocado en análisis y detección
# Autor: Administrador de Redes y Comunicaciones

import os
import json
import subprocess
import time
import threading
import socket
import ssl
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import re
from urllib.parse import urljoin, urlparse

# ================================
# CONFIGURACIÓN GLOBAL
# ================================

class Config:
    def __init__(self, config_file="audit_config.json"):
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                self.data = json.load(f)
        else:
            self.create_default_config(config_file)
            with open(config_file, 'r') as f:
                self.data = json.load(f)
        
        self.create_directories()
    
    def create_default_config(self, config_file):
        """Crear configuración por defecto"""
        default_config = {
            "targets": {
                "single_ip": "192.168.1.1",
                "ip_range": "192.168.1.0/24",
                "domain": "example.com",
                "url": "https://example.com"
            },
            "scan_options": {
                "port_range": "1-65535",
                "top_ports": 1000,
                "aggressive_scan": False,
                "stealth_scan": True,
                "service_detection": True,
                "os_detection": True,
                "vulnerability_scan": True,
                "ssl_scan": True
            },
            "timing": {
                "scan_delay": 0,
                "timeout": 300,
                "max_retries": 2,
                "threads": 50
            },
            "wordlists": {
                "directories": "/usr/share/wordlists/dirb/common.txt",
                "subdomains": "/usr/share/wordlists/subdomains-top1million-5000.txt",
                "passwords": "/usr/share/wordlists/rockyou.txt"
            },
            "output": {
                "format": ["json", "html", "txt"],
                "detailed_reports": True,
                "screenshots": False
            }
        }
        
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        print(f"✅ Configuración por defecto creada: {config_file}")
    
    def create_directories(self):
        """Crear estructura de directorios"""
        directories = [
            "reports/json",
            "reports/html", 
            "reports/txt",
            "evidence/nmap",
            "evidence/ssl",
            "evidence/web",
            "evidence/vulnerabilities",
            "logs"
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def get(self, key, default=None):
        return self.data.get(key, default)

# ================================
# UTILIDADES DE RED
# ================================

class NetworkUtils:
    @staticmethod
    def validate_ip(ip):
        """Validar dirección IP"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def resolve_hostname(hostname):
        """Resolver hostname a IP"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
    
    @staticmethod
    def validate_network(network):
        """Validar rango de red"""
        try:
            ipaddress.ip_network(network, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def get_network_hosts(network):
        """Obtener hosts de una red"""
        try:
            net = ipaddress.ip_network(network, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            return []
    
    @staticmethod
    def is_port_open(host, port, timeout=3):
        """Verificar si un puerto está abierto"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except:
            return False

# ================================
# MÓDULO DE DESCUBRIMIENTO DE HOSTS
# ================================

class HostDiscovery:
    def __init__(self, config):
        self.config = config
        self.results = {
            "live_hosts": [],
            "host_details": {}
        }
    
    def log_action(self, action, result=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("logs/host_discovery.log", "a") as f:
            f.write(f"[{timestamp}] {action}: {result}\n")
    
    def ping_sweep(self, target_range):
        """Barrido de ping para descubrir hosts activos"""
        print(f"🔍 Realizando ping sweep en {target_range}...")
        
        if not NetworkUtils.validate_network(target_range):
            print(f"❌ Rango de red inválido: {target_range}")
            return []
        
        hosts = NetworkUtils.get_network_hosts(target_range)
        live_hosts = []
        
        def ping_host(host):
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", host],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return host
            except:
                pass
            return None
        
        # Ping en paralelo
        threads_config = self.config.get("timing")
        if isinstance(threads_config, int):
            max_threads = threads_config
        elif isinstance(threads_config, dict):
            max_threads = threads_config.get("threads", 50)
        else:
            max_threads = 50

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(ping_host, host) for host in hosts[:254]]  # Limitar a /24
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)
                    print(f"✅ Host activo encontrado: {result}")
        
        self.results["live_hosts"] = live_hosts
        self.log_action("Ping sweep", f"{len(live_hosts)} hosts activos encontrados")
        return live_hosts
    
    def nmap_host_discovery(self, target):
        """Descubrimiento avanzado con Nmap"""
        print(f"🔍 Descubrimiento de hosts con Nmap: {target}...")
        
        output_file = "evidence/nmap/host_discovery.txt"
        cmd = f"nmap -sn {target}"
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            
            with open(output_file, "w") as f:
                f.write(result.stdout)
            
            # Extraer IPs del resultado
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            found_ips = re.findall(ip_pattern, result.stdout)
            
            self.results["live_hosts"].extend(found_ips)
            self.results["live_hosts"] = list(set(self.results["live_hosts"]))
            
            self.log_action("Nmap host discovery", f"Guardado en {output_file}")
            
        except subprocess.TimeoutExpired:
            self.log_action("Nmap host discovery", "Timeout")
    
    def run_discovery(self, target):
        """Ejecutar descubrimiento completo"""
        print("🚀 Iniciando descubrimiento de hosts...")
        
        # Validar si es un rango de red
        if NetworkUtils.validate_network(target):
            self.ping_sweep(target)
            self.nmap_host_discovery(target)
        # Validar si es una IP
        elif NetworkUtils.validate_ip(target):
            self.results["live_hosts"] = [target]
        # Intentar resolver como hostname o extraer de URL
        else:
            hostname = target
            if "://" in target:
                hostname = urlparse(target).hostname
            
            ip = NetworkUtils.resolve_hostname(hostname)
            if ip:
                print(f"✅ Dominio/URL '{target}' resuelto a: {ip}")
                self.results["live_hosts"] = [ip]
            else:
                print(f"❌ No se pudo resolver el objetivo: {target}")

        return self.results["live_hosts"]

# ================================
# MÓDULO DE ESCANEO DE PUERTOS
# ================================

class PortScanner:
    def __init__(self, config):
        self.config = config
        self.results = {}
    
    def log_action(self, action, result=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("logs/port_scan.log", "a") as f:
            f.write(f"[{timestamp}] {action}: {result}\n")
    
    def nmap_comprehensive_scan(self, host):
        """Escaneo completo con Nmap"""
        print(f"🔍 Escaneo completo de puertos: {host}...")
        
        scan_options = self.config.get("scan_options", {})
        
        # Configurar comando Nmap
        nmap_cmd = ["nmap"]
        
        # Tipo de escaneo
        if scan_options.get("stealth_scan", True):
            nmap_cmd.append("-sS")
        else:
            nmap_cmd.append("-sT")
        
        # Detección de servicios y versiones
        if scan_options.get("service_detection", True):
            nmap_cmd.extend(["-sV", "-sC"])
        
        # Detección de OS
        if scan_options.get("os_detection", True):
            nmap_cmd.append("-O")
        
        # Escaneo agresivo
        if scan_options.get("aggressive_scan", False):
            nmap_cmd.append("-A")
        
        # Puertos
        if scan_options.get("top_ports"):
            nmap_cmd.extend(["--top-ports", str(scan_options.get("top_ports", 1000))])
        else:
            nmap_cmd.extend(["-p", scan_options.get("port_range", "1-1000")])
        
        # Timing
        nmap_cmd.extend(["-T4", "--max-retries", "2"])
        
        # Output
        xml_output_file = f"evidence/nmap/scan_{host.replace('.', '_')}.xml"
        txt_output_file = f"evidence/nmap/scan_{host.replace('.', '_')}.txt"
        
        nmap_cmd.extend(["-oX", xml_output_file, "-oN", txt_output_file])
        nmap_cmd.append(host)
        
        try:
            print(f"Ejecutando: {' '.join(nmap_cmd)}")
            subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get("timing", {}).get("timeout", 300),
                check=True
            )
            
            self.results[host] = {
                "scan_file_xml": xml_output_file,
                "scan_file_txt": txt_output_file,
                "scan_completed": True
            }
            
            # Parsear resultados desde el XML
            self._parse_xml_output(host, xml_output_file)
            
            self.log_action(f"Nmap scan {host}", f"Completado - {xml_output_file}")
            
        except subprocess.TimeoutExpired:
            self.log_action(f"Nmap scan {host}", "Timeout")
            self.results[host] = {"scan_completed": False, "error": "Timeout"}
        except subprocess.CalledProcessError as e:
            self.log_action(f"Nmap scan {host}", f"Error: {e.stderr}")
            self.results[host] = {"scan_completed": False, "error": e.stderr}
        except Exception as e:
            self.log_action(f"Nmap scan {host}", f"Error: {str(e)}")
            self.results[host] = {"scan_completed": False, "error": str(e)}

    def _parse_xml_output(self, host, xml_file):
        """Parsear el output XML de Nmap para extraer información detallada."""
        if host not in self.results:
            self.results[host] = {}
        
        self.results[host]["open_ports"] = []
        
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            host_node = root.find("host")
            if host_node is None:
                return

            # Extraer puertos abiertos
            ports_node = host_node.find("ports")
            if ports_node is not None:
                for port_elem in ports_node.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is not None and state_elem.get("state") == "open":
                        service_elem = port_elem.find("service")
                        port_info = {
                            "port": int(port_elem.get("portid")),
                            "service": service_elem.get("name", "unknown") if service_elem is not None else "unknown",
                            "product": service_elem.get("product", "") if service_elem is not None else "",
                            "version": service_elem.get("version", "") if service_elem is not None else "",
                            "extrainfo": service_elem.get("extrainfo", "") if service_elem is not None else ""
                        }
                        self.results[host]["open_ports"].append(port_info)

            # Extraer información del Sistema Operativo
            os_node = host_node.find("os")
            if os_node is not None:
                osmatch_elem = os_node.find("osmatch")
                if osmatch_elem is not None:
                    self.results[host]["os"] = osmatch_elem.get("name", "Unknown")

        except ET.ParseError as e:
            self.log_action(f"XML Parse Error {host}", f"Failed to parse {xml_file}: {e}")
        except FileNotFoundError:
            self.log_action(f"XML Parse Error {host}", f"File not found: {xml_file}")

    def masscan_fast_scan(self, host):
        """Escaneo rápido con Masscan (si está disponible)"""
        print(f"⚡ Escaneo rápido con Masscan: {host}...")
        
        output_file = f"evidence/nmap/masscan_{host.replace('.', '_')}.txt"
        port_range = self.config.get("scan_options", {}).get("port_range", "1-1000")
        
        cmd = f"masscan {host} -p{port_range} --rate=1000 -oG {output_file}"
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                self.log_action(f"Masscan {host}", f"Completado - {output_file}")
                if host not in self.results:
                    self.results[host] = {}
                self.results[host]["masscan_file"] = output_file
            
        except subprocess.TimeoutExpired:
            self.log_action(f"Masscan {host}", "Timeout")
        except FileNotFoundError:
            self.log_action(f"Masscan {host}", "Masscan no disponible")
    
    def scan_hosts(self, hosts):
        """Escanear múltiples hosts"""
        for host in hosts:
            print(f"\n{'='*50}")
            print(f"🎯 Escaneando host: {host}")
            print(f"{'='*50}")
            
            self.nmap_comprehensive_scan(host)
            
            # Escaneo rápido adicional si está habilitado
            if self.config.get("scan_options", {}).get("fast_scan", False):
                self.masscan_fast_scan(host)
            
            time.sleep(1)  # Pequeña pausa entre hosts
        
        return self.results

# ================================
# MÓDULO DE ANÁLISIS DE SERVICIOS
# ================================

class ServiceAnalyzer:
    def __init__(self, config):
        self.config = config
        self.results = {}
        self.vulnerabilities = []
    
    def log_action(self, action, result=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("logs/service_analysis.log", "a") as f:
            f.write(f"[{timestamp}] {action}: {result}\n")
    
    def analyze_web_services(self, host, port):
        """Análisis de servicios web"""
        print(f"🌐 Analizando servicio web en {host}:{port}...")
        
        schemes = ['http', 'https'] if port in [80, 443, 8080, 8443] else ['http']
        
        for scheme in schemes:
            url = f"{scheme}://{host}:{port}"
            
            try:
                # Headers y tecnologías
                response = requests.get(url, timeout=10, verify=False)
                
                web_info = {
                    "url": url,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "server": response.headers.get('Server', ''),
                    "technologies": []
                }
                
                # Detectar tecnologías por headers
                server_header = response.headers.get('Server', '').lower()
                x_powered_by = response.headers.get('X-Powered-By', '').lower()
                
                if 'apache' in server_header:
                    web_info["technologies"].append(f"Apache/{server_header}")
                if 'nginx' in server_header:
                    web_info["technologies"].append(f"Nginx/{server_header}")
                if 'php' in x_powered_by:
                    web_info["technologies"].append(f"PHP/{x_powered_by}")
                
                # WhatWeb si está disponible
                whatweb_file = f"evidence/web/whatweb_{host}_{port}.txt"
                whatweb_cmd = f"whatweb -v {url}"
                
                try:
                    whatweb_result = subprocess.run(
                        whatweb_cmd, 
                        shell=True, 
                        capture_output=True, 
                        text=True, 
                        timeout=30
                    )
                    
                    with open(whatweb_file, "w") as f:
                        f.write(whatweb_result.stdout)
                    
                    web_info["whatweb_file"] = whatweb_file
                    
                except:
                    pass
                
                if host not in self.results:
                    self.results[host] = {}
                self.results[host][f"web_{port}"] = web_info
                
                self.log_action(f"Web analysis {host}:{port}", f"Completado - {url}")
                
            except Exception as e:
                self.log_action(f"Web analysis {host}:{port}", f"Error: {str(e)}")
    
    def analyze_ssl_services(self, host, port):
        """Análisis de servicios SSL/TLS"""
        print(f"🔒 Analizando SSL/TLS en {host}:{port}...")
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    ssl_info = {
                        "certificate": cert,
                        "cipher": cipher,
                        "tls_version": version,
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter')
                    }
                    
                    # Testssl.sh si está disponible
                    testssl_file = f"evidence/ssl/testssl_{host}_{port}.txt"
                    testssl_cmd = f"testssl.sh --quiet {host}:{port}"
                    
                    try:
                        testssl_result = subprocess.run(
                            testssl_cmd,
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=120
                        )
                        
                        with open(testssl_file, "w") as f:
                            f.write(testssl_result.stdout)
                        
                        ssl_info["testssl_file"] = testssl_file
                        
                    except:
                        pass
                    
                    if host not in self.results:
                        self.results[host] = {}
                    self.results[host][f"ssl_{port}"] = ssl_info
                    
                    self.log_action(f"SSL analysis {host}:{port}", "Completado")
                    
        except Exception as e:
            self.log_action(f"SSL analysis {host}:{port}", f"Error: {str(e)}")
    
    def vulnerability_scan(self, host):
        """Escaneo de vulnerabilidades con Nmap NSE"""
        print(f"🔍 Escaneando vulnerabilidades en {host}...")
        
        vuln_output = f"evidence/vulnerabilities/vulns_{host.replace('.', '_')}.txt"
        
        # Scripts de vulnerabilidades comunes
        vuln_scripts = [
            "vuln",
            "smb-vuln*",
            "ssl-*",
            "http-vuln*",
            "ftp-vuln*",
            "ssh-*"
        ]
        
        for script_category in vuln_scripts:
            cmd = f"nmap --script {script_category} {host} -oN {vuln_output}_{script_category.replace('*', 'all')}"
            
            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=180
                )
                
                # Parsear vulnerabilidades encontradas
                self.parse_vulnerabilities(host, result.stdout)
                
                self.log_action(f"Vuln scan {script_category} {host}", "Completado")
                
            except subprocess.TimeoutExpired:
                self.log_action(f"Vuln scan {script_category} {host}", "Timeout")
            except Exception as e:
                self.log_action(f"Vuln scan {script_category} {host}", f"Error: {str(e)}")
    
    def parse_vulnerabilities(self, host, nmap_output):
        """Parsear vulnerabilidades del output de Nmap"""
        vuln_patterns = [
            r'VULNERABLE:',
            r'CVE-\d{4}-\d{4,}',
            r'CRITICAL',
            r'HIGH',
            r'MEDIUM'
        ]
        
        lines = nmap_output.split('\n')
        current_vuln = None
        
        for line in lines:
            for pattern in vuln_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vuln_info = {
                        "host": host,
                        "description": line.strip(),
                        "severity": "Unknown",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    # Determinar severidad
                    if re.search(r'CRITICAL', line, re.IGNORECASE):
                        vuln_info["severity"] = "Critical"
                    elif re.search(r'HIGH', line, re.IGNORECASE):
                        vuln_info["severity"] = "High"
                    elif re.search(r'MEDIUM', line, re.IGNORECASE):
                        vuln_info["severity"] = "Medium"
                    elif re.search(r'LOW', line, re.IGNORECASE):
                        vuln_info["severity"] = "Low"
                    
                    self.vulnerabilities.append(vuln_info)
                    break
    
    def analyze_services(self, port_scan_results):
        """Análisis completo de servicios"""
        print("\n🔬 Iniciando análisis de servicios...")
        
        for host, host_data in port_scan_results.items():
            if "open_ports" in host_data:
                print(f"\n📊 Analizando servicios en {host}...")
                
                for port_info in host_data["open_ports"]:
                    port = port_info["port"]
                    service = port_info["service"]
                    
                    # Análisis web
                    if service.lower() in ['http', 'https', 'http-proxy', 'ssl/http'] or port in [80, 443, 8080, 8443, 8000, 8888]:
                        self.analyze_web_services(host, port)
                    
                    # Análisis SSL
                    if port in [443, 993, 995, 465, 636, 8443] or 'ssl' in service.lower():
                        self.analyze_ssl_services(host, port)
                
                # Escaneo de vulnerabilidades por host
                if self.config.get("scan_options", {}).get("vulnerability_scan", True):
                    self.vulnerability_scan(host)
        
        return self.results

# ================================
# MÓDULO DE REPORTES
# ================================

class AuditReporter:
    def __init__(self, config):
        self.config = config
        self.report_data = {}
    
    def collect_all_data(self, hosts, port_results, service_results, vulnerabilities, target):
        """Recopilar todos los datos del audit"""
        self.report_data = {
            "scan_info": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target": target,
                "scan_options": self.config.get("scan_options", {}),
                "total_hosts": len(hosts),
                "total_vulnerabilities": len(vulnerabilities)
            },
            "hosts": hosts,
            "port_scan_results": port_results,
            "service_analysis": service_results,
            "vulnerabilities": vulnerabilities
        }
    
    def generate_json_report(self):
        """Generar reporte en formato JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = f"reports/json/network_audit_{timestamp}.json"
        
        with open(json_file, 'w') as f:
            json.dump(self.report_data, f, indent=2, default=str)
        
        print(f"📄 Reporte JSON generado: {json_file}")
        return json_file
    
    def generate_html_report(self):
        """Generar reporte HTML"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_file = f"reports/html/network_audit_{timestamp}.html"
        
        # Contar estadísticas
        total_hosts = len(self.report_data["hosts"])
        total_open_ports = sum(
            len(host_data.get("open_ports", [])) 
            for host_data in self.report_data["port_scan_results"].values()
        )
        total_vulnerabilities = len(self.report_data["vulnerabilities"])
        
        # Severidad de vulnerabilidades
        vuln_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        for vuln in self.report_data["vulnerabilities"]:
            severity = vuln.get("severity", "Unknown")
            vuln_severity[severity] += 1
        
        html_content = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: #f8f9ff; padding: 15px; border-radius: 8px; border-left: 4px solid #667eea; }}
        .stat-number {{ font-size: 24px; font-weight: bold; color: #667eea; }}
        .host-section {{ margin-bottom: 30px; padding: 20px; background: #fafafa; border-radius: 8px; }}
        .port-table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        .port-table th, .port-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        .port-table th {{ background-color: #667eea; color: white; }}
        .vuln-critical {{ background-color: #ffebee; border-left: 4px solid #f44336; }}
        .vuln-high {{ background-color: #fff3e0; border-left: 4px solid #ff9800; }}
        .vuln-medium {{ background-color: #f3e5f5; border-left: 4px solid #9c27b0; }}
        .vuln-low {{ background-color: #e8f5e8; border-left: 4px solid #4caf50; }}
        .service-info {{ background: #e3f2fd; padding: 10px; border-radius: 4px; margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Network Security Audit Report</h1>
            <p><strong>Fecha:</strong> {self.report_data["scan_info"]["timestamp"]}</p>
            <p><strong>Objetivo:</strong> {self.report_data["scan_info"]["target"]}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{total_hosts}</div>
                <div>Hosts Analizados</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_open_ports}</div>
                <div>Puertos Abiertos</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_vulnerabilities}</div>
                <div>Vulnerabilidades</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{vuln_severity['Critical'] + vuln_severity['High']}</div>
                <div>Críticas/Altas</div>
            </div>
        </div>
        
        <h2>📊 Resumen de Vulnerabilidades por Severidad</h2>
        <div class="stats">
            <div class="stat-card vuln-critical">
                <div class="stat-number">{vuln_severity['Critical']}</div>
                <div>Críticas</div>
            </div>
            <div class="stat-card vuln-high">
                <div class="stat-number">{vuln_severity['High']}</div>
                <div>Altas</div>
            </div>
            <div class="stat-card vuln-medium">
                <div class="stat-number">{vuln_severity['Medium']}</div>
                <div>Medias</div>
            </div>
            <div class="stat-card vuln-low">
                <div class="stat-number">{vuln_severity['Low']}</div>
                <div>Bajas</div>
            </div>
        </div>
        
        <h2>🎯 Detalles por Host</h2>
        """
        
        # Agregar detalles de cada host
        for host in self.report_data["hosts"]:
            host_data = self.report_data["port_scan_results"].get(host, {})
            service_data = self.report_data["service_analysis"].get(host, {})
            
            html_content += f"""
        <div class="host-section">
            <h3>🖥️ Host: {host}</h3>
            """
            
            # Información del OS si está disponible
            if "os" in host_data:
                html_content += f'<p><strong>Sistema Operativo:</strong> {host_data["os"]}</p>'
            
            # Puertos abiertos
            if "open_ports" in host_data and host_data["open_ports"]:
                html_content += """
            <h4>🔓 Puertos Abiertos y Servicios</h4>
            <table class="port-table">
                <thead>
                    <tr>
                        <th>Puerto</th>
                        <th>Servicio</th>
                        <th>Versión</th>
                        <th>Estado</th>
                    </tr>
                </thead>
                <tbody>
                """
                
                for port_info in host_data["open_ports"]:
                    html_content += f"""
                    <tr>
                        <td>{port_info['port']}</td>
                        <td>{port_info['service']}</td>
                        <td>{port_info.get('version', 'N/A')}</td>
                        <td>Abierto</td>
                    </tr>
                    """
                
                html_content += "</tbody></table>"
            
            # Información de servicios web
            web_services = [k for k in service_data.keys() if k.startswith('web_')]
            if web_services:
                html_content += "<h4>🌐 Servicios Web Detectados</h4>"
                for web_service in web_services:
                    web_info = service_data[web_service]
                    html_content += f"""
                <div class="service-info">
                    <strong>URL:</strong> {web_info['url']}<br>
                    <strong>Servidor:</strong> {web_info.get('server', 'N/A')}<br>
                    <strong>Estado:</strong> {web_info['status_code']}<br>
                    <strong>Tecnologías:</strong> {', '.join(web_info.get('technologies', ['N/A']))}
                </div>
                """
            
            # Información SSL
            ssl_services = [k for k in service_data.keys() if k.startswith('ssl_')]
            if ssl_services:
                html_content += "<h4>🔒 Certificados SSL/TLS</h4>"
                for ssl_service in ssl_services:
                    ssl_info = service_data[ssl_service]
                    html_content += f"""
                <div class="service-info">
                    <strong>Versión TLS:</strong> {ssl_info.get('tls_version', 'N/A')}<br>
                    <strong>Emisor:</strong> {ssl_info.get('issuer', {}).get('organizationName', 'N/A')}<br>
                    <strong>Válido hasta:</strong> {ssl_info.get('not_after', 'N/A')}<br>
                    <strong>Cipher:</strong> {ssl_info.get('cipher', ['N/A'])[0] if ssl_info.get('cipher') else 'N/A'}
                </div>
                """
            
            html_content += "</div>"
        
        # Sección de vulnerabilidades
        if self.report_data["vulnerabilities"]:
            html_content += """
        <h2>⚠️ Vulnerabilidades Detectadas</h2>
        """
            
            # Agrupar por severidad
            for severity in ["Critical", "High", "Medium", "Low", "Unknown"]:
                severity_vulns = [v for v in self.report_data["vulnerabilities"] if v.get("severity") == severity]
                if severity_vulns:
                    css_class = f"vuln-{severity.lower()}"
                    html_content += f"""
        <h3>{severity} ({len(severity_vulns)})</h3>
        """
                    for vuln in severity_vulns:
                        html_content += f"""
        <div class="service-info {css_class}">
            <strong>Host:</strong> {vuln['host']}<br>
            <strong>Descripción:</strong> {vuln['description']}<br>
            <strong>Severidad:</strong> {vuln['severity']}<br>
            <strong>Detectado:</strong> {vuln['timestamp']}
        </div>
        """
        
        html_content += """
        <div style="margin-top: 30px; padding: 20px; background: #f0f0f0; border-radius: 8px; text-align: center;">
            <p><strong>Reporte generado por Network Security Audit Framework</strong></p>
            <p>Para información detallada, consulte los archivos de evidencia en el directorio 'evidence/'</p>
        </div>
    </div>
</body>
</html>
        """
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"📄 Reporte HTML generado: {html_file}")
        return html_file
    
    def generate_text_report(self):
        """Generar reporte en texto plano"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_file = f"reports/txt/network_audit_{timestamp}.txt"
        
        report_content = f"""
========================================
    NETWORK SECURITY AUDIT REPORT
========================================

Fecha del análisis: {self.report_data["scan_info"]["timestamp"]}
Objetivo escaneado: {self.report_data["scan_info"]["target"]}

RESUMEN EJECUTIVO
================
- Total de hosts analizados: {len(self.report_data["hosts"])}
- Total de puertos abiertos: {sum(len(host_data.get("open_ports", [])) for host_data in self.report_data["port_scan_results"].values())}
- Total de vulnerabilidades: {len(self.report_data["vulnerabilities"])}

VULNERABILIDADES POR SEVERIDAD
=============================
"""
        
        # Contar vulnerabilidades por severidad
        vuln_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        for vuln in self.report_data["vulnerabilities"]:
            severity = vuln.get("severity", "Unknown")
            vuln_severity[severity] += 1
        
        for severity, count in vuln_severity.items():
            report_content += f"- {severity}: {count}\n"
        
        report_content += f"""

DETALLES POR HOST
=================
"""
        
        for host in self.report_data["hosts"]:
            host_data = self.report_data["port_scan_results"].get(host, {})
            
            report_content += f"""
[+] HOST: {host}
{'='*50}
"""
            
            if "os" in host_data:
                report_content += f"Sistema Operativo: {host_data['os']}\n"
            
            if "open_ports" in host_data and host_data["open_ports"]:
                report_content += "\nPuertos abiertos:\n"
                for port_info in host_data["open_ports"]:
                    report_content += f"  - {port_info['port']}/tcp - {port_info['service']}"
                    if port_info.get('version'):
                        report_content += f" ({port_info['version']})"
                    report_content += "\n"
            
            # Vulnerabilidades específicas del host
            host_vulns = [v for v in self.report_data["vulnerabilities"] if v["host"] == host]
            if host_vulns:
                report_content += f"\nVulnerabilidades encontradas ({len(host_vulns)}):\n"
                for vuln in host_vulns:
                    report_content += f"  [{vuln['severity']}] {vuln['description']}\n"
            
            report_content += "\n"
        
        report_content += f"""
ARCHIVOS DE EVIDENCIA
====================
Los siguientes archivos contienen información detallada:

- evidence/nmap/        : Resultados de escaneos Nmap
- evidence/ssl/         : Análisis de certificados SSL/TLS  
- evidence/web/         : Análisis de servicios web
- evidence/vulnerabilities/ : Detalles de vulnerabilidades
- logs/                 : Logs de ejecución

RECOMENDACIONES
===============
1. Revisar inmediatamente las vulnerabilidades críticas y altas
2. Actualizar servicios con versiones obsoletas
3. Configurar correctamente certificados SSL/TLS
4. Implementar controles de acceso apropiados
5. Monitorear continuamente la infraestructura

---
Reporte generado por Network Security Audit Framework
"""
        
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"📄 Reporte TXT generado: {txt_file}")
        return txt_file
    
    def generate_all_reports(self):
        """Generar todos los formatos de reporte"""
        reports = []
        
        output_formats = self.config.get("output", {}).get("format", ["json", "html", "txt"])
        
        if "json" in output_formats:
            reports.append(self.generate_json_report())
        
        if "html" in output_formats:
            reports.append(self.generate_html_report())
        
        if "txt" in output_formats:
            reports.append(self.generate_text_report())
        
        return reports

# ================================
# ORQUESTADOR PRINCIPAL
# ================================

class NetworkSecurityAuditor:
    def __init__(self, target, scan_type, save_reports=False, config_file="audit_config.json"):
        print("🛡️ Iniciando Network Security Audit Framework...")
        print("=" * 60)
        
        self.config = Config(config_file)
        self.target = target
        self.scan_type = scan_type
        self.save_reports = save_reports
        
        # Inicializar módulos
        self.host_discovery = HostDiscovery(self.config)
        self.port_scanner = PortScanner(self.config)
        self.service_analyzer = ServiceAnalyzer(self.config)
        self.reporter = AuditReporter(self.config)
        
        # Resultados
        self.live_hosts = []
        self.port_results = {}
        self.service_results = {}
        self.vulnerabilities = []

    def run_comprehensive_audit(self):
        """Ejecutar auditoría completa de seguridad"""
        start_time = time.time()
        
        print("🚀 INICIANDO AUDITORÍA COMPLETA DE SEGURIDAD DE RED")
        print("=" * 60)
        
        # FASE 1: Descubrimiento de hosts
        print("\n📡 FASE 1: DESCUBRIMIENTO DE HOSTS")
        print("-" * 40)
        
        self.live_hosts = self.host_discovery.run_discovery(self.target)
        
        if not self.live_hosts:
            print("❌ No se encontraron hosts activos")
            return
        
        print(f"✅ Hosts activos encontrados: {len(self.live_hosts)}")
        for host in self.live_hosts:
            print(f"   📍 {host}")
        
        # FASE 2: Escaneo de puertos
        print("\n🔍 FASE 2: ESCANEO DE PUERTOS Y SERVICIOS")
        print("-" * 40)
        
        self.port_results = self.port_scanner.scan_hosts(self.live_hosts)
        
        # FASE 3: Análisis de servicios
        print("\n🔬 FASE 3: ANÁLISIS DETALLADO DE SERVICIOS")
        print("-" * 40)
        
        self.service_results = self.service_analyzer.analyze_services(self.port_results)
        self.vulnerabilities = self.service_analyzer.vulnerabilities
        
        # FASE 4: Generación de reportes (solo si se solicita)
        print("\n📋 FASE 4: GENERACIÓN DE REPORTES")
        print("-" * 40)
        
        self.reporter.collect_all_data(
            self.live_hosts,
            self.port_results,
            self.service_results,
            self.vulnerabilities,
            self.target
        )
        
        report_files = []
        if self.save_reports:
            report_files = self.reporter.generate_all_reports()
        else:
            print("\n[INFO] Ejecución tipo nmap: solo mostrando resultados en pantalla. Para guardar reportes use --save.")
        
        # Resumen final
        end_time = time.time()
        duration = end_time - start_time
        
        print("\n" + "=" * 60)
        print("✅ AUDITORÍA COMPLETADA EXITOSAMENTE")
        print("=" * 60)
        print(f"⏱️  Duración total: {duration:.2f} segundos")
        print(f"🎯 Hosts analizados: {len(self.live_hosts)}")
        print(f"🔓 Puertos abiertos: {sum(len(host_data.get('open_ports', [])) for host_data in self.port_results.values())}")
        print(f"⚠️  Vulnerabilidades: {len(self.vulnerabilities)}")
        if self.save_reports:
            print(f"📋 Reportes generados: {len(report_files)}")
            print("\n📁 ARCHIVOS GENERADOS:")
            for report_file in report_files:
                print(f"   📄 {report_file}")
            print(f"\n📂 Evidencias detalladas en: evidence/")
            print(f"📝 Logs en: logs/")
        else:
            print("\n[INFO] No se guardaron reportes. Solo se muestran resultados en pantalla.")
        
        # Mostrar vulnerabilidades críticas si las hay
        critical_vulns = [v for v in self.vulnerabilities if v.get("severity") == "Critical"]
        if critical_vulns:
            print(f"\n🚨 ATENCIÓN: {len(critical_vulns)} VULNERABILIDADES CRÍTICAS ENCONTRADAS")
            for vuln in critical_vulns[:5]:  # Mostrar solo las primeras 5
                print(f"   ❌ {vuln['host']}: {vuln['description']}")
        
        print("\n" + "=" * 60)
        
        return {
            "hosts": self.live_hosts,
            "ports": self.port_results,
            "services": self.service_results,
            "vulnerabilities": self.vulnerabilities,
            "reports": report_files,
            "duration": duration
        }

# ================================
# UTILIDADES Y FUNCIONES AUXILIARES
# ================================

def create_sample_config():
    """Crear archivo de configuración de ejemplo"""
    config = Config("audit_config.json")
    print("✅ Archivo de configuración creado: audit_config.json")
    print("📝 Edita el archivo para configurar tus objetivos de auditoría")

def validate_environment():
    """Validar herramientas necesarias"""
    required_tools = ['nmap', 'ping']
    optional_tools = ['whatweb', 'testssl.sh', 'masscan']
    
    print("🔧 Validando herramientas...")
    
    for tool in required_tools:
        try:
            subprocess.run([tool, '--version'], capture_output=True, timeout=5)
            print(f"✅ {tool} - Disponible")
        except:
            print(f"❌ {tool} - NO disponible (REQUERIDO)")
            return False
    
    for tool in optional_tools:
        try:
            subprocess.run([tool, '--version'], capture_output=True, timeout=5)
            print(f"✅ {tool} - Disponible")
        except:
            print(f"⚠️  {tool} - No disponible (opcional)")
    
    return True

# ================================
# MAIN - PUNTO DE ENTRADA
# ================================

def main():
    """Función principal"""
    import sys
    
    print("🛡️ Network Security Audit Framework v2.0")
    print("🎯 Framework de auditoría de seguridad de red")
    print("👨‍💼 Para administradores de redes y comunicaciones")
    print()
    
    # Analizar argumentos para --save
    save_reports = False
    if any(arg in ["--save", "-s"] for arg in sys.argv):
        save_reports = True
    
    # Validar entorno y configuración
    if not validate_environment() or not os.path.exists("audit_config.json"):
        # ... (mensajes de error)
        return

    # Menú de selección de objetivo
    print("Seleccione el tipo de escaneo:")
    print("1. Escanear un objetivo específico (IP, dominio, URL)")
    print("2. Escanear toda la red interna (según configuración)")
    
    choice = input("Ingrese su opción (1 o 2): ")
    
    target = None
    scan_type = None

    if choice == '1':
        target = input("Ingrese la IP, dominio o URL a escanear: ")
        scan_type = 'single_target'
    elif choice == '2':
        config = Config()
        target = config.get("targets", {}).get("ip_range")
        scan_type = 'network_range'
        print(f"Usando el rango de red de la configuración: {target}")
    else:
        print("Opción no válida. Saliendo.")
        return

    if not target:
        print("No se ha definido un objetivo. Saliendo.")
        return

    try:
        # Iniciar auditoría con el objetivo seleccionado
        auditor = NetworkSecurityAuditor(target=target, scan_type=scan_type, save_reports=save_reports)
        results = auditor.run_comprehensive_audit()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Auditoría interrumpida por el usuario")
    except Exception as e:
        print(f"\n❌ Error durante la auditoría: {str(e)}")
        print("📝 Revisa los logs para más detalles")

if __name__ == "__main__":
    main()