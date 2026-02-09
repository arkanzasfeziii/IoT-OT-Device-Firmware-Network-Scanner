#!/usr/bin/env python3
"""
IoT/OT Device Firmware & Network Scanner
Author: arkanzasfeziii
License: MIT

A comprehensive, single-file IoT and OT security scanner for network discovery,
device fingerprinting, firmware analysis, and vulnerability assessment.
"""

# === Imports ===
import argparse
import ipaddress
import json
import logging
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse

try:
    import requests
    from requests.exceptions import RequestException, Timeout
except ImportError:
    print("Error: 'requests' library not found. Install with: pip install -r requirements.txt")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.tree import Tree
except ImportError:
    print("Error: 'rich' library not found. Install with: pip install -r requirements.txt")
    sys.exit(1)

try:
    from scapy.all import ARP, Ether, srp, ICMP, IP, sr1, conf
    conf.verb = 0  # Suppress scapy verbosity
except ImportError:
    print("Error: 'scapy' library not found. Install with: pip install -r requirements.txt")
    sys.exit(1)

try:
    from pyfiglet import figlet_format
    PYFIGLET_AVAILABLE = True
except ImportError:
    PYFIGLET_AVAILABLE = False


# === Constants ===
VERSION = "1.0.0"
AUTHOR = "arkanzasfeziii"
DEFAULT_TIMEOUT = 3
DEFAULT_PORTS = "21,22,23,80,443,8080,8443,502,102,47808,161,5000,8000,9000"
COMMON_IOT_PORTS = [21, 22, 23, 25, 53, 80, 443, 445, 502, 1883, 5000, 5001, 
                    8000, 8080, 8443, 8883, 9000, 47808, 102, 161, 20000]

OUI_DATABASE = {
    "00:50:C2": "IEEE 1588",
    "00:0C:29": "VMware",
    "00:1C:42": "Parallels",
    "08:00:27": "Oracle VirtualBox",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "00:04:A3": "Microchip Technology",
    "00:1D:C9": "Sonos",
    "00:17:88": "Philips Lighting",
    "EC:FA:BC": "Espressif (ESP8266/ESP32)",
    "18:FE:34": "Espressif",
    "24:0A:C4": "Espressif",
    "30:AE:A4": "Espressif",
    "00:0D:B9": "Modbus/TCP",
    "00:50:56": "VMware ESX",
    "F0:18:98": "Amazon Technologies (Echo/IoT)",
    "FC:A1:83": "Amazon Technologies",
    "00:FC:8B": "Amazon Technologies",
    "AC:63:BE": "Amazon Technologies",
    "50:DC:E7": "Amazon Technologies",
    "00:11:32": "Synology",
    "00:1B:63": "Apple (HomeKit)",
    "A4:D1:8C": "Google (Nest)",
    "18:B4:30": "Nest Labs",
    "64:16:66": "Nest Labs",
    "00:D0:2D": "Cisco",
    "00:01:42": "Cisco",
    "D4:6E:0E": "TP-Link",
    "50:C7:BF": "TP-Link",
    "00:00:00": "Xerox Corporation",
}

VULNERABILITY_DATABASE = {
    "mirai_telnet": {
        "name": "Mirai Botnet - Default Telnet Credentials",
        "severity": "CRITICAL",
        "description": "Device may be vulnerable to Mirai botnet infection due to default credentials on Telnet",
        "cve": ["CVE-2016-10401"],
        "mitigation": "Disable Telnet, change default credentials, update firmware, restrict network access",
        "check": lambda device: device.get("telnet_open", False)
    },
    "http_no_auth": {
        "name": "Web Interface Without Authentication",
        "severity": "HIGH",
        "description": "HTTP service accessible without authentication",
        "cve": [],
        "mitigation": "Enable authentication, use HTTPS, restrict access to management interface",
        "check": lambda device: device.get("http_no_auth", False)
    },
    "upnp_exposed": {
        "name": "UPnP Service Exposed",
        "severity": "MEDIUM",
        "description": "UPnP service may allow unauthorized port forwarding and information disclosure",
        "cve": ["CVE-2013-0229", "CVE-2020-12695"],
        "mitigation": "Disable UPnP if not needed, update firmware, use firewall rules",
        "check": lambda device: device.get("upnp_detected", False)
    },
    "default_credentials": {
        "name": "Potential Default Credentials",
        "severity": "CRITICAL",
        "description": "Device banner suggests default or weak credentials may be in use",
        "cve": [],
        "mitigation": "Change all default passwords immediately, enforce strong password policy",
        "check": lambda device: any(keyword in device.get("banner", "").lower() 
                                   for keyword in ["default", "admin", "password"])
    },
    "weak_protocol": {
        "name": "Insecure Protocol Detected",
        "severity": "HIGH",
        "description": "Device uses unencrypted or weak protocols (Telnet, HTTP, SNMPv1/v2)",
        "cve": [],
        "mitigation": "Use SSH instead of Telnet, HTTPS instead of HTTP, SNMPv3 with encryption",
        "check": lambda device: any(device.get(f"{proto}_open", False) 
                                   for proto in ["telnet", "http"])
    },
    "modbus_exposed": {
        "name": "Modbus Protocol Exposed",
        "severity": "HIGH",
        "description": "Modbus protocol detected - commonly used in industrial systems without authentication",
        "cve": [],
        "mitigation": "Isolate OT networks, use VPN/firewall, implement Modbus security extensions",
        "check": lambda device: 502 in device.get("open_ports", [])
    },
    "bacnet_exposed": {
        "name": "BACnet Protocol Exposed",
        "severity": "MEDIUM",
        "description": "BACnet protocol detected - building automation system may be accessible",
        "cve": [],
        "mitigation": "Segment BACnet network, use BACnet security features, restrict access",
        "check": lambda device: 47808 in device.get("open_ports", [])
    },
    "old_ssh": {
        "name": "Potentially Outdated SSH Version",
        "severity": "MEDIUM",
        "description": "SSH banner suggests potentially outdated version",
        "cve": ["CVE-2016-10009", "CVE-2016-10012"],
        "mitigation": "Update SSH server to latest version, disable weak ciphers",
        "check": lambda device: "SSH-1" in device.get("banner", "") or "OpenSSH_5" in device.get("banner", "")
    }
}

DEFAULT_CREDENTIAL_INDICATORS = [
    "admin", "default", "password", "login", "unauthorized",
    "authentication required", "401", "403"
]


# === Data Classes ===
@dataclass
class ScanConfig:
    """Configuration for scanning operations."""
    targets: List[str]
    interface: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    timeout: int = DEFAULT_TIMEOUT
    aggressive: bool = False
    threads: int = 10
    verbose: bool = False
    output_format: str = "console"
    output_file: Optional[str] = None


@dataclass
class Device:
    """Represents a discovered network device."""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    banners: Dict[int, str] = field(default_factory=dict)
    device_type: Optional[str] = None
    firmware_version: Optional[str] = None
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: int = 0
    upnp_info: Optional[Dict[str, Any]] = None
    http_info: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    scan_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert device to dictionary."""
        return asdict(self)


@dataclass
class ScanResult:
    """Complete scan results."""
    scan_id: str
    start_time: str
    end_time: str
    targets: List[str]
    devices_found: int
    devices: List[Device]
    scan_config: Dict[str, Any]
    summary: Dict[str, Any] = field(default_factory=dict)


# === Logging Setup ===
def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging with appropriate level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stderr)]
    )
    return logging.getLogger(__name__)


# === Utility Functions ===
def parse_targets(target_input: str) -> List[str]:
    """
    Parse target specification into list of IP addresses.
    
    Supports:
    - Single IP: 192.168.1.1
    - CIDR: 192.168.1.0/24
    - Range: 192.168.1.1-192.168.1.50
    """
    targets = []
    
    try:
        if '/' in target_input:
            network = ipaddress.ip_network(target_input, strict=False)
            targets = [str(ip) for ip in network.hosts()]
        elif '-' in target_input:
            start_ip, end_ip = target_input.split('-')
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())
            current = start
            while current <= end:
                targets.append(str(current))
                current += 1
        else:
            ip = ipaddress.ip_address(target_input.strip())
            targets = [str(ip)]
    except ValueError as e:
        raise ValueError(f"Invalid target specification: {target_input}. Error: {e}")
    
    return targets


def parse_ports(port_spec: str) -> List[int]:
    """Parse port specification into list of port numbers."""
    ports = set()
    
    for part in port_spec.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    
    return sorted(list(ports))


def get_mac_vendor(mac: str) -> Optional[str]:
    """Lookup vendor from MAC address OUI."""
    if not mac:
        return None
    
    oui = mac[:8].upper()
    return OUI_DATABASE.get(oui, "Unknown Vendor")


def calculate_risk_score(device: Device) -> int:
    """
    Calculate risk score for device based on vulnerabilities and exposure.
    
    Returns: Risk score 0-100
    """
    score = 0
    
    for vuln in device.vulnerabilities:
        severity = vuln.get("severity", "LOW")
        if severity == "CRITICAL":
            score += 25
        elif severity == "HIGH":
            score += 15
        elif severity == "MEDIUM":
            score += 8
        else:
            score += 3
    
    if 23 in device.open_ports:
        score += 15
    if 21 in device.open_ports:
        score += 10
    if device.upnp_info:
        score += 5
    
    return min(score, 100)


def identify_device_type(device: Device) -> str:
    """Identify device type based on fingerprints."""
    ports = set(device.open_ports)
    banners = " ".join(device.banners.values()).lower()
    vendor = (device.vendor or "").lower()
    
    if 502 in ports:
        return "Industrial Controller (Modbus)"
    if 47808 in ports:
        return "Building Automation (BACnet)"
    if 102 in ports:
        return "Industrial PLC (Siemens S7)"
    if "raspberry pi" in vendor:
        return "IoT Device (Raspberry Pi)"
    if "espressif" in vendor:
        return "IoT Device (ESP8266/ESP32)"
    if "nest" in vendor or "nest" in banners:
        return "Smart Home (Thermostat/Camera)"
    if "sonos" in vendor:
        return "IoT Device (Smart Speaker)"
    if "philips" in vendor:
        return "IoT Device (Smart Lighting)"
    if "amazon" in vendor and any(p in ports for p in [8080, 55443]):
        return "IoT Device (Amazon Echo/Alexa)"
    if "camera" in banners or "dvr" in banners or "nvr" in banners:
        return "Security Camera/NVR/DVR"
    if "router" in banners or "gateway" in banners:
        return "Network Device (Router/Gateway)"
    if device.upnp_info:
        return "UPnP Device"
    if 80 in ports or 443 in ports or 8080 in ports:
        return "Web-Enabled Device"
    
    return "Unknown Device"


# === Network Discovery ===
def arp_scan(network: str, timeout: int = 3) -> List[Tuple[str, str]]:
    """
    Perform ARP scan to discover live hosts on local network.
    
    Returns: List of (IP, MAC) tuples
    """
    results = []
    
    try:
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        
        answered, _ = srp(packet, timeout=timeout, verbose=False)
        
        for sent, received in answered:
            results.append((received.psrc, received.hwsrc))
    
    except PermissionError:
        logging.error("ARP scan requires root/administrator privileges")
    except Exception as e:
        logging.error(f"ARP scan failed: {e}")
    
    return results


def icmp_ping(ip: str, timeout: int = 2) -> bool:
    """Check if host is alive using ICMP ping."""
    try:
        packet = IP(dst=ip) / ICMP()
        response = sr1(packet, timeout=timeout, verbose=False)
        return response is not None
    except Exception:
        return False


def discover_hosts(targets: List[str], config: ScanConfig, logger: logging.Logger) -> List[str]:
    """
    Discover live hosts from target list.
    
    Uses ARP for local networks and ICMP for others.
    """
    live_hosts = []
    console = Console()
    
    if len(targets) == 1:
        return targets
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"[cyan]Discovering live hosts...", total=len(targets))
        
        try:
            network_cidr = f"{targets[0]}/24"
            arp_results = arp_scan(network_cidr, config.timeout)
            
            if arp_results:
                live_hosts = [ip for ip, mac in arp_results if ip in targets]
                logger.info(f"ARP scan found {len(live_hosts)} hosts")
                progress.update(task, completed=len(targets))
                return live_hosts
        except Exception as e:
            logger.debug(f"ARP scan not available: {e}")
        
        with ThreadPoolExecutor(max_workers=config.threads) as executor:
            future_to_ip = {executor.submit(icmp_ping, ip, config.timeout): ip 
                          for ip in targets}
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                progress.update(task, advance=1)
                
                try:
                    if future.result():
                        live_hosts.append(ip)
                except Exception as e:
                    logger.debug(f"Ping failed for {ip}: {e}")
    
    logger.info(f"Discovery found {len(live_hosts)} live hosts")
    return live_hosts if live_hosts else targets


# === Port Scanning ===
def scan_port(ip: str, port: int, timeout: int = 2) -> bool:
    """Scan single port on target host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False


def grab_banner(ip: str, port: int, timeout: int = 3) -> Optional[str]:
    """Attempt to grab service banner from open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            if port in [21, 22, 23, 25]:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
            
            probe = b"GET / HTTP/1.0\r\n\r\n" if port in [80, 443, 8080, 8443] else b"\r\n"
            sock.send(probe)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else None
    
    except Exception:
        return None


def identify_service(port: int, banner: Optional[str] = None) -> str:
    """Identify service running on port."""
    common_services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 443: "HTTPS", 445: "SMB", 502: "Modbus",
        1883: "MQTT", 3306: "MySQL", 5000: "UPnP", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 8883: "MQTT-TLS", 47808: "BACnet", 102: "S7",
        161: "SNMP", 20000: "DNP3"
    }
    
    service = common_services.get(port, f"Unknown-{port}")
    
    if banner:
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            service = "SSH"
        elif "ftp" in banner_lower:
            service = "FTP"
        elif "http" in banner_lower:
            service = "HTTP" if port != 443 else "HTTPS"
        elif "telnet" in banner_lower:
            service = "Telnet"
        elif "smtp" in banner_lower:
            service = "SMTP"
    
    return service


# === HTTP Probing ===
def probe_http(ip: str, port: int = 80, timeout: int = 5) -> Optional[Dict[str, Any]]:
    """Probe HTTP service for information."""
    urls = [f"http://{ip}:{port}", f"https://{ip}:{port}"]
    
    for url in urls:
        try:
            response = requests.get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers={'User-Agent': 'IoTScanner/1.0'}
            )
            
            info = {
                'url': url,
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Unknown'),
                'title': None,
                'requires_auth': response.status_code == 401,
                'headers': dict(response.headers)
            }
            
            if 'text/html' in response.headers.get('Content-Type', ''):
                content = response.text.lower()
                if '<title>' in content:
                    start = content.find('<title>') + 7
                    end = content.find('</title>', start)
                    info['title'] = response.text[start:end].strip()
            
            return info
        
        except requests.exceptions.SSLError:
            continue
        except (RequestException, Timeout):
            continue
        except Exception:
            continue
    
    return None


# === UPnP Discovery ===
def discover_upnp(ip: str, timeout: int = 3) -> Optional[Dict[str, Any]]:
    """Discover UPnP devices using SSDP."""
    ssdp_request = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 3\r\n'
        'ST: ssdp:all\r\n'
        '\r\n'
    )
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(ssdp_request.encode(), (ip, 1900))
        
        data, addr = sock.recvfrom(2048)
        response = data.decode('utf-8', errors='ignore')
        
        info = {'ip': addr[0], 'raw_response': response}
        
        for line in response.split('\r\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                info[key.strip().lower()] = value.strip()
        
        return info
    
    except socket.timeout:
        return None
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except:
            pass


# === Vulnerability Assessment ===
def check_vulnerabilities(device: Device, aggressive: bool = False) -> List[Dict[str, Any]]:
    """Check device for known vulnerabilities."""
    vulnerabilities = []
    
    device_data = {
        "telnet_open": 23 in device.open_ports,
        "http_no_auth": device.http_info and not device.http_info.get('requires_auth'),
        "upnp_detected": device.upnp_info is not None,
        "banner": " ".join(device.banners.values()),
        "open_ports": device.open_ports
    }
    
    for vuln_id, vuln_def in VULNERABILITY_DATABASE.items():
        try:
            if vuln_def["check"](device_data):
                vulnerabilities.append({
                    "id": vuln_id,
                    "name": vuln_def["name"],
                    "severity": vuln_def["severity"],
                    "description": vuln_def["description"],
                    "cve": vuln_def["cve"],
                    "mitigation": vuln_def["mitigation"]
                })
        except Exception:
            continue
    
    return vulnerabilities


# === Core Scanner ===
def scan_device(ip: str, config: ScanConfig, logger: logging.Logger) -> Device:
    """Perform comprehensive scan of a single device."""
    device = Device(ip=ip)
    
    try:
        device.hostname = socket.getfqdn(ip)
    except Exception:
        pass
    
    for port in config.ports:
        if scan_port(ip, port, config.timeout):
            device.open_ports.append(port)
            
            banner = grab_banner(ip, port, config.timeout)
            service = identify_service(port, banner)
            
            device.services[port] = service
            if banner:
                device.banners[port] = banner
    
    if config.aggressive or 80 in device.open_ports or 8080 in device.open_ports:
        for port in [80, 8080, 443, 8443]:
            if port in device.open_ports or config.aggressive:
                http_info = probe_http(ip, port, config.timeout)
                if http_info:
                    device.http_info = http_info
                    break
    
    if config.aggressive:
        upnp_info = discover_upnp(ip, config.timeout)
        if upnp_info:
            device.upnp_info = upnp_info
    
    device.vulnerabilities = check_vulnerabilities(device, config.aggressive)
    device.device_type = identify_device_type(device)
    device.risk_score = calculate_risk_score(device)
    
    return device


def scan_network(config: ScanConfig, logger: logging.Logger) -> ScanResult:
    """Execute complete network scan."""
    console = Console()
    start_time = datetime.now()
    scan_id = f"scan_{start_time.strftime('%Y%m%d_%H%M%S')}"
    
    all_targets = []
    for target in config.targets:
        all_targets.extend(parse_targets(target))
    
    logger.info(f"Parsed {len(all_targets)} total targets")
    
    live_hosts = discover_hosts(all_targets, config, logger)
    logger.info(f"Scanning {len(live_hosts)} live hosts")
    
    devices = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(
            f"[green]Scanning {len(live_hosts)} devices...",
            total=len(live_hosts)
        )
        
        with ThreadPoolExecutor(max_workers=config.threads) as executor:
            future_to_ip = {
                executor.submit(scan_device, ip, config, logger): ip
                for ip in live_hosts
            }
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                progress.update(task, advance=1)
                
                try:
                    device = future.result()
                    if device.open_ports or device.upnp_info:
                        devices.append(device)
                        logger.info(f"Found device at {ip} with {len(device.open_ports)} open ports")
                except Exception as e:
                    logger.error(f"Error scanning {ip}: {e}")
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    summary = {
        "total_targets": len(all_targets),
        "live_hosts": len(live_hosts),
        "devices_with_findings": len(devices),
        "total_vulnerabilities": sum(len(d.vulnerabilities) for d in devices),
        "critical_devices": sum(1 for d in devices if d.risk_score >= 75),
        "high_risk_devices": sum(1 for d in devices if 50 <= d.risk_score < 75),
        "scan_duration_seconds": duration
    }
    
    result = ScanResult(
        scan_id=scan_id,
        start_time=start_time.isoformat(),
        end_time=end_time.isoformat(),
        targets=config.targets,
        devices_found=len(devices),
        devices=devices,
        scan_config={
            "ports": config.ports,
            "timeout": config.timeout,
            "aggressive": config.aggressive,
            "threads": config.threads
        },
        summary=summary
    )
    
    return result


# === Reporting ===
def print_banner(console: Console):
    """Print application banner."""
    if PYFIGLET_AVAILABLE:
        banner_text = figlet_format("IoT/OT Scanner", font="slant")
        console.print(f"[bold cyan]{banner_text}[/bold cyan]")
    else:
        console.print("[bold cyan]IoT/OT Device Firmware & Network Scanner[/bold cyan]")
    
    console.print(f"[yellow]Version {VERSION} | Author: {AUTHOR}[/yellow]")
    console.print("[red bold]⚠️  For Authorized Security Testing Only ⚠️[/red bold]\n")


def display_summary(result: ScanResult, console: Console):
    """Display scan summary."""
    summary_table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="green")
    
    summary_table.add_row("Total Targets", str(result.summary["total_targets"]))
    summary_table.add_row("Live Hosts", str(result.summary["live_hosts"]))
    summary_table.add_row("Devices Found", str(result.devices_found))
    summary_table.add_row("Total Vulnerabilities", str(result.summary["total_vulnerabilities"]))
    summary_table.add_row("Critical Risk Devices", str(result.summary["critical_devices"]))
    summary_table.add_row("High Risk Devices", str(result.summary["high_risk_devices"]))
    summary_table.add_row("Scan Duration", f"{result.summary['scan_duration_seconds']:.2f}s")
    
    console.print(summary_table)


def display_devices(devices: List[Device], console: Console):
    """Display detailed device information."""
    if not devices:
        console.print("[yellow]No devices with findings discovered.[/yellow]")
        return
    
    for device in sorted(devices, key=lambda d: d.risk_score, reverse=True):
        risk_color = "red" if device.risk_score >= 75 else "yellow" if device.risk_score >= 50 else "green"
        
        tree = Tree(f"[bold {risk_color}]🔍 {device.ip}[/bold {risk_color}] (Risk: {device.risk_score}/100)")
        
        info_branch = tree.add("[cyan]Device Information[/cyan]")
        info_branch.add(f"Type: {device.device_type}")
        if device.hostname:
            info_branch.add(f"Hostname: {device.hostname}")
        if device.mac:
            info_branch.add(f"MAC: {device.mac}")
        if device.vendor:
            info_branch.add(f"Vendor: {device.vendor}")
        
        if device.open_ports:
            ports_branch = tree.add(f"[green]Open Ports ({len(device.open_ports)})[/green]")
            for port in sorted(device.open_ports):
                service = device.services.get(port, "Unknown")
                banner = device.banners.get(port, "")
                port_info = f"{port}/{service}"
                if banner:
                    port_info += f" - {banner[:60]}..."
                ports_branch.add(port_info)
        
        if device.vulnerabilities:
            vuln_branch = tree.add(f"[red]Vulnerabilities ({len(device.vulnerabilities)})[/red]")
            for vuln in device.vulnerabilities:
                vuln_color = {
                    "CRITICAL": "red",
                    "HIGH": "orange1",
                    "MEDIUM": "yellow",
                    "LOW": "blue"
                }.get(vuln["severity"], "white")
                
                vuln_node = vuln_branch.add(f"[{vuln_color}]{vuln['severity']}[/{vuln_color}] - {vuln['name']}")
                vuln_node.add(f"Description: {vuln['description']}")
                if vuln['cve']:
                    vuln_node.add(f"CVE: {', '.join(vuln['cve'])}")
                vuln_node.add(f"Mitigation: {vuln['mitigation']}")
        
        if device.http_info:
            http_branch = tree.add("[magenta]HTTP Information[/magenta]")
            http_branch.add(f"URL: {device.http_info['url']}")
            http_branch.add(f"Server: {device.http_info['server']}")
            if device.http_info.get('title'):
                http_branch.add(f"Title: {device.http_info['title']}")
        
        console.print(tree)
        console.print()


def save_json_report(result: ScanResult, filepath: str):
    """Save scan results as JSON."""
    output = {
        "scan_id": result.scan_id,
        "start_time": result.start_time,
        "end_time": result.end_time,
        "targets": result.targets,
        "summary": result.summary,
        "devices": [device.to_dict() for device in result.devices]
    }
    
    with open(filepath, 'w') as f:
        json.dump(output, f, indent=2)


def save_html_report(result: ScanResult, filepath: str):
    """Save scan results as HTML."""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>IoT/OT Scan Report - {result.scan_id}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
            .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .device {{ background: white; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 4px solid #3498db; }}
            .critical {{ border-left-color: #e74c3c; }}
            .high {{ border-left-color: #f39c12; }}
            .medium {{ border-left-color: #f1c40f; }}
            .low {{ border-left-color: #27ae60; }}
            .vuln {{ background: #fff3cd; padding: 10px; margin: 10px 0; border-radius: 3px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
            th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background: #34495e; color: white; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>IoT/OT Device Scan Report</h1>
            <p>Scan ID: {result.scan_id}</p>
            <p>Author: {AUTHOR}</p>
            <p>Generated: {result.end_time}</p>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Total Targets</td><td>{result.summary['total_targets']}</td></tr>
                <tr><td>Live Hosts</td><td>{result.summary['live_hosts']}</td></tr>
                <tr><td>Devices Found</td><td>{result.devices_found}</td></tr>
                <tr><td>Total Vulnerabilities</td><td>{result.summary['total_vulnerabilities']}</td></tr>
                <tr><td>Critical Risk Devices</td><td>{result.summary['critical_devices']}</td></tr>
                <tr><td>Scan Duration</td><td>{result.summary['scan_duration_seconds']:.2f}s</td></tr>
            </table>
        </div>
        
        <h2>Devices</h2>
    """
    
    for device in sorted(result.devices, key=lambda d: d.risk_score, reverse=True):
        risk_class = "critical" if device.risk_score >= 75 else "high" if device.risk_score >= 50 else "medium" if device.risk_score >= 25 else "low"
        
        html_content += f"""
        <div class="device {risk_class}">
            <h3>{device.ip} - {device.device_type}</h3>
            <p><strong>Risk Score:</strong> {device.risk_score}/100</p>
            <p><strong>Open Ports:</strong> {', '.join(map(str, device.open_ports))}</p>
        """
        
        if device.vulnerabilities:
            html_content += "<h4>Vulnerabilities:</h4>"
            for vuln in device.vulnerabilities:
                html_content += f"""
                <div class="vuln">
                    <strong>[{vuln['severity']}] {vuln['name']}</strong><br>
                    {vuln['description']}<br>
                    <em>Mitigation: {vuln['mitigation']}</em>
                </div>
                """
        
        html_content += "</div>"
    
    html_content += """
    </body>
    </html>
    """
    
    with open(filepath, 'w') as f:
        f.write(html_content)


# === CLI ===
def show_examples():
    """Display usage examples."""
    examples = """
    [bold cyan]Usage Examples:[/bold cyan]
    
    1. Scan single IP with default ports:
       python iototscanner.py 192.168.1.1
    
    2. Scan network range with specific ports:
       python iototscanner.py 192.168.1.0/24 --ports 80,443,8080,502
    
    3. Aggressive scan with all features:
       sudo python iototscanner.py 192.168.1.0/24 --aggressive --timeout 5
    
    4. Scan IP range and save to JSON:
       python iototscanner.py 192.168.1.10-192.168.1.50 --output json --file scan_results.json
    
    5. Quick scan of common IoT ports:
       python iototscanner.py 10.0.0.0/24 --ports 23,80,443,8080,1883,5000
    
    6. Scan with verbose logging:
       python iototscanner.py 192.168.1.100 --verbose
    
    [yellow]Note: Aggressive scans and ARP discovery require root/administrator privileges[/yellow]
    """
    Console().print(examples)


def show_legal_warning(console: Console) -> bool:
    """Display legal warning and get user acknowledgment."""
    warning = Panel(
        "[bold red]⚠️  LEGAL WARNING ⚠️[/bold red]\n\n"
        "This tool is designed for AUTHORIZED security testing only.\n\n"
        "You must have explicit permission to scan any network or device.\n"
        "Unauthorized scanning may be illegal in your jurisdiction and could\n"
        "result in criminal prosecution.\n\n"
        "[bold]By proceeding, you acknowledge that:[/bold]\n"
        "• You have authorization to scan the specified targets\n"
        "• You understand the legal implications\n"
        "• You accept full responsibility for your actions\n\n"
        f"[cyan]Author ({AUTHOR}) and contributors assume NO liability for misuse.[/cyan]",
        title="Legal Notice",
        border_style="red"
    )
    
    console.print(warning)
    return True


def main():
    """Main entry point for the scanner."""
    parser = argparse.ArgumentParser(
        description=f"IoT/OT Device Firmware & Network Scanner v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Author: {AUTHOR} | For authorized security testing only"
    )
    
    parser.add_argument(
        "target",
        nargs='?',
        help="Target IP, CIDR range, or IP range (e.g., 192.168.1.1, 192.168.1.0/24, 192.168.1.1-192.168.1.50)"
    )
    parser.add_argument(
        "--ports",
        default=DEFAULT_PORTS,
        help=f"Comma-separated ports to scan (default: {DEFAULT_PORTS})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout in seconds for each connection (default: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Enable aggressive scanning (more thorough but slower and noisier)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )
    parser.add_argument(
        "--interface",
        help="Network interface for ARP scanning (e.g., eth0, wlan0)"
    )
    parser.add_argument(
        "--output",
        choices=["console", "json", "html"],
        default="console",
        help="Output format (default: console)"
    )
    parser.add_argument(
        "--file",
        help="Output file path for json/html formats"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--examples",
        action="store_true",
        help="Show usage examples and exit"
    )
    parser.add_argument(
        "--i-understand-legal-responsibilities",
        action="store_true",
        help="Acknowledge legal responsibilities (required for aggressive scans)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}"
    )
    
    args = parser.parse_args()
    
    console = Console()
    
    if args.examples:
        show_examples()
        sys.exit(0)
    
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    print_banner(console)
    
    if args.aggressive and not args.i_understand_legal_responsibilities:
        if not show_legal_warning(console):
            console.print("[red]Scan cancelled.[/red]")
            sys.exit(1)
        
        response = console.input("\n[yellow]Type 'I UNDERSTAND' to proceed: [/yellow]")
        if response.strip() != "I UNDERSTAND":
            console.print("[red]Scan cancelled.[/red]")
            sys.exit(1)
    
    logger = setup_logging(args.verbose)
    
    try:
        config = ScanConfig(
            targets=[args.target],
            interface=args.interface,
            ports=parse_ports(args.ports),
            timeout=args.timeout,
            aggressive=args.aggressive,
            threads=args.threads,
            verbose=args.verbose,
            output_format=args.output,
            output_file=args.file
        )
        
        logger.info(f"Starting scan of {args.target}")
        logger.info(f"Scanning {len(config.ports)} ports per host")
        
        result = scan_network(config, logger)
        
        console.print("\n")
        display_summary(result, console)
        console.print("\n")
        display_devices(result.devices, console)
        
        if args.output == "json":
            output_file = args.file or f"{result.scan_id}.json"
            save_json_report(result, output_file)
            console.print(f"\n[green]✓[/green] JSON report saved to: {output_file}")
        
        elif args.output == "html":
            output_file = args.file or f"{result.scan_id}.html"
            save_html_report(result, output_file)
            console.print(f"\n[green]✓[/green] HTML report saved to: {output_file}")
        
        console.print(f"\n[cyan]Scan completed successfully![/cyan]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger.exception("Fatal error during scan")
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
