#!/usr/bin/env python3
"""
Aruba Central Connectivity Test Script
Quick diagnostic tool for firewall whitelisting verification
"""

import socket
import requests
import ssl
import json
from datetime import datetime
import concurrent.futures
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_dns(domain):
    """Test DNS resolution"""
    try:
        result = socket.gethostbyname(domain)
        return "Success", result
    except Exception as e:
        return "Failed", str(e)

def test_tcp_connect(domain, port):
    """Test raw TCP connectivity"""
    try:
        with socket.create_connection((domain, port), timeout=10):
            return "Success", "Port open"
    except Exception as e:
        return "Failed", str(e)

def test_https(domain, port=443):
    """Test HTTPS connectivity"""
    try:
        response = requests.get(
            f"https://{domain}:{port}/",
            timeout=10,
            verify=False,
            headers={'User-Agent': 'ArubaCentral-Test/1.0'}
        )
        return "Success", f"HTTP {response.status_code}"
    except requests.exceptions.SSLError as e:
        return "SSL Error", str(e)
    except requests.exceptions.ConnectionError as e:
        return "Failed", str(e)
    except requests.exceptions.Timeout as e:
        return "Timeout", str(e)
    except Exception as e:
        return "Error", str(e)

def test_ntp(server, port=123):
    """Test NTP connectivity"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(10)
            # Simple NTP packet (version 3, client mode)
            packet = bytearray(48)
            packet[0] = 0x1B  # LI=0, VN=3, Mode=3
            sock.sendto(packet, (server, port))
            data, addr = sock.recvfrom(1024)
            return "Success", "NTP response received"
    except Exception as e:
        return "Failed", str(e)

def run_test(test_config):
    """Run individual test and return results"""
    domain = test_config['domain']
    port = test_config['port']
    protocol = test_config['protocol']
    service = test_config['service']
    
    print(f"Testing {service:.<40}", end="")
    
    # DNS test first
    dns_status, dns_result = test_dns(domain)
    
    if dns_status == "Failed":
        print(f"DNS FAILED: {dns_result}")
        return test_config | {
            'dns_resolution': dns_status,
            'ip_address': 'N/A',
            'connectivity_status': 'Failed',
            'error_message': f"DNS: {dns_result}",
            'test_timestamp': datetime.now().strftime('%d/%m/%Y %H:%M')
        }
    
    # Protocol-specific tests
    ip_address = dns_result
    
    if protocol.upper() == "NTP":
        status, message = test_ntp(domain, port)
    elif protocol.upper() == "TCP":
        status, message = test_tcp_connect(domain, port)
    else:  # HTTPS
        status, message = test_https(domain, port)
    
    print(f"{status}")
    
    return test_config | {
        'dns_resolution': dns_status,
        'ip_address': ip_address,
        'connectivity_status': status,
        'error_message': message,
        'test_timestamp': datetime.now().strftime('%d/%m/%Y %H:%M')
    }

def main():
    print("=" * 70)
    print("ARUBA CENTRAL CONNECTIVITY TEST")
    print("=" * 70)
    print(f"Test Time: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print()
    
    # Test configurations for AP SouthEast region
    test_configs = [
        # Core Services
        {'domain': 'app-apacsouth.central.arubanetworks.com', 'port': 443, 'protocol': 'HTTPS', 'service': 'Aruba Central Portal'},
        {'domain': 'device-apacsouth.central.arubanetworks.com', 'port': 443, 'protocol': 'HTTPS', 'service': 'Device Connectivity'},
        {'domain': 'device-apacsouth-h2.central.arubanetworks.com', 'port': 443, 'protocol': 'HTTPS', 'service': 'Overlay Services'},
        
        # Activate & Provisioning
        {'domain': 'device.arubanetworks.com', 'port': 443, 'protocol': 'HTTPS', 'service': 'Aruba Activate'},
        {'domain': 'devices-v2.arubanetworks.com', 'port': 443, 'protocol': 'HTTPS', 'service': 'Activate V2'},
        {'domain': 'est.arubanetworks.com', 'port': 443, 'protocol': 'HTTPS', 'service': 'EST Service'},
        
        # Additional Services
        {'domain': 'apacsouth-hc.central.arubanetworks.com', 'port': 443, 'protocol': 'HTTPS', 'service': 'Hybrid Endpoint'},
        {'domain': 'apacsouth.cloudguest.central.arubanetworks.com', 'port': 443, 'protocol': 'HTTPS', 'service': 'Guest Access HTTPS'},
        {'domain': 'apacsouth.cloudguest.central.arubanetworks.com', 'port': 2083, 'protocol': 'TCP', 'service': 'Guest Access TCP'},
        {'domain': 'apacsouth-elb.cloudguest.central.arubanetworks.com', 'port': 443, 'protocol': 'HTTPS', 'service': 'Guest Access ELB'},
        {'domain': 'au1.api.central.arubanetworks.com', 'port': 443, 'protocol': 'HTTPS', 'service': 'API Gateway'},
        {'domain': 'pool.ntp.org', 'port': 123, 'protocol': 'NTP', 'service': 'NTP Time Sync'},
    ]
    
    results = []
    
    # Run tests with progress indication
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_test = {executor.submit(run_test, config): config for config in test_configs}
        for future in concurrent.futures.as_completed(future_to_test):
            results.append(future.result())
    
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    # Count results
    success_count = sum(1 for r in results if r['connectivity_status'] == 'Success')
    total_count = len(results)
    
    print(f"Results: {success_count}/{total_count} tests passed")
    print()
    
    # Show failures first
    failures = [r for r in results if r['connectivity_status'] != 'Success']
    successes = [r for r in results if r['connectivity_status'] == 'Success']
    
    if failures:
        print("❌ FAILED TESTS:")
        for test in failures:
            print(f"  • {test['service']}: {test['error_message']}")
        print()
    
    if successes:
        print("✅ WORKING SERVICES:")
        for test in successes:
            print(f"  • {test['service']}")
        print()
    
    # Save results to CSV
    csv_filename = f"aruba_connectivity_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(csv_filename, 'w') as f:
        f.write("service,domain,port,protocol,dns_resolution,ip_address,connectivity_status,error_message,test_timestamp\n")
        for result in results:
            f.write(f"\"{result['service']}\",{result['domain']},{result['port']},{result['protocol']},{result['dns_resolution']},{result['ip_address']},{result['connectivity_status']},\"{result['error_message']}\",{result['test_timestamp']}\n")
    
    print(f"Detailed results saved to: {csv_filename}")
    
    # Final recommendation
    print("=" * 70)
    if success_count == total_count:
        print("✅ ALL TESTS PASSED - Network connectivity looks good!")
    elif success_count == 0:
        print("❌ ALL TESTS FAILED - Check firewall/proxy settings")
    else:
        print("⚠️  PARTIAL SUCCESS - Some services may be blocked")
        print("   Provide this report to network team for firewall whitelisting")

if __name__ == "__main__":
    main()