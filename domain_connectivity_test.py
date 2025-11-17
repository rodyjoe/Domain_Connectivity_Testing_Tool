import socket
import requests
import csv
import concurrent.futures
from datetime import datetime
import time
import sys

def test_tcp_connection(hostname, port, timeout=5):
    """Test TCP connection to a hostname and port"""
    try:
        # Remove URL path if present
        hostname = hostname.split('/')[0]
        
        # Create socket and attempt connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((hostname, port))
        sock.close()
        
        return result == 0, "Success" if result == 0 else f"TCP Error: {result}"
    except socket.gaierror as e:
        return False, f"DNS Resolution Failed: {e}"
    except Exception as e:
        return False, f"Connection Error: {e}"

def test_http_connection(url, timeout=5):
    """Test HTTP/HTTPS connection"""
    try:
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        return response.status_code == 200, f"HTTP {response.status_code}"
    except requests.exceptions.RequestException as e:
        return False, f"HTTP Error: {e}"

def test_domain_connectivity(domain_info):
    """Test connectivity for a single domain"""
    hostname = domain_info['domain']
    port = domain_info['port']
    protocol = domain_info['protocol'].upper()
    
    print(f"Testing {hostname}:{port} ({protocol})...")
    
    # Test DNS resolution first
    try:
        ip_address = socket.gethostbyname(hostname.split('/')[0])
        dns_status = "Success"
    except socket.gaierror:
        ip_address = "N/A"
        dns_status = "Failed"
    
    # Test based on protocol
    if protocol in ['HTTPS', 'HTTP']:
        success, message = test_http_connection(hostname)
    elif protocol in ['TCP', 'SSH']:
        success, message = test_tcp_connection(hostname, port)
    elif protocol in ['UDP']:
        # UDP testing is more complex, we'll just test DNS resolution
        success = (dns_status == "Success")
        message = "UDP - DNS resolution only"
    elif protocol in ['ICMP']:
        # ICMP requires ping, which needs admin privileges on Windows
        success = (dns_status == "Success")
        message = "ICMP - DNS resolution only"
    else:
        success, message = test_tcp_connection(hostname, port)
    
    return {
        'domain': hostname,
        'port': port,
        'protocol': protocol,
        'service': domain_info['service'],
        'region': domain_info.get('region', 'Global'),
        'dns_resolution': dns_status,
        'ip_address': ip_address,
        'connectivity_status': 'Success' if success else 'Failed',
        'error_message': message,
        'test_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

def load_domains_from_csv(csv_file):
    """Load domain list from CSV file"""
    domains = []
    try:
        with open(csv_file, 'r', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                # Handle different CSV formats
                if 'Domain Name' in row:
                    domain = row['Domain Name']
                elif 'domain' in row:
                    domain = row['domain']
                else:
                    continue
                
                # Extract port and protocol
                port = int(row.get('Port', 443))
                protocol = row.get('Protocol', 'HTTPS')
                service = row.get('Service', 'Unknown')
                region = row.get('Region', 'Global')
                
                domains.append({
                    'domain': domain,
                    'port': port,
                    'protocol': protocol,
                    'service': service,
                    'region': region
                })
        return domains
    except FileNotFoundError:
        print(f"Error: CSV file '{csv_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        sys.exit(1)

def main():
    # Configuration
    CSV_INPUT_FILE = "aruba_domains.csv"  # Your input CSV file
    CSV_OUTPUT_FILE = f"connectivity_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    MAX_WORKERS = 10  # Number of concurrent tests
    TIMEOUT = 10  # Connection timeout in seconds
    
    print("HPE Aruba Networking Domain Connectivity Test")
    print("=" * 50)
    
    # Load domains from CSV
    print(f"Loading domains from {CSV_INPUT_FILE}...")
    domains = load_domains_from_csv(CSV_INPUT_FILE)
    print(f"Loaded {len(domains)} domains to test.")
    
    # Test connectivity
    print(f"\nTesting connectivity with {MAX_WORKERS} concurrent workers...")
    print("This may take a few minutes...\n")
    
    results = []
    failed_domains = []
    
    # Use thread pool for concurrent testing
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all tasks
        future_to_domain = {
            executor.submit(test_domain_connectivity, domain): domain 
            for domain in domains
        }
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_domain):
            try:
                result = future.result()
                results.append(result)
                
                if result['connectivity_status'] == 'Failed':
                    failed_domains.append(result)
                    print(f"❌ FAILED: {result['domain']}:{result['port']} - {result['error_message']}")
                else:
                    print(f"✅ SUCCESS: {result['domain']}:{result['port']}")
                    
            except Exception as e:
                print(f"Error testing domain: {e}")
    
    # Generate report
    print(f"\nGenerating report: {CSV_OUTPUT_FILE}")
    
    # Write detailed results
    with open(CSV_OUTPUT_FILE, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'domain', 'port', 'protocol', 'service', 'region',
            'dns_resolution', 'ip_address', 'connectivity_status', 
            'error_message', 'test_timestamp'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    # Generate summary
    total_domains = len(results)
    successful = len([r for r in results if r['connectivity_status'] == 'Success'])
    failed = len(failed_domains)
    
    print(f"\n=== TEST SUMMARY ===")
    print(f"Total domains tested: {total_domains}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Success rate: {(successful/total_domains)*100:.1f}%")
    
    if failed_domains:
        print(f"\n=== FAILED DOMAINS ===")
        for domain in failed_domains:
            print(f"- {domain['domain']}:{domain['port']} ({domain['protocol']})")
            print(f"  Error: {domain['error_message']}")
            print(f"  Service: {domain['service']}, Region: {domain['region']}\n")
    
    # Write failed domains to separate file
    if failed_domains:
        failed_file = f"failed_domains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(failed_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(failed_domains)
        print(f"Failed domains list saved to: {failed_file}")
    
    print(f"Detailed report saved to: {CSV_OUTPUT_FILE}")

if __name__ == "__main__":
    # Disable SSL warnings for testing
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()