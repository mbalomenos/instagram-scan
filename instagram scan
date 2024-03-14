import os
import re
import xml.etree.ElementTree as ET
import subprocess
import requests
from bs4 import BeautifulSoup

# Function to decompile APK file using JADX
def decompile_apk(apk_file, output_dir):
    os.system(f"jadx -d {output_dir} {apk_file}")

# Function to extract permissions from AndroidManifest.xml
def extract_permissions(manifest_file):
    permissions = []
    tree = ET.parse(manifest_file)
    root = tree.getroot()
    for elem in root.iter():
        if elem.tag.endswith('uses-permission'):
            permission = elem.attrib.get('{http://schemas.android.com/apk/res/android}name')
            if permission:
                permissions.append(permission)
    return permissions

# Function to scan code for potential security issues
def scan_code(code_dir):
    security_issues = []
    for root, dirs, files in os.walk(code_dir):
        for file in files:
            if file.endswith('.java') or file.endswith('.xml'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Example pattern: search for hardcoded API keys
                    if re.search(r'API_KEY', content):
                        security_issues.append(f"Hardcoded API key found in file: {file_path}")
                    # Add more patterns for scanning here
    return security_issues

# Function to scrape vulnerabilities from a webpage
def scrape_webpage_vulnerabilities(url):
    vulnerabilities = []

    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        # Example: scraping CVE IDs and descriptions from the webpage
        rows = soup.find_all('tr')
        for row in rows[1:]:
            cells = row.find_all('td')
            if len(cells) >= 5:
                cve_id = cells[2].text.strip()
                description = cells[3].text.strip()
                vulnerabilities.append({'CVE ID': cve_id, 'Description': description})

    return vulnerabilities

# Main function
def main():
    # Path to the Instagram APK file
    apk_file = 'Instagram.apk'
    # Output directory for decompiled APK
    output_dir = 'instagram_decompiled'
    # IP address of the Android device on the local Wi-Fi network
    android_device_ip = '192.168.1.5'
    # Output directory for scanning code
    code_dir = os.path.join(output_dir, 'sources')

    print("Decompiling APK...")
    decompile_apk(apk_file, output_dir)

    print("Extracting permissions from AndroidManifest.xml...")
    manifest_file = os.path.join(output_dir, 'AndroidManifest.xml')
    permissions = extract_permissions(manifest_file)
    print("Permissions:")
    for permission in permissions:
        print(permission)

    print("Scanning code for potential security issues...")
    security_issues = scan_code(code_dir)
    if security_issues:
        print("Security issues found:")
        for issue in security_issues:
            print(issue)
    else:
        print("No security issues found.")

    print("\nScraping vulnerabilities from the webpage...")
    webpage_url = "https://www.cvedetails.com/cisa-known-exploited-vulnerabilities/kev-1.html"
    webpage_vulnerabilities = scrape_webpage_vulnerabilities(webpage_url)
    if webpage_vulnerabilities:
        print("\nVulnerabilities scraped from the webpage:")
        for vulnerability in webpage_vulnerabilities:
            print(f"CVE ID: {vulnerability['CVE ID']}, Description: {vulnerability['Description']}")
    else:
        print("No vulnerabilities scraped from the webpage.")

    print("\nRunning dynamic analysis (Nmap)...")
    try:
        nmap_output = subprocess.check_output(['nmap', '-p-', '--script', 'vulners', '-oG', '-', android_device_ip])
        print("Nmap output:")
        print(nmap_output.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        print("Error running Nmap:", e)

if __name__ == "__main__":
    main()
