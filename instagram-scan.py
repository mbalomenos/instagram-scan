import os
import re
import xml.etree.ElementTree as ET
import subprocess
import requests
from bs4 import BeautifulSoup

# Function to install JADX from GitHub
def install_jadx():
    try:
        # Clone JADX repository from GitHub
        subprocess.run(['git', 'clone', 'https://github.com/skylot/jadx.git'])
        # Change directory to jadx
        os.chdir('jadx')
        # Build JADX using gradlew
        subprocess.run(['./gradlew', 'dist'])
    except Exception as e:
        print("Error installing JADX:", e)

# Function to decompile APK file using JADX
def decompile_apk(apk_file, output_dir):
    try:
        # Check if JADX is installed, if not, install it
        if not os.path.exists('jadx'):
            print("JADX not found. Installing...")
            install_jadx()
        # Check if JADX installation was successful
        if os.path.exists('jadx'):
            os.system(f"jadx -d {output_dir} {apk_file}")
        else:
            print("JADX installation failed. Please install JADX manually.")
    except Exception as e:
        print("Error decompiling APK:", e)

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

# Function to find package name and directory of Instagram app
def find_instagram_app_info():
    try:
        # Run adb command to list packages and find Instagram app
        output = subprocess.check_output(['adb', 'shell', 'pm', 'list', 'packages', '|', 'grep', 'instagram'])
        output = output.decode('utf-8')
        # Extract package name from output
        package_name = output.split(':')[1].strip()
        # Run adb command to get app info and extract app directory
        output = subprocess.check_output(['adb', 'shell', 'pm', 'path', package_name])
        output = output.decode('utf-8')
        # Extract app directory from output
        app_directory = re.search(r'package:(.*)', output).group(1).strip()
        return package_name, app_directory
    except subprocess.CalledProcessError as e:
        print("Error finding Instagram app info:", e)
        return None, None

# Function to analyze Instagram app files
def analyze_instagram_app(package_name, app_directory):
    if package_name and app_directory:
        print("Analyzing Instagram app files...")
        # Example: List files in the app directory
        try:
            output = subprocess.check_output(['adb', 'shell', 'ls', app_directory])
            output = output.decode('utf-8')
            print("Files in Instagram app directory:")
            print(output)
        except subprocess.CalledProcessError as e:
            print("Error analyzing Instagram app files:", e)
    else:
        print("Instagram app not found on the device.")

# Main function
def main():
    # Path to the Instagram APK file
    apk_file = 'Instagram.apk'
    # Output directory for decompiled APK
    output_dir = 'instagram_decompiled'
    # Output directory for scanning code
    code_dir = os.path.join(output_dir, 'sources')

    print("Finding Instagram app info...")
    package_name, app_directory = find_instagram_app_info()

    # Analyze Instagram app files
    analyze_instagram_app(package_name, app_directory)

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

if __name__ == "__main__":
    main()
