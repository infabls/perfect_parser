#!/usr/bin/env python3
"""
Domain Checker Script
Проверяет домены через domain-check.exe и сохраняет результаты в CSV, JSON и Google Sheets
"""

import subprocess
import re
import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Optional
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from pathlib import Path

# CONFIG
DOMAIN_CHECK_EXE = "domain-check.exe"
DOMAINS_FILE = "domains.txt"
OUTPUT_CSV = "domains_result.csv"
OUTPUT_JSON = "domains_result.json"
GOOGLE_CREDENTIALS_FILE = "credentials.json"
GOOGLE_SHEET_URL = "https://docs.google.com/spreadsheets/d/10J67cLWeKQSGrqJL0tdsQ_OFBHLlR2N9DgR3mnyLHng/"

# Регулярные выражения для парсинга вывода domain-check.exe
DOMAIN_STATUS_RE = re.compile(r'^([^\s]+)\s+(AVAILABLE|TAKEN|UNKNOWN)', re.MULTILINE)
TAKEN_INFO_RE = re.compile(r'TAKEN\s*\(([^)]+)\)')
REGISTRAR_RE = re.compile(r'Registrar:\s*([^,]+)')
CREATED_RE = re.compile(r'Created:\s*([^,]+)')
EXPIRES_RE = re.compile(r'Expires:\s*([^,]+)')
SUMMARY_RE = re.compile(r'Summary:\s*(\d+)\s+available,\s*(\d+)\s+taken,\s*(\d+)\s+unknown')

class DomainChecker:
    def __init__(self):
        self.results = []
        self.google_sheet = None
        
    def load_domains(self, domains_file: str) -> List[str]:
        """Загружает домены из файла"""
        try:
            with open(domains_file, 'r', encoding='utf-8') as f:
                domains = [line.strip() for line in f if line.strip()]
            print(f"Загружено {len(domains)} доменов из {domains_file}")
            return domains
        except FileNotFoundError:
            print(f"Файл {domains_file} не найден!")
            return []
    
    def run_domain_check(self, domains_file: str) -> str:
        """Запускает domain-check.exe и возвращает вывод"""
        try:
            # Запускаем domain-check.exe с параметрами --file и --info
            cmd = [DOMAIN_CHECK_EXE, "--file", domains_file, "--info"]
            print(f"Выполняется команда: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=300  # 5 минут таймаут
            )
            
            if result.returncode != 0:
                print(f"Ошибка выполнения domain-check.exe: {result.stderr}")
                return ""
            
            print("domain-check.exe выполнен успешно")
            return result.stdout
            
        except subprocess.TimeoutExpired:
            print("Таймаут выполнения domain-check.exe")
            return ""
        except FileNotFoundError:
            print(f"Утилита {DOMAIN_CHECK_EXE} не найдена!")
            return ""
        except Exception as e:
            print(f"Ошибка при запуске domain-check.exe: {e}")
            return ""
    
    def parse_domain_check_output(self, output: str) -> List[Dict]:
        """Парсит вывод domain-check.exe и извлекает информацию о доменах"""
        results = []
        
        # Разбиваем вывод на строки
        lines = output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('Summary:'):
                continue
                
            # Проверяем статус домена
            match = DOMAIN_STATUS_RE.search(line)
            if not match:
                continue
                
            domain = match.group(1)
            status = match.group(2)
            
            result = {
                'domain': domain,
                'status': status,
                'registrar': None,
                'created_date': None,
                'expires_date': None,
                'checked_at': datetime.now().isoformat()
            }
            
            # Если домен занят, извлекаем дополнительную информацию
            if status == 'TAKEN':
                taken_info = TAKEN_INFO_RE.search(line)
                if taken_info:
                    info_text = taken_info.group(1)
                    
                    # Извлекаем регистратора
                    registrar_match = REGISTRAR_RE.search(info_text)
                    if registrar_match:
                        result['registrar'] = registrar_match.group(1).strip()
                    
                    # Извлекаем дату создания
                    created_match = CREATED_RE.search(info_text)
                    if created_match:
                        result['created_date'] = created_match.group(1).strip()
                    
                    # Извлекаем дату истечения
                    expires_match = EXPIRES_RE.search(info_text)
                    if expires_match:
                        result['expires_date'] = expires_match.group(1).strip()
            
            results.append(result)
            print(f"Обработан домен: {domain} - {status}")
        
        return results
    
    def save_to_csv(self, results: List[Dict], filename: str):
        """Сохраняет результаты в CSV файл"""
        if not results:
            print("Нет данных для сохранения в CSV")
            return
            
        # Определяем заголовки
        headers = ['domain', 'status', 'registrar', 'created_date', 'expires_date', 'checked_at']
        
        # Проверяем, существует ли файл
        file_exists = os.path.exists(filename)
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers)
                writer.writeheader()
                
                for result in results:
                    writer.writerow(result)
            
            print(f"Результаты сохранены в {filename}")
            
        except Exception as e:
            print(f"Ошибка при сохранении в CSV: {e}")
    
    def save_to_json(self, results: List[Dict], filename: str):
        """Сохраняет результаты в JSON файл"""
        if not results:
            print("Нет данных для сохранения в JSON")
            return
            
        try:
            with open(filename, 'w', encoding='utf-8') as jsonfile:
                json.dump(results, jsonfile, indent=2, ensure_ascii=False)
            
            print(f"Результаты сохранены в {filename}")
            
        except Exception as e:
            print(f"Ошибка при сохранении в JSON: {e}")
    
    def setup_google_sheets(self):
        """Настраивает подключение к Google Sheets"""
        try:
            if not os.path.exists(GOOGLE_CREDENTIALS_FILE):
                print(f"Файл {GOOGLE_CREDENTIALS_FILE} не найден. Google Sheets не будет использоваться.")
                return False
            
            # Настройка авторизации
            scope = [
                'https://spreadsheets.google.com/feeds',
                'https://www.googleapis.com/auth/drive'
            ]
            
            credentials = ServiceAccountCredentials.from_json_keyfile_name(
                GOOGLE_CREDENTIALS_FILE, scope
            )
            
            gc = gspread.authorize(credentials)
            
            # Открываем таблицу
            self.google_sheet = gc.open_by_url(GOOGLE_SHEET_URL).sheet1
            print("Подключение к Google Sheets установлено")
            return True
            
        except Exception as e:
            print(f"Ошибка при настройке Google Sheets: {e}")
            return False
    
    def save_to_google_sheets(self, results: List[Dict]):
        """Сохраняет результаты в Google Sheets"""
        if not self.google_sheet or not results:
            return
            
        try:
            # Определяем заголовки
            headers = ['domain', 'status', 'registrar', 'created_date', 'expires_date', 'checked_at']
            
            # Очищаем лист и добавляем заголовки
            self.google_sheet.clear()
            self.google_sheet.append_row(headers)
            
            # Добавляем данные
            for result in results:
                row = [result.get(header, '') for header in headers]
                self.google_sheet.append_row(row)
            
            print("Результаты сохранены в Google Sheets")
            
        except Exception as e:
            print(f"Ошибка при сохранении в Google Sheets: {e}")
    
    def print_summary(self, results: List[Dict]):
        """Выводит сводку результатов"""
        if not results:
            print("Нет результатов для отображения")
            return
            
        available = sum(1 for r in results if r['status'] == 'AVAILABLE')
        taken = sum(1 for r in results if r['status'] == 'TAKEN')
        unknown = sum(1 for r in results if r['status'] == 'UNKNOWN')
        
        print(f"\n=== СВОДКА РЕЗУЛЬТАТОВ ===")
        print(f"Всего обработано: {len(results)}")
        print(f"Доступны: {available}")
        print(f"Заняты: {taken}")
        print(f"Неизвестно: {unknown}")
        
        if available > 0:
            print(f"\nДоступные домены:")
            for result in results:
                if result['status'] == 'AVAILABLE':
                    print(f"  - {result['domain']}")
    
    def run(self):
        """Основной метод для запуска проверки доменов"""
        print("=== DOMAIN CHECKER ===")
        print(f"Утилита: {DOMAIN_CHECK_EXE}")
        print(f"Файл доменов: {DOMAINS_FILE}")
        print(f"Выходные файлы: {OUTPUT_CSV}, {OUTPUT_JSON}")
        print()
        
        # Загружаем домены
        domains = self.load_domains(DOMAINS_FILE)
        if not domains:
            return
        
        # Запускаем проверку доменов
        output = self.run_domain_check(DOMAINS_FILE)
        if not output:
            return
        
        # Парсим результаты
        print("\nПарсинг результатов...")
        results = self.parse_domain_check_output(output)
        
        if not results:
            print("Не удалось извлечь данные из вывода domain-check.exe")
            return
        
        # Сохраняем результаты
        print("\nСохранение результатов...")
        self.save_to_csv(results, OUTPUT_CSV)
        self.save_to_json(results, OUTPUT_JSON)
        
        # Настраиваем и сохраняем в Google Sheets
        if self.setup_google_sheets():
            self.save_to_google_sheets(results)
        
        # Выводим сводку
        self.print_summary(results)
        
        print(f"\nПроверка завершена! Результаты сохранены в:")
        print(f"- {OUTPUT_CSV}")
        print(f"- {OUTPUT_JSON}")
        if self.google_sheet:
            print(f"- Google Sheets: {GOOGLE_SHEET_URL}")

def main():
    """Точка входа в программу"""
    checker = DomainChecker()
    checker.run()

if __name__ == "__main__":
    main()
