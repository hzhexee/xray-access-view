#!/usr/bin/env python3
"""
SSH Log Collector for X-Ray Access Logs
Собирает логи с удаленных серверов через SSH согласно PLANS.md
"""

import os
import sys
import platform
import subprocess
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import argparse
from datetime import datetime


class SSHConfig:
    """Класс для работы с SSH конфигурацией"""
    
    def __init__(self):
        self.config_path = self._get_ssh_config_path()
        self.hosts = []
        
    def _get_ssh_config_path(self) -> Path:
        """Определить путь к SSH config в зависимости от ОС"""
        if platform.system() == "Windows":
            # Windows: C:\Users\username\.ssh\config
            home = Path.home()
            ssh_config = home / ".ssh" / "config"
        else:
            # Linux/Unix: ~/.ssh/config
            ssh_config = Path.home() / ".ssh" / "config"
        
        return ssh_config
    
    def parse_hosts(self, exclude_hosts: Optional[List[str]] = None) -> List[str]:
        """Парсить SSH config и извлечь все хосты кроме исключенных"""
        if exclude_hosts is None:
            exclude_hosts = ["192.168.1.1", "rtr"]  # OpenWRT и роутеры по умолчанию
            
        hosts = []
        
        if not self.config_path.exists():
            print(f"❌ SSH config не найден: {self.config_path}")
            return hosts
            
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Парсим конфигурацию более тщательно
            current_host = None
            current_hostname = None
            
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                if line.lower().startswith('host '):
                    # Сохранить предыдущий хост если он подходит
                    if current_host and self._should_include_host_simple(current_host, current_hostname, exclude_hosts):
                        hosts.append(current_host)
                    
                    # Начать новый хост
                    current_host = line.split()[1]
                    current_hostname = current_host  # По умолчанию hostname = host
                    
                elif current_host and line.lower().startswith('hostname '):
                    # Извлечь hostname
                    current_hostname = line.split(None, 1)[1]
            
            # Сохранить последний хост
            if current_host and self._should_include_host_simple(current_host, current_hostname, exclude_hosts):
                hosts.append(current_host)
                    
        except Exception as e:
            print(f"❌ Ошибка при чтении SSH config: {e}")
            
        self.hosts = hosts
        return hosts
    
    def _should_include_host_simple(self, host_name: str, hostname: Optional[str], exclude_hosts: List[str]) -> bool:
        """Определить, должен ли хост быть включен в обработку (упрощенная версия)"""
        # Пропускаем wildcards
        if '*' in host_name:
            return False
            
        # Проверяем имя хоста
        if host_name in exclude_hosts:
            return False
            
        # Проверяем IP адрес хоста
        if hostname and hostname in exclude_hosts:
            return False
            
        # Проверяем, не является ли это локальной сетью
        if hostname and hostname.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                               '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                               '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
            print(f"🚫 Пропуск {host_name} (локальная сеть: {hostname})")
            return False
                
        return True


class RemoteLogCollector:
    """Класс для сбора логов с удаленных серверов"""
    
    def __init__(self, local_logs_dir: str = "./logs"):
        self.local_logs_dir = Path(local_logs_dir)
        self.local_logs_dir.mkdir(exist_ok=True)
        
    def check_container_exists(self, host: str, container_name: str = "remnanode") -> bool:
        """Проверить существование Docker контейнера на удаленном хосте"""
        try:
            cmd = f'ssh {host} "docker ps -a --filter name={container_name} --format \\"{{{{.Names}}}}\\"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and container_name in result.stdout:
                print(f"✅ Контейнер '{container_name}' найден на {host}")
                return True
            else:
                print(f"❌ Контейнер '{container_name}' не найден на {host}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"⏰ Таймаут при проверке контейнера на {host}")
            return False
        except Exception as e:
            print(f"❌ Ошибка при проверке контейнера на {host}: {e}")
            return False
    
    def copy_log_from_container(self, host: str, container_name: str = "remnanode") -> bool:
        """Скопировать лог из Docker контейнера в /tmp на удаленном хосте"""
        try:
            # Путь к логу внутри контейнера
            container_log_path = "/var/log/supervisor/xray.out.log"
            remote_temp_path = f"/tmp/xray_{host}.log"
            
            # Команда для копирования лога из контейнера
            copy_cmd = f'ssh {host} "docker cp {container_name}:{container_log_path} {remote_temp_path}"'
            
            print(f"📦 Копирование лога из контейнера на {host}...")
            result = subprocess.run(copy_cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print(f"✅ Лог скопирован в {remote_temp_path} на {host}")
                return True
            else:
                print(f"❌ Ошибка копирования лога на {host}: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"⏰ Таймаут при копировании лога на {host}")
            return False
        except Exception as e:
            print(f"❌ Ошибка при копировании лога на {host}: {e}")
            return False
    
    def download_log_to_local(self, host: str) -> bool:
        """Скачать лог с удаленного хоста на локальную машину"""
        try:
            remote_log_path = f"/tmp/xray_{host}.log"
            local_log_path = self.local_logs_dir / f"xray_{host}.log"
            
            # Команда для скачивания по scp
            scp_cmd = f'scp {host}:{remote_log_path} "{local_log_path}"'
            
            print(f"📥 Скачивание лога с {host}...")
            result = subprocess.run(scp_cmd, shell=True, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                print(f"✅ Лог сохранен: {local_log_path}")
                return True
            else:
                print(f"❌ Ошибка скачивания лога с {host}: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"⏰ Таймаут при скачивании лога с {host}")
            return False
        except Exception as e:
            print(f"❌ Ошибка при скачивании лога с {host}: {e}")
            return False
    
    def cleanup_remote_log(self, host: str, confirm: bool = True) -> bool:
        """Удалить временный лог на удаленном хосте"""
        if confirm:
            response = input(f"Удалить временный лог на {host}? (y/N): ").strip().lower()
            if response not in ['y', 'yes', 'да']:
                print(f"Пропуск очистки на {host}")
                return False
        
        try:
            remote_log_path = f"/tmp/xray_{host}.log"
            cleanup_cmd = f'ssh {host} "rm -f {remote_log_path}"'
            
            result = subprocess.run(cleanup_cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"🗑️ Временный лог удален на {host}")
                return True
            else:
                print(f"❌ Ошибка удаления лога на {host}: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Ошибка при удалении лога на {host}: {e}")
            return False
    
    def collect_logs_from_host(self, host: str, container_name: str = "remnanode", cleanup: bool = False) -> bool:
        """Полный процесс сбора логов с одного хоста"""
        print(f"\n🔄 Обработка хоста: {host}")
        print("-" * 50)
        
        # 1. Проверить существование контейнера
        if not self.check_container_exists(host, container_name):
            return False
        
        # 2. Скопировать лог из контейнера в /tmp
        if not self.copy_log_from_container(host, container_name):
            return False
        
        # 3. Скачать лог на локальную машину
        if not self.download_log_to_local(host):
            return False
        
        # 4. Очистить временный файл (опционально)
        if cleanup:
            self.cleanup_remote_log(host, confirm=False)
        
        print(f"✅ Обработка {host} завершена успешно")
        return True


def select_hosts(available_hosts: List[str]) -> List[str]:
    """Интерактивный выбор хостов для обработки"""
    if not available_hosts:
        print("❌ Нет доступных хостов")
        return []
    
    print("\n📋 Доступные хосты:")
    for i, host in enumerate(available_hosts, 1):
        print(f"  {i}. {host}")
    
    print("\nВарианты выбора:")
    print("  a - Все хосты")
    print("  1,2,3 - Выбранные хосты (через запятую)")
    print("  q - Выход")
    
    while True:
        choice = input("\nВаш выбор: ").strip().lower()
        
        if choice == 'q':
            return []
        elif choice == 'a':
            return available_hosts
        else:
            try:
                # Парсинг номеров через запятую
                numbers = [int(x.strip()) for x in choice.split(',')]
                selected_hosts = []
                
                for num in numbers:
                    if 1 <= num <= len(available_hosts):
                        selected_hosts.append(available_hosts[num - 1])
                    else:
                        print(f"❌ Неверный номер: {num}")
                        break
                else:
                    return selected_hosts
                    
            except ValueError:
                print("❌ Неверный формат. Используйте 'a' или номера через запятую (например: 1,3,5)")


def main():
    """Основная функция"""
    parser = argparse.ArgumentParser(description="Сбор логов X-Ray с удаленных серверов")
    parser.add_argument("--logs-dir", default="./logs", help="Локальная директория для логов (по умолчанию: ./logs)")
    parser.add_argument("--container", default="remnanode", help="Имя Docker контейнера (по умолчанию: remnanode)")
    parser.add_argument("--exclude", nargs="+", default=["192.168.1.1", "rtr"], help="Хосты для исключения")
    parser.add_argument("--cleanup", action="store_true", help="Автоматически удалять временные файлы")
    parser.add_argument("--all", action="store_true", help="Обработать все доступные хосты без запроса")
    
    args = parser.parse_args()
    
    print("🚀 X-Ray Log Collector")
    print("=" * 50)
    print(f"ОС: {platform.system()}")
    print(f"Локальная директория для логов: {args.logs_dir}")
    print(f"Контейнер: {args.container}")
    print(f"Исключенные хосты: {args.exclude}")
    
    # 1. Инициализация SSH конфигурации
    print("\n📂 Чтение SSH конфигурации...")
    ssh_config = SSHConfig()
    available_hosts = ssh_config.parse_hosts(exclude_hosts=args.exclude)
    
    if not available_hosts:
        print("❌ Не найдено доступных хостов в SSH конфигурации")
        return 1
    
    print(f"✅ Найдено хостов: {len(available_hosts)}")
    
    # 2. Выбор хостов для обработки
    if args.all:
        selected_hosts = available_hosts
        print(f"🎯 Выбраны все хосты: {', '.join(selected_hosts)}")
    else:
        selected_hosts = select_hosts(available_hosts)
    
    if not selected_hosts:
        print("👋 Выход без обработки")
        return 0
    
    # 3. Инициализация коллектора логов
    collector = RemoteLogCollector(local_logs_dir=args.logs_dir)
    
    # 4. Обработка выбранных хостов
    print(f"\n🎯 Начинаем обработку {len(selected_hosts)} хост(ов)...")
    successful = 0
    failed = 0
    
    for host in selected_hosts:
        try:
            if collector.collect_logs_from_host(host, args.container, args.cleanup):
                successful += 1
            else:
                failed += 1
        except KeyboardInterrupt:
            print("\n⏹️ Прервано пользователем")
            break
        except Exception as e:
            print(f"❌ Неожиданная ошибка при обработке {host}: {e}")
            failed += 1
    
    # 5. Итоговая статистика и автоматический анализ
    print("\n" + "=" * 50)
    print("📊 РЕЗУЛЬТАТЫ СБОРА ЛОГОВ")
    print("=" * 50)
    print(f"✅ Успешно обработано: {successful}")
    print(f"❌ Ошибок: {failed}")
    print(f"📁 Логи сохранены в: {args.logs_dir}")
    
    if successful > 0:
        print(f"\n📋 Список сохраненных файлов:")
        logs_path = Path(args.logs_dir)
        for log_file in logs_path.glob("xray_*.log"):
            file_size = log_file.stat().st_size
            print(f"  📄 {log_file.name} ({file_size:,} байт)")
        
        # Предложить автоматический анализ
        print("\n" + "=" * 50)
        print("🔍 АНАЛИЗ СОБРАННЫХ ЛОГОВ")
        print("=" * 50)
        
        auto_analyze = input("Запустить автоматический анализ собранных логов? (Y/n): ").strip().lower()
        if auto_analyze in ['', 'y', 'yes', 'да']:
            try:
                import log_merger
                print("\n🚀 Запуск анализа...")
                
                # Создать объединитель логов
                merger = log_merger.LogMerger(logs_dir=args.logs_dir)
                log_files = merger.find_log_files()
                
                if log_files:
                    # Создать отсортированный объединенный лог
                    merged_path = merger.create_sorted_merged_log(log_files)
                    
                    # Запустить GUI анализ
                    print("\n🎯 Запуск графического интерфейса анализа...")
                    log_merger.analyze_merged_logs(merged_path, "gui")
                else:
                    print("❌ Не найдено файлов логов для анализа")
                    
            except Exception as e:
                print(f"❌ Ошибка при запуске анализа: {e}")
                print("💡 Вы можете запустить анализ вручную: python log_merger.py")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n👋 Прервано пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        sys.exit(1)
