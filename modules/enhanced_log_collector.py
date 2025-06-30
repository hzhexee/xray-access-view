#!/usr/bin/env python3
"""
Enhanced SSH Log Collector using Paramiko
Улучшенная версия коллектора логов с использованием Paramiko для более надежных SSH соединений
"""

import os
import sys
import platform
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import argparse
from datetime import datetime
import time

try:
    import paramiko
    from paramiko import SSHClient, AutoAddPolicy
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


class EnhancedSSHConfig:
    """Расширенный класс для работы с SSH конфигурацией"""
    
    def __init__(self):
        self.config_path = self._get_ssh_config_path()
        self.hosts_config = {}
        
    def _get_ssh_config_path(self) -> Path:
        """Определить путь к SSH config в зависимости от ОС"""
        if platform.system() == "Windows":
            home = Path.home()
            ssh_config = home / ".ssh" / "config"
        else:
            ssh_config = Path.home() / ".ssh" / "config"
        return ssh_config
    
    def parse_ssh_config(self, exclude_hosts: Optional[List[str]] = None) -> Dict[str, Dict[str, str]]:
        """Парсить SSH config и извлечь конфигурацию хостов"""
        if exclude_hosts is None:
            exclude_hosts = ["192.168.1.1", "rtr"]  # Добавим стандартные исключения
            
        hosts_config = {}
        
        if not self.config_path.exists():
            print(f"❌ SSH config не найден: {self.config_path}")
            return hosts_config
            
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            current_host = None
            current_config = {}
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if line.lower().startswith('host '):
                    # Сохранить предыдущий хост
                    if current_host and self._should_include_host(current_host, current_config, exclude_hosts):
                        hosts_config[current_host] = current_config.copy()
                    
                    # Начать новый хост
                    current_host = line.split()[1]
                    current_config = {'Host': current_host}
                    
                elif current_host and ' ' in line:
                    # Парсить параметры хоста
                    key, value = line.split(None, 1)
                    current_config[key.lower()] = value
            
            # Сохранить последний хост
            if current_host and self._should_include_host(current_host, current_config, exclude_hosts):
                hosts_config[current_host] = current_config.copy()
                
        except Exception as e:
            print(f"❌ Ошибка при чтении SSH config: {e}")
            
        self.hosts_config = hosts_config
        return hosts_config
    
    def _should_include_host(self, host_name: str, host_config: Dict[str, str], exclude_hosts: List[str]) -> bool:
        """Определить, должен ли хост быть включен в обработку"""
        # Пропускаем wildcards
        if '*' in host_name:
            return False
            
        # Проверяем имя хоста
        if host_name in exclude_hosts:
            return False
            
        # Проверяем IP адрес хоста
        hostname = host_config.get('hostname', host_name)
        if hostname in exclude_hosts:
            return False
            
        # Проверяем, не является ли это роутером по паттернам
        router_patterns = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                          '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                          '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
        
        for pattern in router_patterns:
            if hostname.startswith(pattern):
                print(f"🚫 Пропуск {host_name} (локальная сеть: {hostname})")
                return False
                
        return True


class EnhancedRemoteLogCollector:
    """Улучшенный класс для сбора логов с удаленных серверов"""
    
    def __init__(self, local_logs_dir: str = "./logs", use_paramiko: bool = True):
        self.local_logs_dir = Path(local_logs_dir)
        self.local_logs_dir.mkdir(exist_ok=True)
        self.use_paramiko = use_paramiko and PARAMIKO_AVAILABLE
        
        if not self.use_paramiko:
            print("⚠️ Paramiko недоступен, используется стандартный SSH")
    
    def create_ssh_connection(self, host_config: Dict[str, str]) -> Optional[paramiko.SSHClient]:
        """Создать SSH соединение с использованием Paramiko"""
        if not self.use_paramiko:
            return None
            
        try:
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            
            # Извлечь параметры подключения
            hostname = host_config.get('hostname', host_config['Host'])
            port = int(host_config.get('port', 22))
            username = host_config.get('user', os.getenv('USER', 'root'))
            
            # Путь к приватному ключу
            key_file = host_config.get('identityfile')
            if key_file:
                key_file = os.path.expanduser(key_file)
            
            print(f"🔗 Подключение к {hostname}:{port} как {username}...")
            
            if key_file and os.path.exists(key_file):
                client.connect(hostname, port=port, username=username, key_filename=key_file, timeout=30)
            else:
                client.connect(hostname, port=port, username=username, timeout=30)
            
            print(f"✅ SSH соединение установлено с {hostname}")
            return client
            
        except Exception as e:
            print(f"❌ Ошибка SSH соединения с {hostname}: {e}")
            return None
    
    def execute_remote_command(self, client: paramiko.SSHClient, command: str, timeout: int = 60) -> Tuple[bool, str, str]:
        """Выполнить команду на удаленном сервере через Paramiko"""
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            
            # Ждем завершения команды
            exit_status = stdout.channel.recv_exit_status()
            
            stdout_data = stdout.read().decode('utf-8')
            stderr_data = stderr.read().decode('utf-8')
            
            return exit_status == 0, stdout_data, stderr_data
            
        except Exception as e:
            return False, "", str(e)
    
    def check_container_exists_paramiko(self, client: paramiko.SSHClient, container_name: str = "remnanode") -> bool:
        """Проверить существование Docker контейнера через Paramiko"""
        command = f'docker ps -a --filter name={container_name} --format "{{{{.Names}}}}"'
        success, stdout, stderr = self.execute_remote_command(client, command)
        
        if success and container_name in stdout:
            print(f"✅ Контейнер '{container_name}' найден")
            return True
        else:
            print(f"❌ Контейнер '{container_name}' не найден")
            if stderr:
                print(f"Ошибка: {stderr}")
            return False
    
    def copy_log_from_container_paramiko(self, client: paramiko.SSHClient, host: str, container_name: str = "remnanode") -> bool:
        """Скопировать лог из Docker контейнера через Paramiko"""
        container_log_path = "/var/log/supervisor/xray.out.log"
        
        # Используем временную директорию на удаленном хосте
        if platform.system() == "Windows":
            # На Windows клиенте используем /tmp на удаленном Linux сервере
            remote_temp_path = f"/tmp/xray_{host}.log"
        else:
            remote_temp_path = f"/tmp/xray_{host}.log"
        
        command = f'docker cp {container_name}:{container_log_path} {remote_temp_path}'
        print(f"📦 Копирование лога из контейнера...")
        
        success, stdout, stderr = self.execute_remote_command(client, command, timeout=120)
        
        if success:
            print(f"✅ Лог скопирован в {remote_temp_path}")
            return True
        else:
            print(f"❌ Ошибка копирования лога: {stderr}")
            return False
    
    def download_log_paramiko(self, client: paramiko.SSHClient, host: str) -> bool:
        """Скачать лог с удаленного хоста через SFTP"""
        try:
            sftp = client.open_sftp()
            remote_log_path = f"/tmp/xray_{host}.log"
            local_log_path = self.local_logs_dir / f"xray_{host}.log"
            
            print(f"📥 Скачивание лога через SFTP...")
            
            # Проверить существование удаленного файла
            try:
                remote_stat = sftp.stat(remote_log_path)
                print(f"📁 Размер удаленного файла: {remote_stat.st_size:,} байт")
            except FileNotFoundError:
                print(f"❌ Файл {remote_log_path} не найден на удаленном сервере")
                sftp.close()
                return False
            
            # Убедиться, что локальная директория существует
            self.local_logs_dir.mkdir(exist_ok=True)
            
            # Скачать файл
            sftp.get(remote_log_path, str(local_log_path))
            sftp.close()
            
            # Проверить локальный файл
            if local_log_path.exists():
                local_size = local_log_path.stat().st_size
                print(f"✅ Лог сохранен: {local_log_path} ({local_size:,} байт)")
                return True
            else:
                print(f"❌ Локальный файл не создан")
                return False
                
        except Exception as e:
            print(f"❌ Ошибка при скачивании через SFTP: {e}")
            return False
    
    def cleanup_remote_log_paramiko(self, client: paramiko.SSHClient, host: str) -> bool:
        """Удалить временный лог на удаленном хосте через Paramiko"""
        remote_log_path = f"/tmp/xray_{host}.log"
        command = f'rm -f {remote_log_path}'
        
        success, stdout, stderr = self.execute_remote_command(client, command)
        
        if success:
            print(f"🗑️ Временный лог удален")
            return True
        else:
            print(f"❌ Ошибка удаления лога: {stderr}")
            return False
    
    def collect_logs_from_host_enhanced(self, host: str, host_config: Dict[str, str], container_name: str = "remnanode", cleanup: bool = False) -> bool:
        """Полный процесс сбора логов с одного хоста через Paramiko"""
        print(f"\n🔄 Обработка хоста: {host}")
        print("-" * 50)
        
        if not self.use_paramiko:
            print("⚠️ Fallback к стандартному SSH")
            # Здесь можно добавить fallback к subprocess SSH
            return False
        
        # Создать SSH соединение
        client = self.create_ssh_connection(host_config)
        if not client:
            return False
        
        try:
            # 1. Проверить существование контейнера
            if not self.check_container_exists_paramiko(client, container_name):
                return False
            
            # 2. Скопировать лог из контейнера в /tmp
            if not self.copy_log_from_container_paramiko(client, host, container_name):
                return False
            
            # 3. Скачать лог на локальную машину
            if not self.download_log_paramiko(client, host):
                return False
            
            # 4. Очистить временный файл (опционально)
            if cleanup:
                self.cleanup_remote_log_paramiko(client, host)
            
            print(f"✅ Обработка {host} завершена успешно")
            return True
            
        finally:
            client.close()
            print(f"🔌 SSH соединение с {host} закрыто")


def create_example_ssh_config():
    """Создать пример SSH конфигурации"""
    example_config = """# Пример ~/.ssh/config для X-Ray Log Collector
# Замените значения на ваши реальные данные

# VPS Node 1
Host node1
    HostName 1.2.3.4
    User root
    Port 22
    IdentityFile ~/.ssh/id_rsa

# VPS Node 2  
Host node2
    HostName 5.6.7.8
    User ubuntu
    Port 2222
    IdentityFile ~/.ssh/id_ed25519

# VPS Node 3
Host node3
    HostName 9.10.11.12
    User debian
    Port 22
    IdentityFile ~/.ssh/id_rsa

# OpenWRT Router (будет исключен автоматически)
Host 192.168.1.1
    HostName 192.168.1.1
    User root
    Port 22
"""
    
    ssh_dir = Path.home() / ".ssh"
    config_file = ssh_dir / "config"
    
    if not ssh_dir.exists():
        print(f"📁 Создание директории {ssh_dir}")
        ssh_dir.mkdir(mode=0o700)
    
    if not config_file.exists():
        print(f"📄 Создание примера SSH config: {config_file}")
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(example_config)
        config_file.chmod(0o600)
        print("✅ Пример SSH config создан. Отредактируйте его с вашими данными.")
    else:
        print(f"ℹ️ SSH config уже существует: {config_file}")


def main():
    """Основная функция для enhanced коллектора"""
    parser = argparse.ArgumentParser(description="Enhanced X-Ray Log Collector с поддержкой Paramiko")
    parser.add_argument("--logs-dir", default="./logs", help="Локальная директория для логов")
    parser.add_argument("--container", default="remnanode", help="Имя Docker контейнера")
    parser.add_argument("--exclude", nargs="+", default=["192.168.1.1", "rtr"], help="Хосты для исключения")
    parser.add_argument("--cleanup", action="store_true", help="Автоматически удалять временные файлы")
    parser.add_argument("--all", action="store_true", help="Обработать все доступные хосты")
    parser.add_argument("--create-config", action="store_true", help="Создать пример SSH конфигурации")
    parser.add_argument("--no-paramiko", action="store_true", help="Не использовать Paramiko")
    
    args = parser.parse_args()
    
    # Создать пример конфигурации если запрошено
    if args.create_config:
        create_example_ssh_config()
        return 0
    
    print("🚀 Enhanced X-Ray Log Collector")
    print("=" * 50)
    print(f"🖥️ ОС клиента: {platform.system()}")
    print(f"✅ Paramiko доступен: {'✅' if PARAMIKO_AVAILABLE and not args.no_paramiko else '❌'}")
    print(f"📁 Локальная директория: {args.logs_dir}")
    print(f"🐳 Контейнер: {args.container}")
    
    # Инициализация SSH конфигурации
    print("\n📂 Чтение SSH конфигурации...")
    ssh_config = EnhancedSSHConfig()
    hosts_config = ssh_config.parse_ssh_config(exclude_hosts=args.exclude)
    
    if not hosts_config:
        print("❌ Не найдено доступных хостов в SSH конфигурации")
        print("💡 Используйте --create-config для создания примера")
        return 1
    
    print(f"✅ Найдено хостов: {len(hosts_config)}")
    
    # Выбор хостов
    available_hosts = list(hosts_config.keys())
    if args.all:
        selected_hosts = available_hosts
        print(f"🎯 Выбраны все хосты: {', '.join(selected_hosts)}")
    else:
        # Интерактивный выбор (упрощенная версия)
        print("\n📋 Доступные хосты:")
        for i, host in enumerate(available_hosts, 1):
            config = hosts_config[host]
            hostname = config.get('hostname', host)
            user = config.get('user', 'root')
            print(f"  {i}. {host} ({user}@{hostname})")
        
        selected_hosts = available_hosts  # Для демонстрации выбираем все
    
    # Инициализация коллектора
    use_paramiko = PARAMIKO_AVAILABLE and not args.no_paramiko
    collector = EnhancedRemoteLogCollector(local_logs_dir=args.logs_dir, use_paramiko=use_paramiko)
    
    # Обработка хостов
    print(f"\n🎯 Начинаем обработку {len(selected_hosts)} хост(ов)...")
    successful = 0
    failed = 0
    
    start_time = time.time()
    
    for host in selected_hosts:
        try:
            host_config = hosts_config[host]
            if collector.collect_logs_from_host_enhanced(host, host_config, args.container, args.cleanup):
                successful += 1
            else:
                failed += 1
        except KeyboardInterrupt:
            print("\n⏹️ Прервано пользователем")
            break
        except Exception as e:
            print(f"❌ Неожиданная ошибка при обработке {host}: {e}")
            failed += 1
        
        # Небольшая пауза между хостами
        if host != selected_hosts[-1]:
            time.sleep(1)
    
    # 5. Итоговая статистика и автоматический анализ
    elapsed_time = time.time() - start_time
    print("\n" + "=" * 50)
    print("📊 РЕЗУЛЬТАТЫ СБОРА ЛОГОВ")
    print("=" * 50)
    print(f"✅ Успешно обработано: {successful}")
    print(f"❌ Ошибок: {failed}")
    print(f"⏱️ Время выполнения: {elapsed_time:.1f} сек")
    print(f"📁 Логи сохранены в: {args.logs_dir}")
    
    if successful > 0:
        print(f"\n📋 Список сохраненных файлов:")
        logs_path = Path(args.logs_dir)
        total_size = 0
        for log_file in logs_path.glob("xray_*.log"):
            file_size = log_file.stat().st_size
            total_size += file_size
            print(f"  📄 {log_file.name} ({file_size:,} байт)")
        print(f"📦 Общий размер: {total_size:,} байт")
        
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
