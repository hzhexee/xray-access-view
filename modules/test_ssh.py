#!/usr/bin/env python3
"""
SSH Connection Tester
Тестирование SSH соединений перед сбором логов
"""

import sys
import os
from pathlib import Path
import platform

# Добавить текущую директорию в path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

from modules.enhanced_log_collector import EnhancedSSHConfig


def test_ssh_connections():
    """Тестировать SSH соединения ко всем хостам"""
    print("🧪 SSH Connection Tester")
    print("=" * 50)
    
    # Загрузить SSH конфигурацию
    ssh_config = EnhancedSSHConfig()
    hosts_config = ssh_config.parse_ssh_config()
    
    if not hosts_config:
        print("❌ Не найдено хостов в SSH конфигурации")
        return 1
    
    print(f"📋 Найдено хостов для тестирования: {len(hosts_config)}")
    
    successful = 0
    failed = 0
    
    for host, config in hosts_config.items():
        print(f"\n🔍 Тестирование {host}...")
        print("-" * 30)
        
        hostname = config.get('hostname', host)
        port = config.get('port', '22')
        user = config.get('user', 'root')
        
        print(f"  Хост: {hostname}:{port}")
        print(f"  Пользователь: {user}")
        
        # Тест ping (опционально)
        print(f"  🏓 Ping {hostname}...", end=" ")
        ping_cmd = f"ping -c 1 {hostname}" if platform.system() != "Windows" else f"ping -n 1 {hostname}"
        ping_result = os.system(f"{ping_cmd} >nul 2>&1" if platform.system() == "Windows" else f"{ping_cmd} >/dev/null 2>&1")
        
        if ping_result == 0:
            print("✅ Доступен")
        else:
            print("❌ Недоступен")
        
        # Тест SSH соединения
        if PARAMIKO_AVAILABLE:
            print(f"  🔐 SSH подключение...", end=" ")
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                key_file = config.get('identityfile')
                if key_file:
                    key_file = os.path.expanduser(key_file)
                
                if key_file and os.path.exists(key_file):
                    client.connect(hostname, port=int(port), username=user, key_filename=key_file, timeout=10)
                else:
                    client.connect(hostname, port=int(port), username=user, timeout=10)
                
                # Тест простой команды
                stdin, stdout, stderr = client.exec_command('echo "SSH OK"', timeout=5)
                result = stdout.read().decode().strip()
                
                if result == "SSH OK":
                    print("✅ Успешно")
                    successful += 1
                else:
                    print("❌ Команда не выполнилась")
                    failed += 1
                
                client.close()
                
            except Exception as e:
                print(f"❌ Ошибка: {e}")
                failed += 1
        else:
            print("  ⚠️ Paramiko недоступен, пропуск SSH теста")
            failed += 1
    
    # Итоги
    print("\n" + "=" * 50)
    print("📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ")
    print("=" * 50)
    print(f"✅ Успешных соединений: {successful}")
    print(f"❌ Неудачных соединений: {failed}")
    
    if failed > 0:
        print("\n💡 Рекомендации:")
        print("  - Проверьте SSH ключи")
        print("  - Убедитесь в правильности hostname и портов")
        print("  - Проверьте доступность серверов")
        
    return 0 if failed == 0 else 1


def main():
    """Главная функция"""
    try:
        return test_ssh_connections()
    except KeyboardInterrupt:
        print("\n👋 Тестирование прервано")
        return 1
    except Exception as e:
        print(f"\n❌ Ошибка: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
