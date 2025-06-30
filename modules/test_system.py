#!/usr/bin/env python3
"""
Test Script for Updated Log Collector
Тестовый скрипт для проверки обновленного коллектора
"""

import sys
import os
from pathlib import Path

# Добавить текущую директорию в path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def test_ssh_config_parsing():
    """Тестировать парсинг SSH конфигурации"""
    print("🧪 Тестирование парсинга SSH конфигурации")
    print("-" * 50)
    
    try:
        from modules.enhanced_log_collector import EnhancedSSHConfig
        
        ssh_config = EnhancedSSHConfig()
        hosts_config = ssh_config.parse_ssh_config()
        
        print(f"📋 Найдено хостов: {len(hosts_config)}")
        
        for host, config in hosts_config.items():
            hostname = config.get('hostname', host)
            user = config.get('user', 'root')
            port = config.get('port', '22')
            print(f"  ✅ {host}: {user}@{hostname}:{port}")
        
        # Проверить исключения
        if 'rtr' in hosts_config:
            print("❌ ОШИБКА: Роутер 'rtr' не должен быть в списке")
            return False
        
        if any('192.168.' in config.get('hostname', '') for config in hosts_config.values()):
            print("❌ ОШИБКА: Локальные IP не должны быть в списке")
            return False
        
        print("✅ Тест парсинга SSH конфигурации прошел успешно")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка при тестировании SSH конфигурации: {e}")
        return False

def test_log_merger():
    """Тестировать объединитель логов"""
    print("\n🧪 Тестирование объединителя логов")
    print("-" * 50)
    
    try:
        from log_merger import LogMerger
        
        # Создать тестовую директорию с логами
        test_logs_dir = Path("./test_logs")
        test_logs_dir.mkdir(exist_ok=True)
        
        # Создать тестовые файлы логов
        test_log1 = test_logs_dir / "xray_server1.log"
        test_log2 = test_logs_dir / "xray_server2.log"
        
        with open(test_log1, 'w') as f:
            f.write("2025/06/30 12:00:00 from 1.2.3.4:12345 accepted tcp:example.com:443 [outbound] email: user1@domain.com\n")
        
        with open(test_log2, 'w') as f:
            f.write("2025/06/30 12:01:00 from 5.6.7.8:54321 accepted tcp:test.com:443 [outbound] email: user2@domain.com\n")
        
        # Тестировать merger
        merger = LogMerger(logs_dir=str(test_logs_dir))
        log_files = merger.find_log_files()
        
        if len(log_files) != 2:
            print(f"❌ ОШИБКА: Ожидалось 2 файла, найдено {len(log_files)}")
            return False
        
        # Тестировать объединение
        merged_path = merger.merge_logs(log_files)
        
        if not os.path.exists(merged_path):
            print("❌ ОШИБКА: Объединенный файл не создан")
            return False
        
        # Проверить содержимое
        with open(merged_path, 'r') as f:
            content = f.read()
        
        if "server1" not in content or "server2" not in content:
            print("❌ ОШИБКА: Не все серверы представлены в объединенном логе")
            return False
        
        # Очистить тестовые файлы
        test_log1.unlink()
        test_log2.unlink()
        test_logs_dir.rmdir()
        os.unlink(merged_path)
        
        print("✅ Тест объединителя логов прошел успешно")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка при тестировании объединителя логов: {e}")
        return False

def test_imports():
    """Тестировать импорты модулей"""
    print("\n🧪 Тестирование импортов модулей")
    print("-" * 50)
    
    modules_to_test = [
        ('log_collector', 'Стандартный коллектор'),
        ('enhanced_log_collector', 'Enhanced коллектор'),
        ('collect_logs', 'Launcher'),
        ('log_merger', 'Объединитель логов'),
        ('view', 'Основной анализатор')
    ]
    
    success_count = 0
    
    for module_name, description in modules_to_test:
        try:
            __import__(module_name)
            print(f"  ✅ {description}: OK")
            success_count += 1
        except ImportError as e:
            print(f"  ❌ {description}: ОШИБКА - {e}")
    
    print(f"\n📊 Результат: {success_count}/{len(modules_to_test)} модулей загружены успешно")
    return success_count == len(modules_to_test)

def main():
    """Главная функция тестирования"""
    print("🚀 Тестирование X-Ray Log Collector")
    print("=" * 50)
    
    tests = [
        ("Импорты модулей", test_imports),
        ("SSH конфигурация", test_ssh_config_parsing),
        ("Объединитель логов", test_log_merger)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"❌ Критическая ошибка в тесте '{test_name}': {e}")
    
    print("\n" + "=" * 50)
    print("📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ")
    print("=" * 50)
    print(f"✅ Пройдено: {passed}")
    print(f"❌ Не пройдено: {total - passed}")
    print(f"📈 Успешность: {passed/total*100:.1f}%")
    
    if passed == total:
        print("\n🎉 Все тесты пройдены успешно!")
        print("💡 Система готова к использованию")
    else:
        print("\n⚠️ Есть проблемы, требующие внимания")
    
    return 0 if passed == total else 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n👋 Тестирование прервано")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        sys.exit(1)
