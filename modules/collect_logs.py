#!/usr/bin/env python3
"""
X-Ray Log Collector Launcher
Главный скрипт для запуска коллектора логов
"""

import sys
import os
from pathlib import Path

# Добавить текущую директорию в path для импорта модулей
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


def main():
    """Главная функция для выбора типа коллектора"""
    print("🚀 X-Ray Log Collector")
    print("=" * 50)
    
    if PARAMIKO_AVAILABLE:
        print("✅ Paramiko доступен - рекомендуется Enhanced коллектор")
        print("\nВыберите действие:")
        print("1. Стандартный коллектор (subprocess SSH)")
        print("2. Enhanced коллектор (Paramiko SSH) - рекомендуется")
        print("3. Анализ ранее собранных логов")
        print("4. Создать пример SSH конфигурации")
        
        while True:
            choice = input("\nВаш выбор (1-4): ").strip()
            
            if choice == "1":
                print("\n🔄 Запуск стандартного коллектора...")
                import log_collector
                return log_collector.main()
                
            elif choice == "2":
                print("\n🔄 Запуск Enhanced коллектора...")
                import modules.enhanced_log_collector as enhanced_log_collector
                return enhanced_log_collector.main()
            
            elif choice == "3":
                print("\n🔍 Запуск анализа логов...")
                import log_merger
                return log_merger.main()
                
            elif choice == "4":
                print("\n📄 Создание примера SSH конфигурации...")
                import modules.enhanced_log_collector as enhanced_log_collector
                enhanced_log_collector.create_example_ssh_config()
                return 0
                
            else:
                print("❌ Неверный выбор. Введите 1, 2, 3 или 4")
    else:
        print("⚠️ Paramiko недоступен - используется стандартный коллектор")
        print("💡 Для установки Paramiko: pip install paramiko")
        print("\nВыберите действие:")
        print("1. Стандартный коллектор")
        print("2. Анализ ранее собранных логов")
        
        while True:
            choice = input("\nВаш выбор (1-2): ").strip()
            
            if choice == "1":
                print("\n🔄 Запуск стандартного коллектора...")
                import log_collector
                return log_collector.main()
            
            elif choice == "2":
                print("\n🔍 Запуск анализа логов...")
                import log_merger
                return log_merger.main()
            
            else:
                print("❌ Неверный выбор. Введите 1 или 2")


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
