#!/usr/bin/env python3
"""
Log Merger and Analyzer
Объединение и анализ собранных логов с нескольких серверов
"""

import os
import sys
import platform
import tempfile
from pathlib import Path
from typing import List, Dict, Optional
import argparse
from datetime import datetime

# Добавить текущую директорию в path для импорта модулей
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))


def get_temp_dir() -> str:
    """Получить кроссплатформенную временную директорию"""
    return tempfile.gettempdir()


def get_platform_specific_paths():
    """Получить специфичные для платформы пути для баз данных"""
    temp_dir = get_temp_dir()
    
    return {
        'city_db': os.path.join(temp_dir, 'GeoLite2-City.mmdb'),
        'asn_db': os.path.join(temp_dir, 'GeoLite2-ASN.mmdb')
    }


class LogMerger:
    """Класс для объединения логов с нескольких серверов"""
    
    def __init__(self, logs_dir: str = "./logs"):
        self.logs_dir = Path(logs_dir)
        self.merged_log_path = None
        
    def find_log_files(self) -> List[Path]:
        """Найти все файлы логов в директории"""
        if not self.logs_dir.exists():
            print(f"❌ Директория логов не найдена: {self.logs_dir}")
            return []
        
        log_files = list(self.logs_dir.glob("xray_*.log"))
        
        if not log_files:
            print(f"❌ Не найдено файлов логов в {self.logs_dir}")
            return []
            
        print(f"📁 Найдено файлов логов: {len(log_files)}")
        for log_file in log_files:
            size = log_file.stat().st_size
            print(f"  📄 {log_file.name} ({size:,} байт)")
            
        return log_files
    
    def merge_logs(self, log_files: List[Path], output_path: Optional[str] = None) -> str:
        """Объединить логи из нескольких файлов в один"""
        if not log_files:
            raise ValueError("Нет файлов для объединения")
        
        if output_path is None:
            # Создать временный файл
            temp_dir = tempfile.gettempdir()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(temp_dir, f"merged_xray_logs_{timestamp}.log")
        
        print(f"🔄 Объединение логов в: {output_path}")
        
        total_lines = 0
        
        try:
            with open(output_path, 'w', encoding='utf-8') as merged_file:
                for log_file in log_files:
                    print(f"  📝 Обработка {log_file.name}...")
                    
                    try:
                        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            
                        # Добавить комментарий о источнике
                        host_name = log_file.stem.replace('xray_', '')
                        merged_file.write(f"# Логи с сервера: {host_name}\n")
                        
                        # Записать строки лога
                        for line in lines:
                            if line.strip() and not line.startswith('#'):
                                merged_file.write(line)
                                total_lines += 1
                        
                        merged_file.write(f"# Конец логов с {host_name}\n\n")
                        
                    except Exception as e:
                        print(f"⚠️ Ошибка при чтении {log_file}: {e}")
                        continue
            
            print(f"✅ Объединение завершено:")
            print(f"  📊 Всего строк: {total_lines:,}")
            print(f"  📁 Файл: {output_path}")
            
            self.merged_log_path = output_path
            return output_path
            
        except Exception as e:
            print(f"❌ Ошибка при объединении логов: {e}")
            raise
    
    def create_sorted_merged_log(self, log_files: List[Path], output_path: Optional[str] = None) -> str:
        """Создать объединенный лог с сортировкой по времени"""
        if not log_files:
            raise ValueError("Нет файлов для объединения")
        
        if output_path is None:
            temp_dir = tempfile.gettempdir()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(temp_dir, f"sorted_merged_xray_logs_{timestamp}.log")
        
        print(f"🔄 Создание отсортированного объединенного лога...")
        
        # Собрать все строки с временными метками
        all_entries = []
        
        for log_file in log_files:
            print(f"  📝 Парсинг {log_file.name}...")
            host_name = log_file.stem.replace('xray_', '')
            
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Извлечь временную метку из строки лога
                    timestamp = self._extract_timestamp(line)
                    if timestamp:
                        # Добавить информацию о сервере в строку
                        enhanced_line = f"{line} [Server: {host_name}]"
                        all_entries.append((timestamp, enhanced_line))
                        
            except Exception as e:
                print(f"⚠️ Ошибка при парсинге {log_file}: {e}")
                continue
        
        # Сортировать по времени
        print(f"  📊 Сортировка {len(all_entries):,} записей...")
        all_entries.sort(key=lambda x: x[0])
        
        # Записать отсортированный лог
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(f"# Объединенный и отсортированный лог X-Ray\n")
                f.write(f"# Создан: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Источников: {len(log_files)}\n")
                f.write(f"# Записей: {len(all_entries)}\n\n")
                
                for _, line in all_entries:
                    f.write(f"{line}\n")
            
            print(f"✅ Отсортированный лог создан:")
            print(f"  📊 Записей: {len(all_entries):,}")
            print(f"  📁 Файл: {output_path}")
            
            self.merged_log_path = output_path
            return output_path
            
        except Exception as e:
            print(f"❌ Ошибка при создании отсортированного лога: {e}")
            raise
    
    def _extract_timestamp(self, log_line: str) -> Optional[datetime]:
        """Извлечь временную метку из строки лога"""
        import re
        
        # Паттерн для извлечения даты/времени из лога X-Ray
        timestamp_pattern = r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)"
        match = re.search(timestamp_pattern, log_line)
        
        if match:
            timestamp_str = match.group(1)
            try:
                # Попробовать с микросекундами
                return datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S.%f")
            except ValueError:
                try:
                    # Попробовать без микросекунд
                    return datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
                except ValueError:
                    pass
        
        return None


def analyze_merged_logs(merged_log_path: str, analysis_mode: str = "gui"):
    """Запустить анализ объединенных логов"""
    try:
        import view
        
        # Временно изменить аргументы для анализа
        original_argv = sys.argv.copy()
        
        # Настроить аргументы в зависимости от режима
        if analysis_mode == "summary":
            sys.argv = ['view.py', '--summary']
        elif analysis_mode == "online":
            sys.argv = ['view.py', '--online']
        elif analysis_mode == "ip":
            sys.argv = ['view.py', '--ip']
        elif analysis_mode == "nodes":
            sys.argv = ['view.py', '--nodes']
        else:
            sys.argv = ['view.py']  # GUI режим
        
        # Monkey patch для использования нашего лога
        original_get_log_file_path = view.get_log_file_path
        
        def mock_get_log_file_path(panel_type):
            return merged_log_path
        
        view.get_log_file_path = mock_get_log_file_path
        
        # Monkey patch для выбора панели
        original_get_panel_type = view.get_panel_type
        
        def mock_get_panel_type():
            return view.PanelType.MARZBAN  # Используем Marzban для анализа
        
        view.get_panel_type = mock_get_panel_type
        
        # Monkey patch для кроссплатформенных путей
        original_get_platform_specific_paths = view.get_platform_specific_paths
        
        def mock_get_platform_specific_paths():
            return get_platform_specific_paths()
        
        view.get_platform_specific_paths = mock_get_platform_specific_paths
        
        print(f"\n🔍 Запуск анализа объединенных логов...")
        print(f"�️ Платформа: {platform.system()}")
        print(f"�📁 Файл: {merged_log_path}")
        print(f"🎯 Режим: {analysis_mode}")
        
        # Запустить анализ
        view.main(view.argparse.Namespace(
            summary=(analysis_mode == "summary"),
            ip=(analysis_mode == "ip"),
            online=(analysis_mode == "online"),
            without_geolite_update=False,
            nodes=(analysis_mode == "nodes")  # Обновляем логику
        ))
        
        # Восстановить оригинальные функции
        view.get_log_file_path = original_get_log_file_path
        view.get_panel_type = original_get_panel_type
        view.get_platform_specific_paths = original_get_platform_specific_paths
        sys.argv = original_argv
        
    except Exception as e:
        print(f"❌ Ошибка при анализе логов: {e}")
        # Восстановить sys.argv в случае ошибки
        sys.argv = original_argv
        raise


def main():
    """Основная функция"""
    parser = argparse.ArgumentParser(description="Объединение и анализ логов X-Ray")
    parser.add_argument("--logs-dir", default="./logs", help="Директория с логами")
    parser.add_argument("--output", help="Путь для сохранения объединенного лога")
    parser.add_argument("--sort", action="store_true", help="Сортировать логи по времени")
    parser.add_argument("--analyze", choices=["gui", "summary", "online", "ip", "nodes"], default="gui", 
                       help="Режим анализа после объединения")
    parser.add_argument("--no-analyze", action="store_true", help="Не запускать анализ")
    
    args = parser.parse_args()
    
    print("🔄 Log Merger and Analyzer")
    print("=" * 50)
    print(f"🖥️ Платформа: {platform.system()}")
    print(f"📁 Временная директория: {get_temp_dir()}")
    
    # Создать объединитель логов
    merger = LogMerger(logs_dir=args.logs_dir)
    
    # Найти файлы логов
    log_files = merger.find_log_files()
    if not log_files:
        return 1
    
    try:
        # Объединить логи
        if args.sort:
            merged_path = merger.create_sorted_merged_log(log_files, args.output)
        else:
            merged_path = merger.merge_logs(log_files, args.output)
        
        # Запустить анализ если не отключен
        if not args.no_analyze:
            print("\n" + "=" * 50)
            analyze_merged_logs(merged_path, args.analyze)
        
        return 0
        
    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n👋 Прервано пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Неожиданная ошибка: {e}")
        sys.exit(1)
