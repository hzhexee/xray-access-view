import argparse
import os
import re
import subprocess
import urllib.request
from argparse import Namespace
from collections import defaultdict
from enum import Enum
from typing import Optional, Tuple, Dict, Set
from datetime import datetime

import geoip2.database
from rich.text import Text
from datetime import timedelta
from rich.text import Text
from textual.app import App
from textual.widgets import Tree
from textual import events
from datetime import timedelta

region_asn_cache = {}

# Предкомпилированные регексы для лучшей производительности
LOG_PATTERN = re.compile(
    r".*?(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) "
    r"from (?P<ip>(?:[0-9a-fA-F:]+|\d+\.\d+\.\d+\.\d+|@|unix:@))?(?::\d+)? accepted (?:(tcp|udp):)?(?P<resource>[\w\.-]+(?:\.\w+)*|\d+\.\d+\.\d+\.\d+):\d+ "
    r"\[(?P<destination>[^\]]+)\](?: email: (?P<email>\S+))?"
)
IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
IPV6_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
EMAIL_NUMBER_PATTERN = re.compile(r"(\d+)\..*")
FOREIGN_IP_PATTERN = re.compile(r"^(\d+\.\d+\.\d+\.\d+):\d+$")

class TextStyle(Enum):
    RESET = 0
    BOLD = 1

class TextColor(Enum):
    BLACK = 30
    RED = 31
    GREEN = 32
    YELLOW = 33
    BLUE = 34
    MAGENTA = 35
    CYAN = 36
    WHITE = 37
    BRIGHT_BLACK = 90
    BRIGHT_RED = 91
    BRIGHT_GREEN = 92
    BRIGHT_YELLOW = 93
    BRIGHT_BLUE = 94
    BRIGHT_CYAN = 96
    BRIGHT_WHITE = 97

# === Настраиваемые цвета подсветки аутбаундов ===
OUTBOUND_CONSOLE_COLOR = TextColor.BRIGHT_YELLOW      # смените при необходимости
OUTBOUND_RICH_STYLE = "bold blue"                  # стиль Rich (можно 'bold yellow', 'red', и т.п.)

def color_text(text: str, color: TextColor) -> str:
    return f"\033[{color.value}m{text}\033[{TextStyle.RESET.value}m"

def style_text(text: str, style: TextStyle) -> str:
    return f"\033[{style.value}m{text}\033[{TextStyle.RESET.value}m"


def setup_remnawave_logs() -> str:
    """Настроить логи для Remnawave и вернуть путь к файлу логов"""
    logs_dir = "/var/log/remnalogs/"
    access_log_path = os.path.join(logs_dir, "access.log")
    
    # Проверить наличие Docker
    try:
        subprocess.run(["docker", "--version"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise RuntimeError("Docker не найден или не запущен")
    
    try:
        # Создать директорию для логов
        print(color_text("Создание директории для логов...", TextColor.BRIGHT_YELLOW))
        os.makedirs(logs_dir, exist_ok=True)
        
        # Проверить существование контейнера
        result = subprocess.run([
            "docker", "ps", "-a", "--filter", "name=remnanode", "--format", "{{.Names}}"
        ], capture_output=True, text=True, check=True)
        
        if "remnanode" not in result.stdout:
            raise RuntimeError("Контейнер 'remnanode' не найден")
        
        # Копировать логи из контейнера
        print(color_text("Копирование логов из контейнера remnanode...", TextColor.BRIGHT_YELLOW))
        subprocess.run([
            "docker", "cp", "remnanode:/var/log/supervisor/xray.out.log", access_log_path
        ], check=True, capture_output=True)
        
        print(color_text("Логи успешно скопированы.", TextColor.BRIGHT_GREEN))
        return access_log_path
        
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode() if e.stderr else str(e)
        print(color_text(f"Ошибка при копировании логов: {error_msg}", TextColor.BRIGHT_RED))
        raise
    except Exception as e:
        print(color_text(f"Неожиданная ошибка: {e}", TextColor.BRIGHT_RED))
        raise

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def download_geoip_db(db_url: str, db_path: str, without_update: bool):
    if os.path.exists(db_path):
        if without_update:
            return
        print(f"{color_text('Удаление старой базы данных:', TextColor.BRIGHT_YELLOW)} {db_path}")
        os.remove(db_path)
    print(color_text(f"Скачивание базы данных из {db_url}...", TextColor.BRIGHT_GREEN))
    urllib.request.urlretrieve(db_url, db_path)
    print(color_text("Загрузка завершена.", TextColor.BRIGHT_GREEN))

def format_date(date_str: str) -> str:
    # Handle both formats: with and without microseconds
    try:
        dt = datetime.strptime(date_str, "%Y/%m/%d %H:%M:%S.%f")
    except ValueError:
        dt = datetime.strptime(date_str, "%Y/%m/%d %H:%M:%S")
    return dt.strftime("%d.%m.%Y %H:%M:%S")

def parse_log_entry(log, filter_ip_resource, city_reader, asn_reader) -> Optional[Tuple[str, str, str, str, str]]:
    match = LOG_PATTERN.match(log)
    if not match:
        return None
    
    date = match.group(1)  # Extract the date from the first capture group
    ip = match.group("ip") or "Unknown IP"
    if ip in {"@", "unix:@"}:
        ip = "Unknown IP"
    email = match.group("email") or "Unknown Email"
    resource = match.group("resource")
    destination = match.group("destination")

    if filter_ip_resource:
        if IPV4_PATTERN.match(resource) or IPV6_PATTERN.match(resource):
            return None
    else:
        if IPV4_PATTERN.match(resource) or IPV6_PATTERN.match(resource):
            region_asn = get_region_and_asn(resource, city_reader, asn_reader)
            country = region_asn.split(",")[0]
            if country in {"Russia", "Belarus"}:
                resource = color_text(f"{resource} ({country})", TextColor.BRIGHT_RED)
            else:
                resource = f"{resource} ({country})"
    return ip, email, resource, destination, date

def extract_email_number(email):
    if email == "Unknown Email":
        return float('inf')
    match = EMAIL_NUMBER_PATTERN.match(email)
    return int(match.group(1)) if match else email

def highlight_email(email):
    return Text(email, style="bold green")

def highlight_ip(ip):
    return Text(ip, style="blue")

def highlight_resource(resource):
    highlight_domains = {
        "mycdn.me", "mvk.com", "userapi.com", "vk-apps.com", "vk-cdn.me", "vk-cdn.net", "vk-portal.net", "vk.cc",
        "vk.com", "vk.company", "vk.design", "vk.link", "vk.me", "vk.team", "vkcache.com", "vkgo.app", "vklive.app",
        "vkmessenger.app", "vkmessenger.com", "vkuser.net", "vkuseraudio.com", "vkuseraudio.net", "vkuserlive.net",
        "vkuservideo.com", "vkuservideo.net", "yandex.aero", "yandex.az", "yandex.by", "yandex.co.il", "yandex.com",
        "yandex.com.am", "yandex.com.ge", "yandex.com.ru", "yandex.com.tr", "yandex.com.ua", "yandex.de", "yandex.ee",
        "yandex.eu", "yandex.fi", "yandex.fr", "yandex.jobs", "yandex.kg", "yandex.kz", "yandex.lt", "yandex.lv",
        "yandex.md", "yandex.net", "yandex.org", "yandex.pl", "yandex.ru", "yandex.st", "yandex.sx", "yandex.tj",
        "yandex.tm", "yandex.ua", "yandex.uz", "yandexcloud.net", "yastatic.net", "dodois.com", "dodois.io", "ekatox-ru.com",
        "jivosite.com", "showip.net", "kaspersky-labs.com", "kaspersky.com"
    }
    questinable_domains = {
        "alicdn.com", "xiaomi.net", "xiaomi.com", "mi.com", "miui.com"
    }
    if any(resource == domain or resource.endswith("." + domain) for domain in highlight_domains) \
            or re.search(r"\.ru$|\.ru.com$|\.su$|\.by$|[а-яА-Я]", resource) \
            or "xn--" in resource:
        return Text(resource, style="red")
    if any(resource == domain or resource.endswith("." + domain) for domain in questinable_domains) \
            or re.search(r"\.cn$|\.citic$|\.baidu$|\.sohu$|\.unicom$", resource):
        return Text(resource, style="yellow")
    return Text(resource)

def get_region_and_asn(ip, city_reader, asn_reader):
    if ip == "Unknown IP":
        return "Unknown Country, Unknown Region, Unknown ASN"
    if ip in region_asn_cache:
        return region_asn_cache[ip]
    unknown_country = "Unknown Country"
    unknown_region = "Unknown Region"
    try:
        city_response = city_reader.city(ip)
        country = city_response.country.name or unknown_country
        region = city_response.subdivisions.most_specific.name or unknown_region
    except Exception:
        country, region = unknown_country, unknown_region
    unknown_asn = "Unknown ASN"
    try:
        asn_response = asn_reader.asn(ip)
        asn = f"AS{asn_response.autonomous_system_number} {asn_response.autonomous_system_organization}"
    except Exception:
        asn = unknown_asn
    result = f"{country}, {region}, {asn}"
    region_asn_cache[ip] = result
    return result

def process_logs(logs_iterator, city_reader, asn_reader, filter_ip_resource):
    data = defaultdict(lambda: defaultdict(dict))
    last_seen = {}
    last_seen = {}
    for log in logs_iterator:
        parsed = parse_log_entry(log, filter_ip_resource, city_reader, asn_reader)
        if parsed:
            ip, email, resource, destination, date = parsed
            region_asn = get_region_and_asn(ip, city_reader, asn_reader)
            data[email].setdefault(ip, {"region_asn": region_asn, "resources": {}, "last_seen": None})["resources"][resource] = destination
            if ip not in last_seen or last_seen[ip] < date:
                last_seen[ip] = date
                data[email][ip]["last_seen"] = date
            data[email].setdefault(ip, {"region_asn": region_asn, "resources": {}, "last_seen": None})["resources"][resource] = destination
            if ip not in last_seen or last_seen[ip] < date:
                last_seen[ip] = date
                data[email][ip]["last_seen"] = date
    return data

def process_summary(logs_iterator, city_reader, asn_reader, filter_ip_resource):
    summary = defaultdict(set)
    regions = {}
    last_seen = {}
    for log in logs_iterator:
        parsed = parse_log_entry(log, filter_ip_resource, city_reader, asn_reader)
        if parsed:
            ip, email, _, _, date = parsed
            summary[email].add(ip)
            regions[ip] = get_region_and_asn(ip, city_reader, asn_reader)
            if ip not in last_seen or last_seen[ip] < date:
                last_seen[ip] = date
    return {email: (ips, regions, last_seen) for email, ips in summary.items()}

def print_sorted_logs(data):
    for email in sorted(data.keys(), key=extract_email_number):
        print(f"Email: {highlight_email(email)}")
        for ip, info in sorted(data[email].items()):
            print(f"  IP: {highlight_ip(ip)} ({info['region_asn']})")
            for resource, destination in sorted(info["resources"].items()):
                highlighted_dest = highlight_destination_console(destination)
                print(f"    Resource: {highlight_resource(resource)} -> [{highlighted_dest}]")


def print_summary(summary):
    for email in sorted(summary.keys(), key=extract_email_number):
        ips, regions = summary[email]
        email_colored = highlight_email(email)
        unique_ips_colored = (f"{color_text('Unique IPs:', TextColor.BRIGHT_YELLOW)} "
                      f"{style_text(f'{len(ips)}', TextStyle.BOLD)}")
        print(f"Email: {email_colored}, {unique_ips_colored}")
        for ip in sorted(ips):
            print(f"  IP: {highlight_ip(ip)} ({regions[ip]})")

def extract_ip_from_foreign(foreign):
    if foreign in {"@", "unix:@"}:
        return "Unknown IP"
    match = FOREIGN_IP_PATTERN.match(foreign)
    if match:
        return match.group(1)
    parts = foreign.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return "Unknown IP"

def process_online_mode(logs_iterator, city_reader, asn_reader):
    ip_last_email = {}
    last_seen = {}
    last_seen = {}
    for log in logs_iterator:
        parsed = parse_log_entry(log, filter_ip_resource=False, city_reader=city_reader, asn_reader=asn_reader)
        if parsed:
            ip, email, _, _, date = parsed
            ip, email, _, _, date = parsed
            ip_last_email[ip] = email
            if ip not in last_seen or last_seen[ip] < date:
                last_seen[ip] = date

    try:
        result = subprocess.run(
            ["netstat", "-an"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        netstat_lines = [line for line in result.stdout.splitlines() if "ESTABLISHED" in line]
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Ошибка при выполнении netstat: {e}")
        return
    active_ips = set()
    for line in netstat_lines:
        parts = line.split()
        if len(parts) >= 5:
            foreign_address = parts[4]
            ip = extract_ip_from_foreign(foreign_address)
            active_ips.add(ip)

    relevant_ips = active_ips.intersection(ip_last_email.keys())
    email_to_ips = defaultdict(list)
    for ip in relevant_ips:
        email = ip_last_email[ip]
        email_to_ips[email].append(ip)
    if email_to_ips:
        print(
            color_text("Активные ESTABLISHED соединения (из логов) сгруппированные по email:", TextColor.BRIGHT_GREEN)
        )
        for email in sorted(email_to_ips.keys(), key=extract_email_number):
            print(f"Email: {highlight_email(email)}")
            for ip in sorted(email_to_ips[email]):
                region_asn = get_region_and_asn(ip, city_reader, asn_reader)
                last_date = format_date(last_seen[ip])
                print(f"  IP: {highlight_ip(ip)} ({region_asn}) (Last Online: {last_date})")
                last_date = format_date(last_seen[ip])
                print(f"  IP: {highlight_ip(ip)} ({region_asn}) (Last Online: {last_date})")
    else:
        print("Нет ESTABLISHED соединений, найденных в логах.")

def highlight_destination_console(destination: str) -> str:

    # Новый формат "servername -> outbound"
    if "->" in destination:
        left, right = map(str.strip, destination.split("->", 1))
        if right != "DIRECT":
            right = color_text(right, OUTBOUND_CONSOLE_COLOR)
        return f"{left} -> {right}"

    # Одиночный outbound
    if destination != "DIRECT" and " " not in destination and ":" not in destination and "->" not in destination and ">>" not in destination:
        return color_text(destination, OUTBOUND_CONSOLE_COLOR)
        
    return destination

def highlight_destination_rich(destination: str) -> Text:
    result = Text()

    # Новый формат "servername -> outbound"
    if "->" in destination:
        left, right = map(str.strip, destination.split("->", 1))
        result.append(left + " -> ")
        if right != "DIRECT":
            result.append(right, style=OUTBOUND_RICH_STYLE)
        else:
            result.append(right)
        return result
    
    # Одиночный outbound
    if destination != "DIRECT" and " " not in destination and ":" not in destination and "->" not in destination and ">>" not in destination:
        return Text(destination, style=OUTBOUND_RICH_STYLE)
        
    return Text(destination)

class LogApp(App):
    def __init__(self, data):
        super().__init__()
        self.data = data

    def on_mount(self):
        now = datetime.now()
        tree = Tree("Logs (Click)")
        for email in sorted(self.data.keys(), key=extract_email_number):
            ip_infos = self.data[email]
            unique_ip_count = len(ip_infos)
            active_ip_count = 0
            for info in ip_infos.values():
                last_seen_str = info["last_seen"].split('.', 1)[0]
                last_seen_time = datetime.strptime(last_seen_str, "%Y/%m/%d %H:%M:%S")
                if now - last_seen_time <= timedelta(days=1):
                    active_ip_count += 1
            email_node = tree.root.add(
                Text("Email: ")
                .append(highlight_email(email))
                .append(f" | Unique IP's: {unique_ip_count} | In last 24h: {active_ip_count}")
            )
            ips_info = list(ip_infos.items())
            ips_info.sort(key=lambda item: datetime.strptime(item[1]["last_seen"].split('.',1)[0], "%Y/%m/%d %H:%M:%S"), reverse=True)
            for ip, info in ips_info:
                last_dt = datetime.strptime(info["last_seen"].split('.',1)[0], "%Y/%m/%d %H:%M:%S")
                last_str = last_dt.strftime("%d.%m.%Y %H:%M:%S")
                ip_node = email_node.add(
                    Text("IP: ").append(highlight_ip(ip))
                    .append(f" ({info['region_asn']}) (Last Online: {last_str})")
                )
                for resource, dest in sorted(info["resources"].items()):
                    dest_text = highlight_destination_rich(dest)
                    line = Text("Resource: ").append(highlight_resource(resource)).append(" -> [")
                    line.append(dest_text).append("]")
                    ip_node.add_leaf(line)
        self.mount(tree)

def main(arguments: Namespace):
    try:
        # Убраны запросы к пользователю: фиксированный путь к логам Remnawave
        log_file_path = "/opt/remnawave/logs/xray.out.log"

        city_db_path = "/tmp/GeoLite2-City.mmdb"
        asn_db_path = "/tmp/GeoLite2-ASN.mmdb"
        city_db_url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
        asn_db_url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"

        download_geoip_db(city_db_url, city_db_path, arguments.without_geolite_update)
        download_geoip_db(asn_db_url, asn_db_path, arguments.without_geolite_update)

        with geoip2.database.Reader(city_db_path) as city_reader, geoip2.database.Reader(asn_db_path) as asn_reader:
            filter_ip_resource = True
            if arguments.ip:
                filter_ip_resource = False

            clear_screen()

            if arguments.online:
                with open(log_file_path, "r", encoding="utf-8", errors="ignore") as file:
                    process_online_mode(file, city_reader, asn_reader)
                return

            if arguments.summary:
                filter_ip_resource = False
                with open(log_file_path, "r", encoding="utf-8", errors="ignore") as file:
                    summary_data = process_summary(file, city_reader, asn_reader, filter_ip_resource)
                print_summary(summary_data)
            else:
                with open(log_file_path, "r", encoding="utf-8", errors="ignore") as file:
                    sorted_data = process_logs(file, city_reader, asn_reader, filter_ip_resource)
                app = LogApp(sorted_data)
                app.run()
    except Exception as e:
        print(color_text(f"Критическая ошибка: {e}", TextColor.BRIGHT_RED))
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Вывести только email, количество уникальных IP и сами IP с регионами и ASN"
    )
    parser.add_argument(
        "--ip",
        action="store_true",
        help="Вывести не только домены, но и ip")
    parser.add_argument(
        "--online",
        action="store_true",
        help="Показать ESTABLISHED соединения (из логов) с последним email доступа"
    )
    parser.add_argument(
        "-wgu", "--without-geolite-update",
        action="store_true",
        help="Не обновлять базы данных GeoLite в случае, если они существуют"
    )
    args = parser.parse_args()
    try:
        main(args)
    except KeyboardInterrupt:
        pass