import argparse
import os
import re
import urllib.request
from argparse import Namespace
from collections import defaultdict
from enum import Enum
from datetime import datetime

import geoip2.database
from rich.text import Text
from textual.app import App
from textual.widgets import Tree
from textual import events

region_asn_cache = {}

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

def color_text(text: str, color: TextColor) -> str:
    return f"\033[{color.value}m{text}\033[{TextStyle.RESET.value}m"

def style_text(text: str, style: TextStyle) -> str:
    return f"\033[{style.value}m{text}\033[{TextStyle.RESET.value}m"

def get_log_file_path() -> str:
    default_log_file_path = "/var/lib/marzban/access.log"
    while True:
        user_input_path = input(
            f"Укажите путь до логов (нажмите Enter для использования '{default_log_file_path}'): "
        ).strip()
        log_file_path = user_input_path or default_log_file_path
        if os.path.exists(log_file_path):
            return log_file_path
        print(f"Ошибка: файл по пути '{log_file_path}' не существует.")

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

def parse_log_entry(log, filter_ip_resource, city_reader, asn_reader):
    pattern = re.compile(
        r".*?(?P<date>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) "
        r"from (?P<ip>(?:[0-9a-fA-F:]+|\d+\.\d+\.\d+\.\d+|@|unix:@))?(?::\d+)? accepted (?:(tcp|udp):)?(?P<resource>[\w\.-]+(?:\.\w+)*|\d+\.\d+\.\d+\.\d+):\d+ "
        r"\[(?P<destination>[^\]]+)\](?: email: (?P<email>\S+))?"
    )
    match = pattern.match(log)
    if match:
        ip = match.group("ip") or "Unknown IP"
        date = match.group("date")
        if ip in {"@", "unix:@"}:
            ip = "Unknown IP"
        email = match.group("email") or "Unknown Email"
        resource = match.group("resource")
        destination = match.group("destination")
        ipv4_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
        ipv6_pattern = re.compile(r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
        if filter_ip_resource:
            if ipv4_pattern.match(resource) or ipv6_pattern.match(resource):
                return None
        else:
            if ipv4_pattern.match(resource) or ipv6_pattern.match(resource):
                region_asn = get_region_and_asn(resource, city_reader, asn_reader)
                country = region_asn.split(",")[0]
                if country in {"Russia", "Belarus"}:
                    resource = color_text(f"{resource} ({country})", TextColor.BRIGHT_RED)
                else:
                    resource = f"{resource} ({country})"
        return ip, email, resource, destination, date
    return None

def extract_email_number(email):
    if email == "Unknown Email":
        return float('inf')
    match = re.match(r"(\d+)\..*", email)
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
    for log in logs_iterator:
        parsed = parse_log_entry(log, filter_ip_resource, city_reader, asn_reader)
        if parsed:
            ip, email, resource, destination, date = parsed
            region_asn = get_region_and_asn(ip, city_reader, asn_reader)
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

def extract_ip_from_foreign(foreign):
    if foreign in {"@", "unix:@"}:
        return "Unknown IP"
    m = re.match(r"^(\d+\.\d+\.\d+\.\d+):\d+$", foreign)
    if m:
        return m.group(1)
    parts = foreign.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return "Unknown IP"

def process_online_mode(logs_iterator, city_reader, asn_reader):
    ip_last_email = {}
    last_seen = {}
    for log in logs_iterator:
        parsed = parse_log_entry(log, filter_ip_resource=False, city_reader=city_reader, asn_reader=asn_reader)
        if parsed:
            ip, email, _, _, date = parsed
            ip_last_email[ip] = email
            if ip not in last_seen or last_seen[ip] < date:
                last_seen[ip] = date
    try:
        netstat_output = os.popen("netstat -an | grep ESTABLISHED").read().strip().splitlines()
    except Exception as e:
        print(f"Ошибка при выполнении netstat: {e}")
        return
    active_ips = set()
    for line in netstat_output:
        parts = line.split()
        if len(parts) < 6:
            continue
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
    else:
        print("Нет ESTABLISHED соединений, найденных в логах.")

class LogApp(App):
    def __init__(self, data):
        super().__init__()
        self.data = data

    def on_mount(self):
        tree = Tree("Logs (Click)")
        for email in sorted(self.data.keys(), key=extract_email_number):
            email_text = Text("Email: ").append(highlight_email(email))
            email_node = tree.root.add(email_text)
            for ip, info in sorted(self.data[email].items()):
                last_date = format_date(info["last_seen"])
                ip_text = Text("IP: ").append(highlight_ip(ip)).append(f" ({info['region_asn']}) (Last Online: {last_date})")
                ip_node = email_node.add(ip_text)
                for resource, destination in sorted(info["resources"].items()):
                    resource_text = Text("Resource: ").append(highlight_resource(resource)).append(f" -> [{destination}]")
                    ip_node.add_leaf(resource_text)
        self.mount(tree)

    def on_key(self, event: events.Key):
        if event.key == "q":
            self.exit()

class SummaryApp(App):
    def __init__(self, summary):
        super().__init__()
        self.summary = summary

    def on_mount(self):
        tree = Tree("Summary (Click)")
        for email in sorted(self.summary.keys(), key=extract_email_number):
            ips, regions, last_seen = self.summary[email]
            email_text = Text("Email: ").append(highlight_email(email)).append(f", Unique IPs: {len(ips)}")
            email_node = tree.root.add(email_text)
            for ip in sorted(ips):
                last_date = format_date(last_seen[ip])
                ip_text = Text("IP: ").append(highlight_ip(ip)).append(f" ({regions[ip]}) (Last Online: {last_date})")
                email_node.add_leaf(ip_text)
        self.mount(tree)

    def on_key(self, event: events.Key):
        if event.key == "q":
            self.exit()

def main(arguments: Namespace):
    log_file_path = get_log_file_path()
    city_db_path = "/tmp/GeoLite2-City.mmdb"
    asn_db_path = "/tmp/GeoLite2-ASN.mmdb"
    city_db_url = "https://git.io/GeoLite2-City.mmdb"
    asn_db_url = "https://git.io/GeoLite2-ASN.mmdb"
    download_geoip_db(city_db_url, city_db_path, arguments.without_geolite_update)
    download_geoip_db(asn_db_url, asn_db_path, arguments.without_geolite_update)

    with geoip2.database.Reader(city_db_path) as city_reader, geoip2.database.Reader(asn_db_path) as asn_reader:
        filter_ip_resource = True
        if arguments.ip:
            filter_ip_resource = False
        clear_screen()
        if arguments.online:
            with open(log_file_path, "r") as file:
                process_online_mode(file, city_reader, asn_reader)
            exit(0)
        if arguments.summary:
            filter_ip_resource = False
            with open(log_file_path, "r") as file:
                summary_data = process_summary(file, city_reader, asn_reader, filter_ip_resource)
            app = SummaryApp(summary_data)
            app.run()
        else:
            with open(log_file_path, "r") as file:
                sorted_data = process_logs(file, city_reader, asn_reader, filter_ip_resource)
            app = LogApp(sorted_data)
            app.run()

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
