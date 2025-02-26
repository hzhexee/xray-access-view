import re
import os
import argparse
import geoip2.database
import urllib.request
from collections import defaultdict

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def download_geoip_db(db_url, db_path):
    if os.path.exists(db_path):
        print(f"\033[93mУдаление старой базы данных:\033[0m {db_path}")
        os.remove(db_path)
    print(f"\033[92mСкачивание базы данных из\033[0m {db_url}...")
    urllib.request.urlretrieve(db_url, db_path)
    print("\033[92mЗагрузка завершена.\033[0m")

def parse_log_entry(log, filter_ip_resource=True):
    pattern = re.compile(
        r"(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)"
        r" from (?P<ip>[\d\.]+):\d+ accepted tcp:(?P<resource>[\w\.-]+):\d+ "
        r"\[.*? -> (?P<destination>\S+)\] email: (?P<email>\S+)"
    )
    match = pattern.match(log)
    if match:
        ip = match.group("ip")
        email = match.group("email")
        resource = match.group("resource")
        destination = match.group("destination")
        if filter_ip_resource and re.match(r"^\d+\.\d+\.\d+\.\d+$", resource):
            return None
        return ip, email, resource, destination
    return None

def extract_email_number(email):
    match = re.match(r"(\d+)\..*", email)
    return int(match.group(1)) if match else float('inf')

def highlight_email(email):
    return f"\033[92m{email}\033[0m"

def highlight_ip(ip):
    return f"\033[94m{ip}\033[0m"

def highlight_resource(resource):
    highlight_domains = {
        "mycdn.me", "mvk.com", "userapi.com", "vk-apps.com", "vk-cdn.me", "vk-cdn.net", "vk-portal.net", "vk.cc", "vk.com", "vk.company",
        "vk.design", "vk.link", "vk.me", "vk.team", "vkcache.com", "vkgo.app", "vklive.app", "vkmessenger.app", "vkmessenger.com", "vkuser.net",
        "vkuseraudio.com", "vkuseraudio.net", "vkuserlive.net", "vkuservideo.com", "vkuservideo.net",
        "yandex.aero", "yandex.az", "yandex.by", "yandex.co.il", "yandex.com", "yandex.com.am", "yandex.com.ge", "yandex.com.ru", "yandex.com.tr",
        "yandex.com.ua", "yandex.de", "yandex.ee", "yandex.eu", "yandex.fi", "yandex.fr", "yandex.jobs", "yandex.kg", "yandex.kz", "yandex.lt",
        "yandex.lv", "yandex.md", "yandex.net", "yandex.org", "yandex.pl", "yandex.ru", "yandex.st", "yandex.sx", "yandex.tj", "yandex.tm",
        "yandex.ua", "yandex.uz", "yandexcloud.net", "yastatic.net"
    }

    # Проверка на соответствие домену или его поддомену
    if any(resource == domain or resource.endswith("." + domain) for domain in highlight_domains) \
       or re.search(r"\.ru$|\.su$|\.by$|[а-яА-Я]", resource) \
       or "xn--" in resource:
        return f"\033[91m{resource}\033[0m"

    return resource

def get_region_and_asn(ip, city_reader, asn_reader):
    try:
        city_response = city_reader.city(ip)
        country = city_response.country.name if city_response.country.name else "Unknown Country"
        region = city_response.subdivisions.most_specific.name if city_response.subdivisions.most_specific.name else "Unknown Region"
    except Exception:
        country, region = "Unknown Country", "Unknown Region"
    
    try:
        asn_response = asn_reader.asn(ip)
        asn = f"AS{asn_response.autonomous_system_number} {asn_response.autonomous_system_organization}"
    except Exception:
        asn = "Unknown ASN"
    
    return f"{country}, {region}, {asn}"

def process_logs(logs, city_reader, asn_reader):
    data = defaultdict(lambda: defaultdict(dict))
    for log in logs:
        parsed = parse_log_entry(log, filter_ip_resource=True)
        if parsed:
            ip, email, resource, destination = parsed
            region_asn = get_region_and_asn(ip, city_reader, asn_reader)
            data[email].setdefault(ip, {"region_asn": region_asn, "resources": {}})["resources"][resource] = destination
    return data

def print_sorted_logs(data):
    clear_screen()
    for email in sorted(data.keys(), key=extract_email_number):
        print(f"Email: {highlight_email(email)}")
        for ip, info in sorted(data[email].items()):
            print(f"  IP: {highlight_ip(ip)} ({info['region_asn']})")
            for resource, destination in sorted(info["resources"].items()):
                print(f"    Resource: {highlight_resource(resource)} -> [{destination}]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", action="store_true", help="Вывести только email, количество уникальных IP и сами IP с регионами и ASN")
    args = parser.parse_args()

    default_log_file_path = "/var/lib/marzban/access.log"
    user_input_path = input(f"Укажите путь до логов (нажмите Enter для использования '{default_log_file_path}'): ").strip()
    log_file_path = user_input_path if user_input_path else default_log_file_path

    if log_file_path == default_log_file_path:
        print(f"Используется стандартный путь: {log_file_path}")
    else:
        print(f"Используется кастомный путь: {log_file_path}")

    city_db_path = "/tmp/GeoLite2-City.mmdb"
    asn_db_path = "/tmp/GeoLite2-ASN.mmdb"
    city_db_url = "https://git.io/GeoLite2-City.mmdb"
    asn_db_url = "https://git.io/GeoLite2-ASN.mmdb"
    
    download_geoip_db(city_db_url, city_db_path)
    download_geoip_db(asn_db_url, asn_db_path)
    
    clear_screen()  # Это место для очищения экрана, оставляем только здесь

    with geoip2.database.Reader(city_db_path) as city_reader, geoip2.database.Reader(asn_db_path) as asn_reader:
        with open(log_file_path, "r") as file:
            logs = file.readlines()
        
        sorted_data = process_logs(logs, city_reader, asn_reader)
        print_sorted_logs(sorted_data)
