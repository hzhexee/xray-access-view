import re
import os
import argparse
import geoip2.database
import urllib.request
import chardet
from collections import defaultdict

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def detect_encoding(file_path):
    with open(file_path, "rb") as f:
        raw_data = f.read(10000)  # Читаем небольшой фрагмент файла
    result = chardet.detect(raw_data)
    return result["encoding"]

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
    for email in sorted(data.keys()):
        print(f"Email: {email}")
        for ip, info in sorted(data[email].items()):
            print(f"  IP: {ip} ({info['region_asn']})")
            for resource, destination in sorted(info["resources"].items()):
                print(f"    Resource: {resource} -> [{destination}]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", action="store_true", help="Вывести только email, количество уникальных IP и сами IP с регионами и ASN")
    args = parser.parse_args()

    default_log_file_path = "/var/lib/marzban/access.log"
    user_input_path = input(f"Укажите путь до логов (нажмите Enter для использования '{default_log_file_path}'): ").strip()
    log_file_path = user_input_path if user_input_path else default_log_file_path

    print(f"Используется путь: {log_file_path}")

    city_db_path = "/tmp/GeoLite2-City.mmdb"
    asn_db_path = "/tmp/GeoLite2-ASN.mmdb"
    city_db_url = "https://git.io/GeoLite2-City.mmdb"
    asn_db_url = "https://git.io/GeoLite2-ASN.mmdb"
    
    download_geoip_db(city_db_url, city_db_path)
    download_geoip_db(asn_db_url, asn_db_path)
    
    clear_screen()
    
    encoding = detect_encoding(log_file_path)
    print(f"Определена кодировка: {encoding}")

    with geoip2.database.Reader(city_db_path) as city_reader, geoip2.database.Reader(asn_db_path) as asn_reader:
        with open(log_file_path, "r", encoding=encoding) as file:
            logs = file.readlines()
        
        sorted_data = process_logs(logs, city_reader, asn_reader)
        print_sorted_logs(sorted_data)
