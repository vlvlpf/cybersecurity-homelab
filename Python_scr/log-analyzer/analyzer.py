import re
from collections import Counter

LOG_FILE = "../logs/auth.log"

failed_ips = Counter()
successful_logins = Counter()

pattern_failed = re.compile(
    r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"
)

pattern_success = re.compile(
	r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)"
)


with open(LOG_FILE, "r", errors="ignore") as file:

    for line in file:

        match_failed = pattern_failed.search(line)

        if match_failed:
            ip = match_failed.group(1)
            failed_ips[ip] += 1
            continue

        match_success = pattern_success.search(line)

        if match_success:
            user = match_success.group(1)
            ip = match_success.group(2)
            successful_logins[f"{user}@{ip}"] +=1


print("\n=== SECURITY REPORT ===\n")

for ip, count in failed_ips.most_common():

    if count >= 5:
        print(f"[ALERT] {ip}: {count} failed attempts")
    else:
        print(f"[INFO] {ip}: {count} failed attempts")


for login_info, count in successful_logins.most_common():
    print(f"[SUCCESS] Вход: {login_info} (Количество: {count})")



#-------------


threat_found = False

for login_info, success_count in successful_logins.items():
    user, ip = login_info.split("@")
    if ip in failed_ips:
        fail_count = failed_ips[ip]
        if fail_count >=5:
            print(f"[CRITICAL] ВЗЛОМ! IP {ip} ошибся {fail_count} раз, затем УСПЕШНО вошел как пользователь '{user}' (Всего входов: {success_count}).")
            threat_found = True
