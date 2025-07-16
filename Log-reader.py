import re
from collections import Counter

# Pattern for log format
log_pattern = re.compile(
    r'(?P<ip>[\d\.]+) - (?P<country>\w+) - \[(?P<date>[^\]]+)\] "(?P<method>\w+) (?P<path>[^ ]+) HTTP/[0-9.]+" (?P<status>\d+) (?P<size>\d+) "-" "(?P<useragent>[^"]+)" \d+'
)
#Counters?
ip_counter = Counter()
page_counter = Counter()
useragent_counter = Counter()
suspected_bots = set()
#  Path, to be changed soomehow to an autopath rrather than indicate path!!
with open(r'sample-log.log', 'r', encoding='utf-8') as f:

    for line in f:
        m = log_pattern.match(line)
        if m:
            ip = m.group('ip')
            page = m.group('path')
            ua = m.group('useragent')

            ip_counter[ip] += 1
            page_counter[page] += 1
            useragent_counter[ua] += 1

            # Detect bots via common keywords
            if any(bot in ua.lower() for bot in ['bot', 'crawl', 'spider', 'scrap']):
                suspected_bots.add(ip)

print("Top 10 Pages:")
for page, count in page_counter.most_common(10):
    print(f"{page}: {count}")

print("\nTop 10 IPs:")
for ip, count in ip_counter.most_common(10):
    print(f"{ip}: {count}")

print("\nTop 10 User Agents:")
for ua, count in useragent_counter.most_common(10):
    print(f"{ua}: {count}")

print("\nSuspected bot IPs:", suspected_bots)
