from enum import unique
import pyshark
from matplotlib import pyplot as plt

#A program for determining top talkers to the host above threshold packet count
#Renders a matplotlib distribution of source ips and the their respective packet counts

#capture = pyshark.LiveCapture(interface='en0')
src_ips_dist = []
unique_ips = []
threshold_count = 5

for packet in capture.sniff_continuously(packet_count=50):
    if packet['ip'].src not in unique_ips:
        unique_ips.append(packet['ip'].src)
        src_ips_dist.append(1)
    else:
        src_ips_dist[unique_ips.index(packet['ip'].src)] += 1

mapping = dict(zip(unique_ips, src_ips_dist))
filtered_mapping = {k:v for k,v in mapping.items() if v > threshold_count}

plt.bar(range(len(filtered_mapping.keys())), filtered_mapping.values())
plt.title("Top Talkers")
plt.ylabel("# Packets Recieved")
plt.xlabel("Source Addresses of Top Talkers")
plt.xticks(range(len(filtered_mapping.keys())), filtered_mapping.keys())

plt.show()