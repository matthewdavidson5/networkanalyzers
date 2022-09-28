import pyshark
import pandas
import seaborn as sns
import matplotlib.pyplot as plt

ports_list = []
capture = pyshark.LiveCapture(interface='en0')

for packet in capture.sniff_continuously(packet_count=10):
    try:
        ports_list.append(packet.tcp.port)
    except:
        pass

unique_ports_counter = {}
for port in ports_list:
    unique_ports_counter[port] = unique_ports_counter.get(port, 0) + 1

plt.pie(unique_ports_counter.values(), labels=unique_ports_counter.keys())
circle = plt.Circle( (0,0), 0.7, color='white')

p = plt.gcf()
p.gca().add_artist(circle)

plt.title("Top Ports in Communication")
plt.show()