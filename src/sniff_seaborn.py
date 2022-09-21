import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import pyshark as ps

#A version of the sniffer written with seaborn and pandas -> seaborn takes on the pre-processing task of placing packets into 'address' bins for histogram rendering

capture = ps.LiveCapture(interface='en0')
src_ips = []

for packet in capture.sniff_continuously(packet_count=10):
    src_ips.append(packet['ip'].src)

#Seaborn pre-processing -> network capture as dataframe
details = {"Source IPs" : src_ips } 
df = pd.DataFrame(details)

#Seaborn theme set and histplot on dataframe
sns.set_theme(style="darkgrid")
sns.histplot(data=df, x="Source IPs")
plt.show()


