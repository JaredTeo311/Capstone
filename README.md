```
# Setup the docker environment of the 5G network
cd oai-cn5g
docker-compose build
docker-compose up -d

Change the filepaths in the code to your own directory
for example the file generate_traffic.py: malicious_log_file = "/home/jared/oai-cn5g/flask_server/tmp/malicious_traffic_logs.txt"
change the filepath to your own directory

Check the files directory and run the code to install python libraries needed
# command to install python libraries
pip3 install pandas dash plotly tqdm scapy pyshark

# command to install tshark for the parsing of packets from pcap to csv
sudo apt-get install tshark

CD to your directory containing the files, and run the following commands:

# generate traffic
sudo python3 generate_traffic.py

# run rule-based detection code
sudo python3 rule_based_detection.py

# run dashboard
sudo python3 dashboard.py

Navigate to the dashboard in the browser
http://0.0.0.0:8050/

# some of the attack traffic was taken from the dataset availble here: https://github.com/IdahoLabResearch/5GAD
@INPROCEEDINGS{10008647,
  author={Coldwell, Cooper and Conger, Denver and Goodell, Edward and Jacobson, Brendan and Petersen, Bryton and Spencer, Damon and Anderson, Matthew and Sgambati, Matthew},
  booktitle={2022 IEEE Globecom Workshops (GC Wkshps)}, 
  title={Machine Learning 5G Attack Detection in Programmable Logic}, 
  year={2022},
  volume={},
  number={},
  pages={1365-1370},
  doi={10.11578/dc.20220811.1}}
```
