from scapy.all import *
import logging
import re
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

# Memuat model dan vectorizer
model = pickle.load(open('/home/boy/Testing/AI/cyber/dataset/web_attacks/web_detect2.model','rb'))
vectorizer = pickle.load(open('/home/boy/Testing/AI/cyber/dataset/web_attacks/web_detect2.vectorizer','rb'))

label_ = np.array(["SQL Injection","XSS","Normal"])


def sniff_http(interface):
    """
    Fungsi untuk menangkap paket HTTP pada interface yang ditentukan dan melakukan logging detail.
    """
    logging.basicConfig(filename='http_traffic.log', level=logging.INFO, format='%(asctime)s - %(message)s')

    sniff(iface=interface, filter="tcp port 80", prn=process_packet, store=0)

def process_packet(packet):
    """
    Fungsi untuk memproses paket yang ditangkap.
    """
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        method = ""
        uri = ""
        payload = ""
        try:
            # Ambil alamat IP sumber
            src_ip = packet[IP].src
            # Coba parsing sebagai HTTP request
            request = packet[Raw].load.decode('utf-8')
            data_ = request.split('\r\n')
            if data_[0].find("POST") >= 0 or data_[0].find("GET") >= 0:
                #print(data_)
                method = data_[0].split()[0]
                uri = data_[0].split()[1]
                if method == 'GET':
                     payload = uri.split('?')
                     if len(payload) > 1:
                        payload = payload[-1]
                     else:
                        payload = ""
                elif method == 'POST':
                     payload = data_[-1]
                else:
                     payload =""
                
                if payload:
                     x_predict = [payload]
                     tfidf_x = vectorizer.transform(x_predict)
                     X_ = tfidf_x.toarray() 
                     y_ = model.predict(X_)
                     for i in y_:
                         attack_type = label_[np.where(i==1)[0:]]
                         if attack_type != "Normal":
                              logging.info(f"ALERT!!! {attack_type[0]} Attack, Source IP: {src_ip}, Method: {method}, Payload: {payload}")
                         else:
                              logging.info(f"{attack_type[0]} access, Source IP: {src_ip}, Method: {method}, Payload: {payload}")
                else:
                         logging.info(f"Source IP: {src_ip}, Method: {method}, Payload: {payload}")
        except UnicodeDecodeError:
            logging.info("Unable to decode packet")

if __name__ == "__main__":
    interface = "lo"  # Ganti dengan nama interface jaringan Anda
    sniff_http(interface)
