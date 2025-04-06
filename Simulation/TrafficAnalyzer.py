from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS
from collections import defaultdict
import threading
import queue
import numpy as np
import pickle
import os
import logging
import json
from datetime import datetime
import joblib
import pandas as pd
import requests
import time


class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface="en7"):
        def capture_thread():
            sniff(iface=interface,
                  prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda _: self.stop_capture.is_set())

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()


class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
            'inter_arrival_times': [],
            'packet_sizes': [],
            'tcp_flags_count': defaultdict(int),
            'window_sizes': []
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            # Create flow key (source to destination)
            flow_key = (ip_src, ip_dst, port_src, port_dst)
            
            # Determine direction (forward or backward)
            is_forward = True
            
            # Check if reverse flow exists but current flow doesn't
            reverse_key = (ip_dst, ip_src, port_dst, port_src)
            if reverse_key in self.flow_stats and flow_key not in self.flow_stats:
                flow_key = reverse_key
                is_forward = False

            # Update flow statistics
            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            
            # Update direction-specific counts
            if is_forward:
                stats['fwd_packet_count'] = stats.get('fwd_packet_count', 0) + 1
                stats['fwd_byte_count'] = stats.get('fwd_byte_count', 0) + len(packet)
            else:
                stats['bwd_packet_count'] = stats.get('bwd_packet_count', 0) + 1
                stats['bwd_byte_count'] = stats.get('bwd_byte_count', 0) + len(packet)
            
            # Update timing information
            current_time = packet.time
            if stats['last_time'] is not None:
                stats['inter_arrival_times'].append(current_time - stats['last_time'])
            
            # Update packet size information
            stats['packet_sizes'].append(len(packet))
            
            # Update TCP flags information
            flags = packet[TCP].flags
            stats['tcp_flags_count'][flags] += 1
            
            # Track specific flags
            if flags & 0x02:  # SYN flag (0x02)
                stats['syn_count'] = stats.get('syn_count', 0) + 1
            if flags & 0x10:  # ACK flag (0x10)
                stats['ack_count'] = stats.get('ack_count', 0) + 1
            if flags & 0x08:  # PSH flag (0x08)
                stats['psh_count'] = stats.get('psh_count', 0) + 1
            if flags & 0x04:  # RST flag (0x04)
                stats['rst_count'] = stats.get('rst_count', 0) + 1
            if flags & 0x01:  # FIN flag (0x01)
                stats['fin_count'] = stats.get('fin_count', 0) + 1
            
            # Track window sizes
            stats['window_sizes'].append(packet[TCP].window)

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return self.extract_features(packet, stats, flow_key, is_forward)

    def extract_features(self, packet, stats, flow_key, is_forward):
        """Extract features compatible with the RFE selector's expected format"""
        # Initialize features with all expected feature names
        features = {
            # ARP features
            'arp.hw.size': 0,  # Default value for non-ARP packets
            
            # ICMP features
            'icmp.checksum': 0,
            'icmp.seq_le': 0,
            
            # HTTP features
            'http.content_length': 0,
            'http.request.method': 0,
            'http.referer': 0,
            'http.response': 0,
            
            # TCP features
            'tcp.ack': packet[TCP].ack if TCP in packet else 0,
            'tcp.ack_raw': packet[TCP].ack if TCP in packet else 0,
            'tcp.dstport': packet[TCP].dport if TCP in packet else 0,
            'tcp.flags.ack': 1 if (TCP in packet and packet[TCP].flags & 0x10) else 0,
            'tcp.len': len(packet[TCP]) if TCP in packet else 0,
            'tcp.seq': packet[TCP].seq if TCP in packet else 0,
            
            # UDP features
            'udp.port': 0,
            'udp.stream': 0,
            'udp.time_delta': 0,
            
            # DNS features
            'dns.qry.name': 0,
            'dns.qry.qu': 0,
            'dns.retransmission': 0,
            'dns.retransmit_request': 0,
            
            # MQTT features
            'mqtt.msgtype': 0,
            'mqtt.topic_len': 0,
            'mqtt.ver': 0,
            
            # # Attack features - these were dropped in preprocessing
            # 'Attack_label': 0,  # Default: not an attack
            # 'Attack_type': 0,   # Default: no attack type
            
            # IP address parts
            'ip.src_1': int(packet[IP].src.split('.')[0]) if IP in packet else 0,
            'ip.src_2': int(packet[IP].src.split('.')[1]) if IP in packet else 0,
            'ip.src_3': int(packet[IP].src.split('.')[2]) if IP in packet else 0,
            'ip.src_4': int(packet[IP].src.split('.')[3]) if IP in packet else 0,
            'ip.dst_1': int(packet[IP].dst.split('.')[0]) if IP in packet else 0,
            'ip.dst_2': int(packet[IP].dst.split('.')[1]) if IP in packet else 0,
            'ip.dst_3': int(packet[IP].dst.split('.')[2]) if IP in packet else 0,
            'ip.dst_4': int(packet[IP].dst.split('.')[3]) if IP in packet else 0,
            
            # TCP flag category
            'tcp_flag_category': self.categorize_tcp_flags(packet)
        }
        
        # Add metadata (these won't be used by the model but are useful for alerts)
        features.update({
            'source_ip': packet[IP].src if IP in packet else '',
            'destination_ip': packet[IP].dst if IP in packet else '',
            'source_port': packet[TCP].sport if TCP in packet else 0,
            'destination_port': packet[TCP].dport if TCP in packet else 0,
            'flow_key': flow_key,
            
            # Add original stats for signature-based detection
            'packet_count': stats['packet_count'],
            'byte_count': stats['byte_count'],
            'flow_duration': stats['last_time'] - stats['start_time'] if stats['start_time'] else 0,
            'syn_count': stats.get('syn_count', 0),
            'ack_count': stats.get('ack_count', 0),
            'rst_count': stats.get('rst_count', 0),
            'fin_count': stats.get('fin_count', 0),
            'packet_rate': stats['packet_count'] / (stats['last_time'] - stats['start_time']) if stats['start_time'] and (stats['last_time'] - stats['start_time']) > 0 else 0,
            'current_packet_size': len(packet)
        })
        
        # Add statistical features for signature-based detection
        if len(stats['packet_sizes']) > 1:
            features.update({
                'mean_packet_size': np.mean(stats['packet_sizes']),
                'std_packet_size': np.std(stats['packet_sizes']),
                'min_packet_size': min(stats['packet_sizes']),
                'max_packet_size': max(stats['packet_sizes'])
            })
        else:
            features.update({
                'mean_packet_size': len(packet),
                'std_packet_size': 0,
                'min_packet_size': len(packet),
                'max_packet_size': len(packet)
            })
        
        return features
        
    def categorize_tcp_flags(self, packet):
        """Categorize TCP flags into a numeric value for the model"""
        if TCP not in packet:
            return 0
        
        flags = packet[TCP].flags
        if flags & 0x02:  # SYN
            return 1
        elif flags & 0x10:  # ACK
            return 2
        elif flags & 0x18:  # PSH+ACK
            return 3
        elif flags & 0x04:  # RST
            return 4
        elif flags & 0x01:  # FIN
            return 5
        return 0  # Other or no flags


class RealTimePredictor:
    def __init__(self, analyzer, endpoint_url="http://13.201.229.60:5000/predict"):
        self.analyzer = analyzer
        self.endpoint_url = endpoint_url

    def process_packets(self, packet_queue):
        while True:
            try:
                packet = packet_queue.get(timeout=5)
                features_dict = self.analyzer.analyze_packet(packet)

                if features_dict:
                    # Ensure that we only send model-relevant 32 features
                    feature_vector = self.prepare_features_for_model(features_dict)
                    if feature_vector:
                        self.send_to_model(feature_vector)

            except queue.Empty:
                continue

    def prepare_features_for_model(self, features_dict):
        # Define the exact order of the 32 features used by your RFE and model
        expected_features = [
            'arp.hw.size', 'icmp.checksum', 'icmp.seq_le', 'http.content_length', 'http.request.method',
            'http.referer', 'http.response', 'tcp.ack', 'tcp.ack_raw', 'tcp.dstport',
            'tcp.flags.ack', 'tcp.len', 'tcp.seq', 'udp.port', 'udp.stream', 'udp.time_delta',
            'dns.qry.name', 'dns.qry.qu', 'dns.retransmission', 'dns.retransmit_request',
            'mqtt.msgtype', 'mqtt.topic_len', 'mqtt.ver',
            'ip.src_1', 'ip.src_2', 'ip.src_3', 'ip.src_4',
            'ip.dst_1', 'ip.dst_2', 'ip.dst_3', 'ip.dst_4',
            'tcp_flag_category'
        ]

        try:
            feature_vector = [features_dict[feat] for feat in expected_features]
            return feature_vector
        except KeyError as e:
            print(f"[ERROR] Missing feature in dict: {e}")
            return None

    def send_to_model(self, feature_vector):
        try:
            payload = {"features": feature_vector}
            response = requests.post(self.endpoint_url, json=payload)

            if response.status_code == 200:
                result = response.json()
                print(f"[PREDICTION] Attack Type: {result['attack_type']}")
            else:
                print(f"[ERROR] Model response {response.status_code}: {response.text}")
        except Exception as e:
            print(f"[EXCEPTION] Failed to send to model: {e}")

            

if __name__ == '__main__':
    packet_capture = PacketCapture()
    analyzer = TrafficAnalyzer()
    predictor = RealTimePredictor(analyzer)

    # Start capturing packets
    packet_capture.start_capture(interface="en0")

    # Start the prediction processing thread
    processing_thread = threading.Thread(target=predictor.process_packets, args=(packet_capture.packet_queue,))
    processing_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...")
        packet_capture.stop()
        processing_thread.join()
