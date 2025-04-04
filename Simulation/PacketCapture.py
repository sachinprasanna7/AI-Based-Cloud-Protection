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


class EdgeIIoTDetectionEngine:
    def __init__(self, model_path=None, rfe_selector_path=None):
        self.model = None
        self.rfe_selector = None
        # self.signature_rules = self.load_signature_rules()
        self.attack_types = {}
        
        # Load RFE selector if provided
        if rfe_selector_path and os.path.exists(rfe_selector_path):
            self.load_rfe_selector(rfe_selector_path)
            
        # Load pre-trained model if provided
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
        
    def load_rfe_selector(self, rfe_selector_path):
        """Load the RFE feature selector"""
        try:
            self.rfe_selector = joblib.load(rfe_selector_path)
            print(f"Successfully loaded RFE selector from {rfe_selector_path}")
            
            # Get the feature names from the RFE selector
            if hasattr(self.rfe_selector, 'feature_names_in_'):
                # Get all original feature names
                all_features = self.rfe_selector.feature_names_in_
                
                # Get mask of selected features
                feature_mask = self.rfe_selector.support_
                
                # Get names of only the selected features
                self.selected_features = [
                    name for name, selected in zip(all_features, feature_mask) 
                    if selected
                ]
                
                print(f"RFE selector is using {len(self.selected_features)} out of {len(all_features)} features")
                print(f"Selected features: {self.selected_features}")
            else:
                print("Warning: RFE selector loaded but feature names not available")
                
        except Exception as e:
            print(f"Error loading RFE selector: {e}")
            self.rfe_selector = None
        
    def load_model(self, model_path):
        """Load a pre-trained model from file"""
        try:
            self.model = joblib.load(model_path)
            print(f"Successfully loaded model from {model_path}")
            
            # Try to extract attack types from model if available
            if hasattr(self.model, 'classes_'):
                self.attack_types = {i: cls for i, cls in enumerate(self.model.classes_)}
                print(f"Detected attack types: {self.attack_types}")
                
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model = None

    # def load_signature_rules(self):
    #     """Load signature-based detection rules"""
    #     return {
    #         'syn_flood': {
    #             'condition': lambda features: (
    #                 features.get('syn_count', 0) > 10 and
    #                 features.get('packet_rate', 0) > 100
    #             )
    #         },
    #         'port_scan': {
    #             'condition': lambda features: (
    #                 features.get('current_packet_size', 0) < 100 and
    #                 features.get('packet_rate', 0) > 50
    #             )
    #         },
    #         'dos_attack': {
    #             'condition': lambda features: (
    #                 features.get('packet_rate', 0) > 200 and
    #                 features.get('mean_packet_size', 0) > 1000
    #             )
    #         },
    #         'brute_force': {
    #             'condition': lambda features: (
    #                 features.get('syn_count', 0) > 5 and
    #                 features.get('rst_count', 0) > 5 and
    #                 features.get('flow_duration', 0) < 10
    #             )
    #         }
    #     }

    def prepare_feature_vector(self, features):
        """Extract and normalize relevant features for the model"""
        if self.rfe_selector:
            try:
                # Create a pandas DataFrame with the same structure as training data
                # Extract the expected feature names from the RFE selector
                feature_names = self.rfe_selector.feature_names_in_
                
                # Create a single-row DataFrame with all expected features
                # Use 0 as default for any missing features
                feature_dict = {feature: features.get(feature, 0) for feature in feature_names}
                feature_df = pd.DataFrame([feature_dict])
                
                # Transform using RFE
                return self.rfe_selector.transform(feature_df)
                
            except Exception as e:
                print(f"Error applying RFE selection: {e}")
                print(f"Available features: {list(features.keys())}")
                print(f"Expected features: {list(self.rfe_selector.feature_names_in_)}")
                # Fall back to original feature vector - with better error handling
                if hasattr(self, 'selected_features') and len(self.selected_features) > 0:
                    return np.array([[features.get(feature, 0) for feature in self.selected_features]])
                else:
                    print("No selected features available, prediction may be inaccurate")
                    return np.array([[0]])
        else:
            # Without RFE, use all numeric features except metadata
            numeric_features = []
            for key, value in features.items():
                if key not in ['source_ip', 'destination_ip', 'source_port', 'destination_port', 'flow_key'] and isinstance(value, (int, float)):
                    numeric_features.append(value)
            return np.array([numeric_features])

    def detect_threats(self, features):
        """Detect threats using both signature-based and ML-based detection"""
        threats = []

        # # 1. Signature-based detection
        # for rule_name, rule in self.signature_rules.items():
        #     try:
        #         if rule['condition'](features):
        #             threats.append({
        #                 'type': 'signature',
        #                 'rule': rule_name,
        #                 'confidence': 1.0,
        #                 'severity': 'high' if rule_name in ['syn_flood', 'dos_attack'] else 'medium'
        #             })
        #     except Exception as e:
        #         print(f"Error applying rule {rule_name}: {e}")

        # 2. ML-based detection with pre-trained model
        if self.model:
            try:
                feature_vector = self.prepare_feature_vector(features)
                
                # Get prediction from model
                prediction = self.model.predict(feature_vector)[0]
                
                # Convert prediction to string if it's numeric
                if isinstance(prediction, (int, np.integer)):
                    predicted_class = self.attack_types.get(int(prediction), f"class_{prediction}")
                else:
                    predicted_class = str(prediction)
                
                # Get prediction probabilities if available
                if hasattr(self.model, 'predict_proba'):
                    probabilities = self.model.predict_proba(feature_vector)[0]
                    max_prob = probabilities[np.argmax(probabilities)]
                else:
                    max_prob = 0.85  # Default confidence for models without probabilities
                
                # Report all non-normal predictions as threats
                if str(predicted_class).lower() not in ['normal', 'benign']:
                    threats.append({
                        'type': 'ml_detection',
                        'attack_type': predicted_class,
                        'confidence': float(max_prob),
                        'severity': 'high' if max_prob > 0.8 else 'medium',
                        'all_probabilities': {
                            self.attack_types.get(i, str(i)): float(prob) 
                            for i, prob in enumerate(probabilities) if hasattr(self.model, 'predict_proba')
                        } if hasattr(self.model, 'predict_proba') else {}
                    })
                        
            except Exception as e:
                print(f"Error in ML detection: {e}")
                import traceback
                traceback.print_exc()

        return threats


class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        # Ensure we don't add duplicate handlers
        if not self.logger.handlers:
            # File handler for all alerts
            file_handler = logging.FileHandler(log_file)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
            
            # Console handler for high-severity alerts
            console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(
                '\033[91m%(asctime)s - ALERT - %(message)s\033[0m'  # Red text
            )
            console_handler.setFormatter(console_formatter)
            console_handler.setLevel(logging.WARNING)
            self.logger.addHandler(console_handler)
            
        # Counter for alerts
        self.alert_count = defaultdict(int)
        self.last_report_time = datetime.now()

    def generate_alert(self, threat, packet_info):
        """Generate and log an alert based on the detected threat"""
        threat_key = f"{threat['type']}_{threat.get('rule', threat.get('attack_type', 'unknown'))}"
        self.alert_count[threat_key] += 1
        
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'source_port': packet_info.get('source_port'),
            'destination_port': packet_info.get('destination_port'),
            'confidence': threat.get('confidence', 0.0),
            'severity': threat.get('severity', 'medium'),
            'details': {k: v for k, v in threat.items() if k not in ['type', 'confidence', 'severity']}
        }

        # # Log based on severity
        # if threat.get('severity') == 'high':
        #     self.logger.critical(json.dumps(alert))
        # else:
        #     self.logger.warning(json.dumps(alert))

        # Report statistics periodically (every minute)
        current_time = datetime.now()
        if (current_time - self.last_report_time).total_seconds() > 60:
            self.report_statistics()
            self.last_report_time = current_time
    
    def report_statistics(self):
        """Report alert statistics"""
        if sum(self.alert_count.values()) > 0:
            stats = {
                'timestamp': datetime.now().isoformat(),
                'total_alerts': sum(self.alert_count.values()),
                'alerts_by_type': dict(self.alert_count)
            }
            # self.logger.info(f"Alert Statistics: {json.dumps(stats)}")


class IntrusionDetectionSystem:
    def __init__(self, interface="en7", model_path=None, rfe_selector_path=None):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = EdgeIIoTDetectionEngine(
            model_path=model_path, 
            rfe_selector_path=rfe_selector_path
        )
        self.alert_system = AlertSystem()
        self.interface = interface
        self.stats_interval = 60  # seconds
        self.last_stats_time = datetime.now()
        self.processed_packets = 0
        self.detected_threats = 0

    def start(self):
        """Start the IDS"""
        print(f"Starting IDS on interface {self.interface}")

        # Check model status
        if self.detection_engine.model and self.detection_engine.rfe_selector:
            print("Using pre-trained Edge-IIoTset model with RFE feature selection")
        elif self.detection_engine.model:
            print("Using pre-trained model without RFE feature selection")
        else:
            print("Warning: No ML model loaded, falling back to signature-based detection only")
            
        self.packet_capture.start_capture(self.interface)

        try:
            while True:
                try:
                    packet = self.packet_capture.packet_queue.get(timeout=1)
                    self.processed_packets += 1
                    
                    features = self.traffic_analyzer.analyze_packet(packet)
                    if features:
                        threats = self.detection_engine.detect_threats(features)
                        
                        for threat in threats:
                            self.detected_threats += 1
                            packet_info = {
                                'source_ip': features['source_ip'],
                                'destination_ip': features['destination_ip'],
                                'source_port': features['source_port'],
                                'destination_port': features['destination_port']
                            }
                            self.alert_system.generate_alert(threat, packet_info)
                    
                    # Print stats periodically
                    current_time = datetime.now()
                    if (current_time - self.last_stats_time).total_seconds() > self.stats_interval:
                        self.print_statistics()
                        self.last_stats_time = current_time
                        
                except queue.Empty:
                    continue
                    
        except KeyboardInterrupt:
            print("\nStopping IDS...")
            self.packet_capture.stop()
            self.print_statistics(final=True)
    
    def print_statistics(self, final=False):
        """Print IDS statistics"""
        duration = (datetime.now() - self.last_stats_time).total_seconds()
        if not final:
            packets_per_second = self.processed_packets / duration if duration > 0 else 0
            print(f"\n--- IDS Statistics (last {duration:.1f} seconds) ---")
            print(f"Packets processed: {self.processed_packets} ({packets_per_second:.1f}/sec)")
            print(f"Threats detected: {self.detected_threats}")
            print(f"Active flows: {len(self.traffic_analyzer.flow_stats)}")
            # Reset counters
            self.processed_packets = 0
            self.detected_threats = 0
        else:
            # Final statistics
            print("\n--- Final IDS Statistics ---")
            print(f"Total flows analyzed: {len(self.traffic_analyzer.flow_stats)}")
            print(f"Alert counts: {dict(self.alert_system.alert_count)}")
            

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Edge-IIoTset Intrusion Detection System')
    parser.add_argument('--interface', '-i', type=str, default="en7", 
                        help='Network interface to capture packets')
    parser.add_argument('--model', '-m', type=str, default="../Models/gradient_boosting.pkl",
                        help='Path to pre-trained Gradient Boosting model file')
    parser.add_argument('--rfe', '-r', type=str, default="../Models/rfe_selector.pkl",
                        help='Path to RFE feature selector file')
    args = parser.parse_args()
    
    ids = IntrusionDetectionSystem(
        interface=args.interface, 
        model_path=args.model,
        rfe_selector_path=args.rfe
    )
    ids.start()