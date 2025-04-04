import platform
import subprocess
from scapy.all import sniff, IP, TCP, UDP
import joblib
import numpy as np
import time
from datetime import datetime
import os
import sys
import threading

# Store detected DDoS IPs to avoid duplicate reports
detected_ips = set()
# Store logs to be written to file
ddos_logs = []
# Track when the last log file was created
last_log_time = time.time()
# Log file directory
log_dir = "ddos_logs"

def ensure_log_directory():
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

def safe_int(value):
    """Safely convert a value to int, handling FlagValue types"""
    try:
        return int(value)
    except (TypeError, ValueError):
        # For FlagValue types, convert to int using the value attribute
        if hasattr(value, 'value'):
            return int(value.value)
        # For bitfield types, convert using int()
        try:
            return int(value)
        except:
            return 0

def extract_features_from_packet(packet):
    # Initialize a feature vector with zeros for all 32 expected features
    features = np.zeros(32)
    
    # Feature extraction - adjust these based on your model's expected features
    index = 0
    
    # Basic packet features
    features[index] = len(packet) if packet else 0; index += 1
    features[index] = float(packet.time) if hasattr(packet, 'time') else 0; index += 1
    
    # IP layer features
    if IP in packet:
        features[index] = safe_int(packet[IP].version); index += 1
        features[index] = safe_int(packet[IP].ihl); index += 1
        features[index] = safe_int(packet[IP].tos); index += 1
        features[index] = safe_int(packet[IP].len); index += 1
        features[index] = safe_int(packet[IP].id); index += 1
        features[index] = safe_int(packet[IP].flags); index += 1
        features[index] = safe_int(packet[IP].frag); index += 1
        features[index] = safe_int(packet[IP].ttl); index += 1
        features[index] = safe_int(packet[IP].proto); index += 1
        
        # Handle IP addresses more safely
        try:
            src_ip_parts = packet[IP].src.split('.')
            src_ip_int = sum(int(part) << (8 * i) for i, part in enumerate(reversed(src_ip_parts)))
            features[index] = src_ip_int % 1000; index += 1
        except:
            features[index] = 0; index += 1
        
        try:
            dst_ip_parts = packet[IP].dst.split('.')
            dst_ip_int = sum(int(part) << (8 * i) for i, part in enumerate(reversed(dst_ip_parts)))
            features[index] = dst_ip_int % 1000; index += 1
        except:
            features[index] = 0; index += 1
    else:
        index += 11  # Skip IP features if not present
    
    # TCP layer features
    if TCP in packet:
        features[index] = safe_int(packet[TCP].sport); index += 1
        features[index] = safe_int(packet[TCP].dport); index += 1
        features[index] = safe_int(packet[TCP].seq) % 10000; index += 1  # Modulo to avoid overflow
        features[index] = safe_int(packet[TCP].ack) % 10000; index += 1  # Modulo to avoid overflow
        features[index] = safe_int(packet[TCP].dataofs); index += 1
        features[index] = safe_int(packet[TCP].reserved); index += 1
        features[index] = safe_int(packet[TCP].flags); index += 1
        features[index] = safe_int(packet[TCP].window); index += 1
        features[index] = safe_int(packet[TCP].urgptr); index += 1
    else:
        index += 9  # Skip TCP features if not present
    
    # UDP layer features
    if UDP in packet:
        features[index] = safe_int(packet[UDP].sport); index += 1
        features[index] = safe_int(packet[UDP].dport); index += 1
        features[index] = safe_int(packet[UDP].len); index += 1
    else:
        index += 3  # Skip UDP features if not present
    
    # Additional derived features
    features[index] = 1 if TCP in packet else 0; index += 1  # Is TCP?
    features[index] = 1 if UDP in packet else 0; index += 1  # Is UDP?
    features[index] = packet.time % 60 if hasattr(packet, 'time') else 0; index += 1  # Time modulo 60
    features[index] = packet.time % 3600 if hasattr(packet, 'time') else 0; index += 1  # Time modulo 3600
    features[index] = 0  # Padding feature if needed
    
    # Ensure we have exactly 32 features
    assert len(features) == 32, f"Expected 32 features, got {len(features)}"
    
    return features

def block_ip(ip_address):
    """Block the given IP address using iptables"""
    # Print detailed information for debugging
    print(f"Attempting to block IP: {ip_address}")
    
    try:
        # Create a custom rule name including the IP to avoid duplicates
        rule_name = f"BlockDDoS_{ip_address.replace('.', '_')}"
        
        # Direct iptables command
        cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        print(f"Executing command: {' '.join(cmd)}")
        
        # Execute the command (try without sudo first)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                # If it fails, try with sudo
                sudo_cmd = ["sudo"] + cmd
                print(f"Trying with sudo: {' '.join(sudo_cmd)}")
                result = subprocess.run(sudo_cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    print(f"Failed to block IP using iptables: {result.stderr}")
                    return False
                else:
                    print(f"Successfully blocked IP {ip_address} using sudo iptables")
                    return True
            else:
                print(f"Successfully blocked IP {ip_address}")
                return True
                
        except Exception as e:
            print(f"Exception during iptables execution: {e}")
            
            # Fallback to using a temporary script with sudo
            print("Falling back to temporary script method...")
            block_script = f"/tmp/block_ip_{ip_address.replace('.', '_')}.sh"
            
            with open(block_script, "w") as f:
                f.write("#!/bin/bash\n")
                f.write(f"iptables -A INPUT -s {ip_address} -j", "DROP\n")
            
            # Make executable
            os.chmod(block_script, 0o755)
            
            # Execute with sudo
            script_result = subprocess.run(["sudo", block_script], capture_output=True, text=True)
            
            if script_result.returncode == 0:
                print(f"Successfully blocked IP {ip_address} using script method")
                return True
            else:
                print(f"Failed to block IP using script method: {script_result.stderr}")
                return False
                
    except Exception as e:
        print(f"Failed to block IP {ip_address}: {e}")
        import traceback
        traceback.print_exc()
        return False

def detect_ddos(packet, model):
    global ddos_logs, last_log_time, detected_ips
    
    try:
        # Only process packets with IP layer
        if IP in packet:
            # Extract source IP
            src_ip = packet[IP].src
            
            # Skip localhost
            if src_ip.startswith('127.'):
                return
                
            # Extract features from the packet
            features = extract_features_from_packet(packet)
            
            # Predict using the pre-trained model
            prediction = model.predict([features])
            
            if prediction == 1:  # DDoS attack detected
                # Add debugging information
                print(f"\nDDoS detected from IP: {src_ip}")
                print(f"Packet details: {packet.summary()}")
                
                # Only log if this IP hasn't been detected in this session
                if src_ip not in detected_ips:
                    detection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log_entry = f"[{detection_time}] DDoS attack detected from IP: {src_ip}"
                    
                    # Print to console
                    print(log_entry)
                    print("Blocking IP address...")
                    
                    # Add to log collection
                    ddos_logs.append(log_entry)
                    
                    # Block the IP address
                    if block_ip(src_ip):
                        # Add to detected IPs set only if blocking was successful
                        detected_ips.add(src_ip)
                        ddos_logs.append(f"[{detection_time}] Successfully blocked IP: {src_ip}")
                    else:
                        ddos_logs.append(f"[{detection_time}] Failed to block IP: {src_ip}")
                else:
                    print(f"IP {src_ip} already detected and processed")
            
            # Check if 1 minute has passed since last log file creation
            current_time = time.time()
            if current_time - last_log_time >= 60:  # 60 seconds = 1 minute
                write_logs_to_file()
                last_log_time = current_time
                # Clear the logs after writing to file
                ddos_logs = []
    
    except Exception as e:
        print(f"Error in DDoS detection: {e}")
        import traceback
        traceback.print_exc()

def write_logs_to_file():
    if ddos_logs:
        # Create filename with current timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(log_dir, f"ddos_log_{timestamp}.txt")
        
        # Write logs to file
        with open(filename, 'w') as f:
            f.write("\n".join(ddos_logs))
        
        print(f"Logs written to {filename}")

def packet_callback_with_detection(packet, model):
    # Pass the packet to detection logic
    detect_ddos(packet, model)

def check_admin_privileges():
    """Check if the script is running with administrative privileges"""
    system_platform = platform.system()
    
    if system_platform == "Linux":
        if os.geteuid() != 0:
            print("WARNING: Not running as root.")
            print("IP blocking will not work without root privileges.")
            print("Please restart the script with sudo.")
            return False
    
    print("Running with sufficient privileges.")
    return True

def sniff_interface(interface, model):
    """Sniff packets on a specific interface"""
    print(f"Starting packet capture on interface: {interface}")
    try:
        sniff(iface=interface, prn=lambda pkt: packet_callback_with_detection(pkt, model), store=False)
    except Exception as e:
        print(f"Error capturing on interface {interface}: {e}")

def sniff_all_interfaces(model):
    """Capture packets on all available interfaces using threads"""
    system_platform = platform.system()
    
    if system_platform == "Linux":
        # Get all network interfaces
        try:
            interfaces = [iface for iface in os.listdir('/sys/class/net/') 
                         if iface != 'lo']  # Exclude loopback
        except:
            print("Failed to list network interfaces. Using default method.")
            try:
                # Fallback to sniffing without specifying interface
                print("Starting packet capture on all interfaces (default mode)")
                sniff(prn=lambda pkt: packet_callback_with_detection(pkt, model), store=False)
                return
            except Exception as e:
                print(f"Failed to capture packets: {e}")
                return
                
        # Create threads for each interface
        threads = []
        for iface in interfaces:
            thread = threading.Thread(target=sniff_interface, args=(iface, model))
            thread.daemon = True  # Allow the program to exit even if thread is running
            threads.append(thread)
            
        # Start all threads
        for thread in threads:
            thread.start()
            
        print(f"Started packet capture on {len(threads)} interfaces")
        
        # Also start a thread for the default interface (no iface specified)
        def sniff_default():
            try:
                print("Also capturing on default interface")
                sniff(prn=lambda pkt: packet_callback_with_detection(pkt, model), store=False)
            except Exception as e:
                print(f"Error capturing on default interface: {e}")
                
        default_thread = threading.Thread(target=sniff_default)
        default_thread.daemon = True
        default_thread.start()
        
        # Wait for threads - note that these won't actually end until program is terminated
        try:
            while True:
                # Check if any threads are still alive
                alive = False
                for thread in threads + [default_thread]:
                    if thread.is_alive():
                        alive = True
                        break
                
                if not alive:
                    print("All capture threads have stopped")
                    break
                    
                time.sleep(1)
        except KeyboardInterrupt:
            print("Capture interrupted by user")
    else:
        # For other platforms, use default capture
        print("Platform not explicitly supported. Using default capture method.")
        try:
            print("Starting packet capture on all interfaces")
            sniff(prn=lambda pkt: packet_callback_with_detection(pkt, model), store=False)
        except Exception as e:
            print(f"Failed to capture packets: {e}")

if __name__ == "__main__":
    # Ensure log directory exists
    ensure_log_directory()
    
    # Check for admin privileges first
    has_admin = check_admin_privileges()
    if not has_admin:
        print("Continuing anyway, but IP blocking may not work.")
        print("Press Ctrl+C to exit or any key to continue...")
        input()
    
    model_path = "random_forest_model.pkl"  # Path to your pre-trained model
    try:
        model = joblib.load(model_path)
        print("Model loaded successfully.")
    except Exception as e:
        print(f"Failed to load model: {e}")
        exit(1)
    
    try:
        # Register handler to save logs on exit
        import atexit
        atexit.register(write_logs_to_file)
        
        # Start packet capture on all interfaces
        print("Starting DDoS detection on all network interfaces...")
        print("Log files will be created every minute")
        
        # Use the new multi-interface capture function
        sniff_all_interfaces(model)
    except KeyboardInterrupt:
        print("\nStopping DDoS detection. Writing final logs...")
        write_logs_to_file()
        print("Done.")