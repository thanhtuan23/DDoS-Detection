import platform
import subprocess
from scapy.all import sniff, IP, TCP, UDP
import joblib
import numpy as np
import time
from datetime import datetime
import os
import sys

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
    """Block the given IP address using system-specific firewall commands"""
    system_platform = platform.system()
    
    # Print detailed information for debugging
    print(f"Attempting to block IP: {ip_address} on {system_platform}")
    
    try:
        if system_platform == "Linux":
            # Check if running as root
            # if os.geteuid() != 0:
            #     print("Warning: Not running as root. IP blocking may fail.")
            #     print("Try running the script with sudo.")
            
            # Use iptables to block the IP
            cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
            print(f"Executing command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Command failed with error: {result.stderr}")
                # Try alternative approach with sudo
                print("Trying with sudo...")
                cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"Sudo command also failed: {result.stderr}")
                else:
                    print("Successfully blocked IP with sudo")
            else:
                print("Successfully blocked IP")
                
        # elif system_platform == "Windows":
            # Running with admin privileges check
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                print("Warning: Not running with administrator privileges. IP blocking may fail.")
                print("Try running the script as Administrator.")
                
            # Use netsh to block the IP on Windows
            rule_name = f"BlockDDoS_{ip_address.replace('.', '_')}"
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule", 
                   f"name={rule_name}", "dir=in", "action=block", 
                   f"remoteip={ip_address}"]
            print(f"Executing command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Command failed with error: {result.stderr}")
                # Try alternative approach for Windows
                try:
                    # Create a temporary batch file to execute with elevated privileges
                    batch_file = f"block_ip_{ip_address.replace('.', '_')}.bat"
                    with open(batch_file, 'w') as f:
                        f.write(f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}\n')
                    
                    # Execute the batch file with elevated privileges
                    print(f"Trying to execute batch file: {batch_file}")
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f"/c {batch_file}", None, 1)
                    print(f"Batch file execution initiated. Check for UAC prompt.")
                except Exception as e:
                    print(f"Alternative approach failed: {e}")
            else:
                print("Successfully blocked IP")
        else:
            print(f"Unsupported platform: {system_platform}")
            
    except Exception as e:
        print(f"Failed to block IP {ip_address}: {e}")
        import traceback
        traceback.print_exc()

def detect_ddos(packet, model):
    global ddos_logs, last_log_time, detected_ips
    
    try:
        # Only process packets with IP layer
        if IP in packet:
            # Extract source IP
            src_ip = packet[IP].src
            
            # Extract features from the packet
            features = extract_features_from_packet(packet)
            
            # Predict using the pre-trained model
            prediction = model.predict([features])
            
            if prediction == 1:  # DDoS attack detected
                # Add debugging information
                print(f"DDoS detected from IP: {src_ip}")
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
                    
                    # Add to detected IPs set
                    detected_ips.add(src_ip)
                
                    # Block the IP address
                    block_ip(src_ip)
                    
                    # Verify IP was blocked
                    # This is platform-specific, so we'll just check our detected_ips set
                    if src_ip in detected_ips:
                        print(f"IP {src_ip} has been processed for blocking")
                        ddos_logs.append(f"[{detection_time}] Attempted to block IP: {src_ip}")
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
    # We don't need to print packet summary for every packet anymore
    # Only print when DDoS is detected
    detect_ddos(packet, model)

def check_admin_privileges():
    """Check if the script is running with administrative privileges"""
    system_platform = platform.system()
    
    if system_platform == "Windows":
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("WARNING: Not running with administrator privileges.")
            print("IP blocking will not work without admin rights.")
            print("Please restart the script as Administrator.")
            return False
    elif system_platform == "Linux":
        if os.geteuid() != 0:
            print("WARNING: Not running as root.")
            print("IP blocking will not work without root privileges.")
            print("Please restart the script with sudo.")
            return False
    
    print("Running with sufficient privileges.")
    return True

def capture_packets_with_detection(model):
    system_platform = platform.system()
    
    print(f"Starting DDoS detection on {system_platform}...")
    print("Only logging detected DDoS IPs. Log files will be created every 1 minute.")
    
    # Try to capture from both WiFi and Ethernet interfaces
    if system_platform == "Linux":
        interfaces = os.listdir('/sys/class/net/')  # Dynamically list all network interfaces
        
        # Try each interface one by one
        for iface in interfaces:
            try:
                print(f"Attempting to capture on interface: {iface}")
                # This line will block until an error occurs or the program is terminated
                sniff(iface=iface, prn=lambda pkt: packet_callback_with_detection(pkt, model), store=False)
                # If we get here, sniffing was successful on this interface
                break
            except Exception as e:
                print(f"Failed to capture on {iface}: {e}")
        
        # If all explicit interfaces failed, try default interface
        try:
            print("Attempting to capture on default interface")
            sniff(prn=lambda pkt: packet_callback_with_detection(pkt, model), store=False)
        except Exception as e:
            print(f"Failed to capture on default interface: {e}")
    
    # elif system_platform == "Windows":
    #     # Get all available interfaces
    #     from scapy.arch.windows import get_windows_if_list
    #     interfaces = get_windows_if_list()
        
    #     if interfaces:
    #         # Try to find WiFi and Ethernet interfaces
    #         for interface in interfaces:
    #             try:
    #                 iface_name = interface['name']
    #                 print(f"Attempting to capture on interface: {iface_name}")
    #                 sniff(iface=iface_name, prn=lambda pkt: packet_callback_with_detection(pkt, model), store=False)
    #                 # If we get here, sniffing was successful on this interface
    #                 break
    #             except Exception as e:
    #                 print(f"Failed to capture on {iface_name}: {e}")
            
    #         # If all explicit interfaces failed, try default interface
    #         try:
    #             print("Attempting to capture on default interface")
    #             sniff(prn=lambda pkt: packet_callback_with_detection(pkt, model), store=False)
    #         except Exception as e:
    #             print(f"Failed to capture on default interface: {e}")
    #     else:
    #         # Fallback to default interface
    #         try:
    #             print("Attempting to capture on default interface")
    #             sniff(prn=lambda pkt: packet_callback_with_detection(pkt, model), store=False)
    #         except Exception as e:
    #             print(f"Failed to capture on default interface: {e}")
    
    else:
        print(f"Unsupported platform: {system_platform}")

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
        
        # Start packet capture
        capture_packets_with_detection(model)
    except KeyboardInterrupt:
        print("\nStopping DDoS detection. Writing final logs...")
        write_logs_to_file()
        print("Done.")