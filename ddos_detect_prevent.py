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

def block_ip_comprehensive(ip_address):
    """Block the given IP address using multiple iptables rules for different protocols"""
    ip_address = str(ip_address)
    print(f"Attempting comprehensive block of IP: {ip_address}")
    
    try:
        # Block common protocols individually for better filtering
        protocols = ["tcp", "udp", "icmp"]
        success = False
        
        for proto in protocols:
            # Insert rule at the beginning of INPUT chain (-I instead of -A)
            cmd = ["iptables", "-I", "INPUT", "-p", proto, "-s", ip_address, "-j", "DROP"]
            print(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Command failed with error: {result.stderr}")
                # Try with sudo
                cmd = ["sudo", "iptables", "-I", "INPUT", "-p", proto, "-s", ip_address, "-j", "DROP"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"Sudo command also failed for {proto}: {result.stderr}")
                else:
                    print(f"Successfully blocked {proto} traffic from IP with sudo")
                    success = True
            else:
                print(f"Successfully blocked {proto} traffic from IP")
                success = True
        
        # Also add a general rule to catch all other protocols
        cmd = ["iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"]
        print(f"Executing: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"General rule command failed: {result.stderr}")
            # Try with sudo
            cmd = ["sudo", "iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"General rule sudo command also failed: {result.stderr}")
            else:
                print("Successfully added general block rule with sudo")
                success = True
        else:
            print("Successfully added general block rule")
            success = True
            
        # Save iptables rules to persist across reboots
        try:
            print("Saving iptables rules...")
            save_cmd = ["iptables-save"]
            save_result = subprocess.run(save_cmd, capture_output=True, text=True)
            
            if save_result.returncode != 0:
                print(f"Failed to save iptables rules: {save_result.stderr}")
                # Try with sudo
                save_cmd = ["sudo", "iptables-save"]
                save_result = subprocess.run(save_cmd, capture_output=True, text=True)
                if save_result.returncode != 0:
                    print(f"Sudo iptables-save also failed: {save_result.stderr}")
                else:
                    print("Successfully saved iptables rules with sudo")
            else:
                print("Successfully saved iptables rules")
        except Exception as e:
            print(f"Error saving iptables rules: {e}")
            
        return success
            
    except Exception as e:
        print(f"Failed to block IP {ip_address}: {e}")
        import traceback
        traceback.print_exc()
        return False

def verify_ip_blocked(ip_address):
    """Verify if the IP is actually blocked in iptables rules"""
    ip_address = str(ip_address)
    print(f"Verifying if IP {ip_address} is blocked...")
    
    try:
        cmd = ["iptables", "-L", "INPUT", "-v", "-n"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            output = result.stdout
            if ip_address in output:
                print(f"Verification SUCCESS: IP {ip_address} is in iptables rules")
                return True
            else:
                print(f"Verification FAILED: IP {ip_address} not found in iptables rules")
                # Try with sudo
                cmd = ["sudo", "iptables", "-L", "INPUT", "-v", "-n"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    output = result.stdout
                    if ip_address in output:
                        print(f"Verification SUCCESS with sudo: IP {ip_address} is in iptables rules")
                        return True
                return False
        else:
            print(f"Failed to check iptables: {result.stderr}")
            # Try with sudo
            cmd = ["sudo", "iptables", "-L", "INPUT", "-v", "-n"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                output = result.stdout
                if ip_address in output:
                    print(f"Verification SUCCESS with sudo: IP {ip_address} is in iptables rules")
                    return True
            return False
    except Exception as e:
        print(f"Error verifying IP block: {e}")
        return False

def detect_ddos(packet, model):
    global ddos_logs, last_log_time, detected_ips
    
    try:
        # Only process packets with IP layer
        if IP in packet:
            # Extract source IP and convert to string explicitly
            src_ip = str(packet[IP].src)
            
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
                
                    # Block the IP address with comprehensive approach
                    block_success = block_ip_comprehensive(src_ip)
                    
                    # Verify IP was blocked
                    if verify_ip_blocked(src_ip):
                        print(f"IP {src_ip} verified as blocked in iptables")
                        ddos_logs.append(f"[{detection_time}] Successfully blocked IP: {src_ip}")
                    else:
                        print(f"WARNING: Could not verify block for IP {src_ip}")
                        ddos_logs.append(f"[{detection_time}] Warning: Could not verify block for IP: {src_ip}")
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
    """Check if the script is running with root privileges"""
    if os.geteuid() != 0:
        print("WARNING: Not running as root.")
        print("IP blocking will not work without root privileges.")
        print("Please restart the script with sudo.")
        return False
    
    print("Running with root privileges.")
    return True

def capture_packets_with_detection(model):
    print("Starting DDoS detection on Linux...")
    print("Only logging detected DDoS IPs. Log files will be created every 1 minute.")
    
    # Dynamically list all network interfaces
    interfaces = os.listdir('/sys/class/net/')
    
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

if __name__ == "__main__":
    # Ensure log directory exists
    ensure_log_directory()
    
    # Check for root privileges first
    has_root = check_admin_privileges()
    if not has_root:
        print("WARNING: This script requires root privileges for proper IP blocking.")
        print("Press Ctrl+C to exit or any key to continue with limited functionality...")
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
        
        # Test block capability if running as root
        # if has_root:
        #     print("Testing iptables functionality...")
        #     test_ip = "127.0.0.1"  # Use localhost for testing
        #     try:
        #         # Add a test rule and immediately remove it
        #         subprocess.run(["iptables", "-A", "INPUT", "-s", test_ip, "-j", "DROP"], 
        #                       check=True, capture_output=True)
        #         subprocess.run(["iptables", "-D", "INPUT", "-s", test_ip, "-j", "DROP"], 
        #                       check=True, capture_output=True)
        #         print("iptables test successful!")
        #     except subprocess.CalledProcessError as e:
        #         print(f"iptables test failed: {e}")
        #         print("IP blocking may not work correctly.")
        
        # Start packet capture
        capture_packets_with_detection(model)
    except KeyboardInterrupt:
        print("\nStopping DDoS detection. Writing final logs...")
        write_logs_to_file()
        print("Done.")