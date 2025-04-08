import platform
import subprocess
from scapy.all import sniff, IP, TCP, UDP, ICMP
import joblib
import numpy as np
import time
from datetime import datetime
import os
import sys

# Luu tru cac IP DDoS da phat hien de tranh bao cao trung lap
detected_ips = set()
# Luu tru nhat ky de ghi vao file
ddos_logs = []
# Theo doi thoi gian tao file nhat ky cuoi cung
last_log_time = time.time()
# Thu muc de luu tru file nhat ky
log_dir = "ddos_logs"
# Tu dien de theo doi luong luu luong
traffic_flows = {}
# Cua so thoi gian de theo doi luong luu luong (tinh bang giay)
FLOW_WINDOW = 60
# Nguong cho so goi tin moi giay de coi la dang nghi ngo
PPS_THRESHOLD = 100
# Nguong cho phat hien tan cong UDP flood
UDP_THRESHOLD = 80

def ensure_log_directory():
    # Tao thu muc neu chua ton tai
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

def safe_int(value):
    """Chuyen doi gia tri thanh so nguyen mot cach an toan, xu ly cac loai gia tri FlagValue"""
    try:
        return int(value)
    except (TypeError, ValueError):
        # Neu la loai FlagValue, chuyen doi thanh int su dung thuoc tinh value
        if hasattr(value, 'value'):
            return int(value.value)
        # Neu la loai bitfield, chuyen doi su dung int()
        try:
            return int(value)
        except:
            return 0

def extract_features_from_packet(packet):
    # Khoi tao vector dac trung voi gia tri 0 cho tat ca 32 dac trung duoc mong doi
    features = np.zeros(32)
    
    # Trich xuat cac dac trung - dieu chinh theo yeu cau cua mo hinh
    index = 0
    
    # Dac trung co ban cua goi tin
    features[index] = len(packet) if packet else 0; index += 1
    features[index] = float(packet.time) if hasattr(packet, 'time') else 0; index += 1
    
    # Dac trung cua lop IP
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
        
        # Xu ly dia chi IP mot cach an toan hon
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
        index += 11  # Bo qua cac dac trung IP neu khong co lop IP
    
    # Dac trung cua lop TCP
    if TCP in packet:
        features[index] = safe_int(packet[TCP].sport); index += 1
        features[index] = safe_int(packet[TCP].dport); index += 1
        features[index] = safe_int(packet[TCP].seq) % 10000; index += 1  # Modulo de tranh tran so
        features[index] = safe_int(packet[TCP].ack) % 10000; index += 1  # Modulo de tranh tran so
        features[index] = safe_int(packet[TCP].dataofs); index += 1
        features[index] = safe_int(packet[TCP].reserved); index += 1
        features[index] = safe_int(packet[TCP].flags); index += 1
        features[index] = safe_int(packet[TCP].window); index += 1
        features[index] = safe_int(packet[TCP].urgptr); index += 1
    else:
        index += 9  # Bo qua cac dac trung TCP neu khong co lop TCP
    
    # Dac trung cua lop UDP
    if UDP in packet:
        features[index] = safe_int(packet[UDP].sport); index += 1
        features[index] = safe_int(packet[UDP].dport); index += 1
        features[index] = safe_int(packet[UDP].len); index += 1
    else:
        index += 3  # Bo qua cac dac trung UDP neu khong co lop UDP
    
    # Dac trung duoc suy dien
    features[index] = 1 if TCP in packet else 0; index += 1  # Co phai TCP?
    features[index] = 1 if UDP in packet else 0; index += 1  # Co phai UDP?
    features[index] = packet.time % 60 if hasattr(packet, 'time') else 0; index += 1  # Thoi gian modulo 60
    features[index] = packet.time % 3600 if hasattr(packet, 'time') else 0; index += 1  # Thoi gian modulo 3600
    features[index] = 0  # Dac trung giu cho neu can thiet
    
    # Dam bao co chinh xac 32 dac trung
    assert len(features) == 32, f"Expected 32 features, got {len(features)}"
    
    return features

def clean_old_flows():
    """Xoa cac luong khong duoc thay trong FLOW_WINDOW giay"""
    global traffic_flows
    current_time = time.time()
    to_delete = []
    
    for flow_key, flow_data in traffic_flows.items():
        if current_time - flow_data["last_seen"] > FLOW_WINDOW:
            to_delete.append(flow_key)
    
    for key in to_delete:
        del traffic_flows[key]

def block_ip_comprehensive(ip_address):
    """Chan dia chi IP da cho su dung nhieu quy tac iptables cho cac giao thuc khac nhau"""
    ip_address = str(ip_address)
    print(f"Thu chan toan dien IP: {ip_address}")
    
    try:
        # Chan cac giao thuc pho bien rieng le de loc tot hon
        protocols = ["tcp", "udp", "icmp"]
        success = False
        
        for proto in protocols:
            # Chen quy tac vao dau chuoi INPUT (-I thay vi -A)
            cmd = ["iptables", "-I", "INPUT", "-p", proto, "-s", ip_address, "-j", "DROP"]
            print(f"Thuc thi: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Loi lenh: {result.stderr}")
                # Thu voi sudo
                cmd = ["sudo", "iptables", "-I", "INPUT", "-p", proto, "-s", ip_address, "-j", "DROP"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"Loi sudo cho {proto}: {result.stderr}")
                else:
                    print(f"Chan thanh cong luong {proto} tu IP voi sudo")
                    success = True
            else:
                print(f"Chan thanh cong luong {proto} tu IP")
                success = True
        
        # Them quy tac tong quat de bat tat ca cac giao thuc khac
        cmd = ["iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"]
        print(f"Thuc thi: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Loi lenh tong quat: {result.stderr}")
            # Thu voi sudo
            cmd = ["sudo", "iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Loi sudo lenh tong quat: {result.stderr}")
            else:
                print("Them thanh cong quy tac chan tong quat voi sudo")
                success = True
        else:
            print("Them thanh cong quy tac chan tong quat")
            success = True
            
        # Luu quy tac iptables de duy tri sau khi khoi dong lai
        try:
            print("Dang luu quy tac iptables...")
            save_cmd = ["iptables-save"]
            save_result = subprocess.run(save_cmd, capture_output=True, text=True)
            
            if save_result.returncode != 0:
                print(f"Loi luu quy tac iptables: {save_result.stderr}")
                # Thu voi sudo
                save_cmd = ["sudo", "iptables-save"]
                save_result = subprocess.run(save_cmd, capture_output=True, text=True)
                if save_result.returncode != 0:
                    print(f"Loi sudo iptables-save: {save_result.stderr}")
                else:
                    print("Luu thanh cong quy tac iptables voi sudo")
            else:
                print("Luu thanh cong quy tac iptables")
        except Exception as e:
            print(f"Loi khi luu quy tac iptables: {e}")
            
        return success
            
    except Exception as e:
        print(f"Khong the chan IP {ip_address}: {e}")
        import traceback
        traceback.print_exc()
        return False

def verify_ip_blocked(ip_address):
    """Xac minh xem IP co thuc su bi chan trong quy tac iptables"""
    ip_address = str(ip_address)
    print(f"Xac minh xem IP {ip_address} co bi chan khong...")
    
    try:
        cmd = ["iptables", "-L", "INPUT", "-v", "-n"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            output = result.stdout
            if ip_address in output:
                print(f"Xac minh THANH CONG: IP {ip_address} co trong quy tac iptables")
                return True
            else:
                print(f"Xac minh THAT BAI: IP {ip_address} khong co trong quy tac iptables")
                # Thu voi sudo
                cmd = ["sudo", "iptables", "-L", "INPUT", "-v", "-n"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    output = result.stdout
                    if ip_address in output:
                        print(f"Xac minh THANH CONG voi sudo: IP {ip_address} co trong quy tac iptables")
                        return True
                return False
        else:
            print(f"Loi khi kiem tra iptables: {result.stderr}")
            # Thu voi sudo
            cmd = ["sudo", "iptables", "-L", "INPUT", "-v", "-n"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                output = result.stdout
                if ip_address in output:
                    print(f"Xac minh THANH CONG voi sudo: IP {ip_address} co trong quy tac iptables")
                    return True
            return False
    except Exception as e:
        print(f"Loi khi xac minh chan IP: {e}")
        return False

def detect_ddos(packet, model):
    global ddos_logs, last_log_time, detected_ips, traffic_flows
    
    try:
        # Bo qua xu ly cac thong bao loi ICMP de tranh nham lan
        if ICMP in packet and packet[ICMP].type == 3:  # Loai 3 la "Destination Unreachable"
            if IP in packet:
                original_dst = str(packet[IP].dst)
                print(f"Bo qua ICMP Destination Unreachable tu {packet[IP].src} den {original_dst}")
            return
        
        # Chi xu ly cac goi tin co lop IP
        if IP in packet:
            # Trich xuat IP nguon va dich
            src_ip = str(packet[IP].src)
            dst_ip = str(packet[IP].dst)
            
            # Tao mot khoa luong
            if TCP in packet:
                flow_key = f"{src_ip}:{packet[TCP].sport}-{dst_ip}:{packet[TCP].dport}-TCP"
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                flow_key = f"{src_ip}:{packet[UDP].sport}-{dst_ip}:{packet[UDP].dport}-UDP"
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                flow_key = f"{src_ip}-{dst_ip}-{packet[IP].proto}"
                protocol = str(packet[IP].proto)
                src_port = 0
                dst_port = 0
            
            # Theo doi thong ke luong
            current_time = time.time()
            
            # Dinh ky xoa cac luong cu
            if not hasattr(detect_ddos, "last_cleanup") or current_time - detect_ddos.last_cleanup > 60:
                clean_old_flows()
                detect_ddos.last_cleanup = current_time
            
            # Khoi tao theo doi luong cho cac luong moi
            if flow_key not in traffic_flows:
                traffic_flows[flow_key] = {
                    "count": 0, 
                    "first_seen": current_time, 
                    "last_seen": current_time,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "packet_sizes": []
                }
            
            # Cap nhat du lieu luong
            flow = traffic_flows[flow_key]
            flow["count"] += 1
            flow["last_seen"] = current_time
            flow["packet_sizes"].append(len(packet))
            
            # Tinh so goi tin moi giay cho luong nay
            duration = flow["last_seen"] - flow["first_seen"]
            pps = flow["count"] / max(duration, 1)  # Tranh chia cho 0
            
            # Chi giu lai 100 kich thuoc goi tin cuoi cung de giam su dung bo nho
            if len(flow["packet_sizes"]) > 100:
                flow["packet_sizes"] = flow["packet_sizes"][-100:]
            
            # Tinh kich thuoc goi tin trung binh
            avg_packet_size = sum(flow["packet_sizes"]) / len(flow["packet_sizes"])
            
            # Trich xuat dac trung tu goi tin de du doan mo hinh
            features = extract_features_from_packet(packet)
            
            # Kiem tra bo sung cho tan cong UDP flood tren cong 80
            udp_flood = False
            if protocol == "UDP" and dst_port == 80 and pps > UDP_THRESHOLD:
                udp_flood = True
                print(f"Phat hien co the UDP flood: {src_ip} -> {dst_ip}:{dst_port}, PPS: {pps:.2f}")
            
            # Du doan su dung mo hinh hoc may
            prediction = model.predict([features])
            
            # Xac dinh xem co phai tan cong dua tren du doan mo hinh va cac phuong phap heuristic
            is_attack = prediction == 1 or pps > PPS_THRESHOLD or udp_flood
            
            # Thong tin debug
            if is_attack:
                print(f"Phat hien co the tan cong: {src_ip} -> {dst_ip}")
                print(f"Giao thuc: {protocol}, PPS: {pps:.2f}, Kich thuoc TB: {avg_packet_size:.2f} bytes")
                print(f"Du doan mo hinh: {prediction[0]}, UDP flood: {udp_flood}")
                
                # Chi ghi log va chan neu IP nay chua duoc phat hien
                if src_ip not in detected_ips:
                    detection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    attack_type = "UDP Flood" if udp_flood else "DDoS"
                    log_entry = (f"[{detection_time}] Phat hien tan cong {attack_type} tu IP: {src_ip} "
                                f"den {dst_ip}:{dst_port} ({protocol}), PPS: {pps:.2f}")
                    
                    # Ghi log ra console
                    print(log_entry)
                    print("Dang chan dia chi IP...")
                    
                    # Them vao danh sach log
                    ddos_logs.append(log_entry)
                    
                    # Them vao tap hop cac IP da phat hien
                    detected_ips.add(src_ip)
                
                    # Chan dia chi IP toan dien
                    block_success = block_ip_comprehensive(src_ip)
                    
                    # Xac minh xem IP co bi chan
                    if verify_ip_blocked(src_ip):
                        print(f"IP {src_ip} da duoc xac minh bi chan trong iptables")
                        ddos_logs.append(f"[{detection_time}] Da chan thanh cong IP: {src_ip}")
                    else:
                        print(f"CANH BAO: Khong the xac minh chan cho IP {src_ip}")
                        ddos_logs.append(f"[{detection_time}] Canh bao: Khong the xac minh chan cho IP: {src_ip}")
                else:
                    print(f"IP {src_ip} da duoc phat hien va xu ly")
            
            # Kiem tra neu da qua 1 phut ke tu lan tao file log cuoi cung
            current_time = time.time()
            if current_time - last_log_time >= 60:  # 60 giay = 1 phut
                write_logs_to_file()
                last_log_time = current_time
                # Xoa log sau khi ghi vao file
                ddos_logs = []
    
    except Exception as e:
        print(f"Loi trong phat hien DDoS: {e}")
        import traceback
        traceback.print_exc()

# Khoi tao thuoc tinh theo doi cleanup
detect_ddos.last_cleanup = time.time()

def write_logs_to_file():
    if ddos_logs:
        # Tao ten file voi dau thoi gian hien tai
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(log_dir, f"ddos_log_{timestamp}.txt")
        
        # Ghi log vao file
        with open(filename, 'w') as f:
            f.write("\n".join(ddos_logs))
        
        print(f"Logs written to {filename}")

def packet_callback_with_detection(packet, model):
    # Chi in khi phat hien DDoS
    detect_ddos(packet, model)

def check_admin_privileges():
    """Kiem tra xem script co dang chay voi quyen root khong"""
    if os.geteuid() != 0:
        print("WARNING: Khong chay voi quyen root.")
        print("Chan IP se khong hoat dong neu khong co quyen root.")
        print("Vui long khoi dong lai script voi sudo.")
        return False
    
    print("Dang chay voi quyen root.")
    return True

def capture_packets_with_detection(model):
    print("Bat dau phat hien DDoS tren Linux...")
    print("Chi ghi log cac IP DDoS phat hien. File log se duoc tao moi 1 phut.")
    
    # Liet ke tat ca cac giao dien mang
    interfaces = os.listdir('/sys/class/net/')
    
    # Thu tung giao dien mot
    for iface in interfaces:
        try:
            print(f"Thu bat goi tin tren giao dien: {iface}")
            # Lenh nay se block cho den khi co loi hoac ket thuc chuong trinh
            sniff(iface=iface, prn=lambda pkt: packet_callback_with_detection(pkt, model), store=False)
            # Neu den day, viec sniff tren giao dien nay thanh cong
            break
        except Exception as e:
            print(f"Khong the bat goi tin tren {iface}: {e}")
    
    # Neu tat ca giao dien cu the deu that bai, thu giao dien mac dinh
    try:
        print("Thu bat goi tin tren giao dien mac dinh")
        sniff(prn=lambda pkt: packet_callback_with_detection(pkt, model), store=False)
    except Exception as e:
        print(f"Khong the bat goi tin tren giao dien mac dinh: {e}")

if __name__ == "__main__":
    # Dam bao thu muc log ton tai
    ensure_log_directory()
    
    # Kiem tra quyen root truoc
    has_root = check_admin_privileges()
    if not has_root:
        print("WARNING: Script nay can quyen root de chan IP dung cach.")
        print("Nhan Ctrl+C de thoat hoac phim bat ky de tiep tuc voi tinh nang han che...")
        input()
    
    model_path = "random_forest_model.pkl"  # Duong dan den mo hinh da duoc train
    try:
        model = joblib.load(model_path)
        print("Tai mo hinh thanh cong.")
    except Exception as e:
        print(f"Khong the tai mo hinh: {e}")
        exit(1)
    
    try:
        # Dang ky handler de luu log khi thoat
        import atexit
        atexit.register(write_logs_to_file)
        
        # Bat dau bat goi tin
        capture_packets_with_detection(model)
    except KeyboardInterrupt:
        print("\nDung phat hien DDoS. Dang ghi log cuoi cung...")
        write_logs_to_file()
        print("Hoan thanh.")