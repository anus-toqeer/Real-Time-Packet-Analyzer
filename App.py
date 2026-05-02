from flask import Flask, render_template,redirect,request,url_for
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import datetime
import csv
import os

app = Flask(__name__)


port_services = {
    80:   "HTTP",
    443:  "HTTPS",
    53:   "DNS",
    22:   "SSH",
    21:   "FTP",
    25:   "SMTP",
    110:  "POP3",
    3306: "MySQL",
    0:    "ICMP"
}


captured_packets = []
stopped_packets  = []
is_monitoring    = False
sniff_thread     = None
LOG_FILE         = 'packet_log.csv'

# Every time app.py runs, old session data is deleted
if os.path.exists(LOG_FILE):
    os.remove(LOG_FILE)
    print("[INFO] Old session log cleared. Fresh start.")


def save_to_log(pkt_data):
    file_exists = os.path.exists(LOG_FILE)
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'time', 'source_ip', 'destination_ip',
            'protocol', 'packet_size',
            'source_port', 'destination_port', 'service'
        ])
        if not file_exists:
            writer.writeheader()
        writer.writerow(pkt_data)


def load_from_log():
    packets = []
    if not os.path.exists(LOG_FILE):
        return packets
    with open(LOG_FILE, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            packets.append(row)
    return packets


def handle_packet(packet):
    if not is_monitoring:
        return
    if not packet.haslayer(IP):
        return

    src_ip   = packet[IP].src
    dst_ip   = packet[IP].dst
    pkt_size = len(packet)
    time_now = datetime.datetime.now().strftime('%H:%M:%S')

    if packet.haslayer(TCP):
        protocol = 'TCP'
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = 'UDP'
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol = 'ICMP'
        src_port = 0
        dst_port = 0
    else:
        return

    service = port_services.get(dst_port, "Unknown")

    pkt_data = {
        'time':             time_now,
        'source_ip':        src_ip,
        'destination_ip':   dst_ip,
        'protocol':         protocol,
        'packet_size':      pkt_size,
        'source_port':      src_port,
        'destination_port': dst_port,
        'service':          service
    }

    captured_packets.append(pkt_data)
    save_to_log(pkt_data)

    if len(captured_packets) > 100:
        captured_packets.pop(0)


def startSniffing():
    sniff(
        prn=handle_packet,
        store=False,
        filter="tcp or udp or icmp"
    )

def CalStats(packets):
    total      = len(packets)
    tcp_count  = 0
    udp_count  = 0
    icmp_count = 0
    total_size = 0

    for packet in packets:
        proto = packet.get('protocol', '')
        if proto == 'TCP':
            tcp_count += 1
        elif proto == 'UDP':
            udp_count += 1
        elif proto == 'ICMP':
            icmp_count += 1
        total_size += int(packet['packet_size']) if packet['packet_size'] else 0

    avg_size = round(total_size / total, 2) if total > 0 else 0

    return {
        'total':      total,
        'tcp_count':  tcp_count,
        'udp_count':  udp_count,
        'icmp_count': icmp_count,
        'avg_size':   avg_size
    }

@app.route('/', methods=['GET', 'POST'])
def home():
    global is_monitoring, sniff_thread, captured_packets, stopped_packets

    selected_protocol  = ''
    selected_source_ip = ''
    selected_dest_ip   = ''
    view_mode          = 'live'   # live | stopped | session

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'start':
            if not is_monitoring:
                is_monitoring    = True
                captured_packets = []
                stopped_packets  = []
                view_mode        = 'live'
                sniff_thread = threading.Thread(
                    target=startSniffing,
                    daemon=True
                )
                sniff_thread.start()
                return redirect(url_for('home'))


        elif action == 'stop':
            is_monitoring   = False
            stopped_packets = list(captured_packets)
            view_mode       = 'stopped'

        elif action == 'view_session':
            # load complete session from CSV file
            view_mode = 'session'

        elif action == 'filter':
            selected_protocol  = request.form.get('protocol')
            selected_source_ip = request.form.get('source_ip').strip()
            selected_dest_ip   = request.form.get('destination_ip').strip()
            view_mode          = request.form.get('view_mode', 'live')

    
    if view_mode == 'live':
        if is_monitoring:
            packets = list(captured_packets)
        else:
            packets = []

    elif view_mode == 'stopped':
        packets = list(stopped_packets)

    elif view_mode == 'session':
       
        packets = load_from_log()

    else:
        packets = []

    
    if selected_protocol:
        packets = [p for p in packets
                   if p['protocol'] == selected_protocol]

    if selected_source_ip:
        packets = [p for p in packets
                   if selected_source_ip in p['source_ip']]

    if selected_dest_ip:
        packets = [p for p in packets
                   if selected_dest_ip in p['destination_ip']]

    stats = CalStats(packets)

    return render_template('index.html',
                           packets=packets,
                           stats=stats,
                           selected_protocol=selected_protocol,
                           selected_source_ip=selected_source_ip,
                           selected_dest_ip=selected_dest_ip,
                           monitoring_status='running' if is_monitoring else 'stopped',
                           view_mode=view_mode)

app.run(debug=False)