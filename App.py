from flask import Flask, render_template, redirect, request, url_for
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import datetime
import csv
import os
import re

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
uploaded_packets = []
is_monitoring    = False
sniff_thread     = None
packet_lock      = threading.Lock()   
LOG_FILE         = 'packet_log.csv'

if os.path.exists(LOG_FILE):
    os.remove(LOG_FILE)
    print("[INFO] Old session log cleared. Fresh start.")


def is_valid_ip(ip_str):
    pattern = r'^(\d{1,3}\.){0,3}\d{1,3}$'
    return bool(re.match(pattern, ip_str))

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

    with packet_lock:
        captured_packets.append(pkt_data)
        if len(captured_packets) > 100:
            captured_packets.pop(0)

    save_to_log(pkt_data)


def stop_sniff(packet):
    return not is_monitoring

def startSniffing():
    sniff(
        prn=handle_packet,
        store=False,
        filter="tcp or udp or icmp",
        stop_filter=stop_sniff   
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

#  CSV Upload Route 

@app.route('/upload_csv', methods=['POST'])
def upload_csv():
    global uploaded_packets

    if 'csv_file' not in request.files:
        return redirect(url_for('home') + '?upload_error=no_file')

    file = request.files['csv_file']

    if file.filename == '':
        return redirect(url_for('home') + '?upload_error=no_file')

    if not file.filename.endswith('.csv'):
        return redirect(url_for('home') + '?upload_error=not_csv')

    try:
        import io
        stream = io.StringIO(file.stream.read().decode('utf-8'))
        reader = csv.DictReader(stream)
        uploaded_packets = []
        for row in reader:
            try:
                dst_port = int(row.get('destination_port', 0))
                row['service'] = port_services.get(dst_port, "Unknown")
            except:
                row['service'] = "Unknown"
            uploaded_packets.append(row)

        return redirect(url_for('home') + '?view_mode=uploaded')

    except Exception:
        return redirect(url_for('home') + '?upload_error=read_error')



@app.route('/', methods=['GET', 'POST'])
def home():
    global is_monitoring, sniff_thread, captured_packets, stopped_packets

    selected_protocol  = ''
    selected_source_ip = ''
    selected_dest_ip   = ''
    view_mode          = 'live'
    filter_error       = ''
    upload_error       = request.args.get('upload_error', '')

    if request.args.get('view_mode') == 'uploaded':
        view_mode = 'uploaded'

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'start':
            # FIX 4: only start a new thread if previous one is not alive
            if not is_monitoring:
                is_monitoring = True
                with packet_lock:
                    captured_packets = []
                stopped_packets = []
                if sniff_thread is None or not sniff_thread.is_alive():
                    sniff_thread = threading.Thread(
                        target=startSniffing,
                        daemon=True
                    )
                    sniff_thread.start()
                return redirect(url_for('home'))

        elif action == 'stop':
            is_monitoring = False
            with packet_lock:
                stopped_packets = list(captured_packets)
            view_mode = 'stopped'

        elif action == 'view_session':
            view_mode = 'session'

        elif action == 'clear_filter':
            view_mode = request.form.get('view_mode', 'live')
            selected_protocol  = ''
            selected_source_ip = ''
            selected_dest_ip   = ''

        elif action == 'filter':
            selected_protocol  = request.form.get('protocol', '')
            selected_source_ip = request.form.get('source_ip', '').strip()
            selected_dest_ip   = request.form.get('destination_ip', '').strip()
            view_mode          = request.form.get('view_mode', 'live')

            if selected_source_ip and not is_valid_ip(selected_source_ip):
                filter_error = 'Invalid Source IP — enter numbers and dots only (e.g. 192.168.1.5)'
                selected_source_ip = ''

            elif selected_dest_ip and not is_valid_ip(selected_dest_ip):
                filter_error = 'Invalid Destination IP — enter numbers and dots only (e.g. 8.8.8.8)'
                selected_dest_ip = ''

    # ─── Load Correct Packets ──────────────────────
    if view_mode == 'live':
        with packet_lock:
            packets = list(captured_packets) if is_monitoring else []

    elif view_mode == 'stopped':
        packets = list(stopped_packets)

    elif view_mode == 'session':
        packets = load_from_log()

    elif view_mode == 'uploaded':
        packets = list(uploaded_packets)

    else:
        packets = []

    # ─── Apply Filters ─────────────────────────────
    if selected_protocol:
        packets = [p for p in packets
                   if p.get('protocol') == selected_protocol]

    if selected_source_ip:
        packets = [p for p in packets
                   if selected_source_ip in p.get('source_ip', '')]

    if selected_dest_ip:
        packets = [p for p in packets
                   if selected_dest_ip in p.get('destination_ip', '')]

    # ─── No Results Message ────────────────────────
    no_results = False
    if (selected_protocol or selected_source_ip or selected_dest_ip):
        if len(packets) == 0 and not filter_error:
            no_results = True

    stats = CalStats(packets)

    return render_template('index.html',
                           packets=packets,
                           stats=stats,
                           selected_protocol=selected_protocol,
                           selected_source_ip=selected_source_ip,
                           selected_dest_ip=selected_dest_ip,
                           monitoring_status='running' if is_monitoring else 'stopped',
                           view_mode=view_mode,
                           filter_error=filter_error,
                           no_results=no_results,
                           upload_error=upload_error,
                           uploaded_count=len(uploaded_packets))



if __name__ == '__main__':
    app.run(debug=False, threaded=True)  