import subprocess
import difflib
from flask import Flask, render_template, request, jsonify, send_file
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os
import time
import atexit
from pymetasploit3.msfrpc import MsfRpcClient
from zapv2 import ZAPv2
from flask import session
import pymysql
from pymysql.constants import CLIENT



app = Flask(__name__)
app.secret_key = 'gizli_bir_anahtar'

ZAP_PATH = "/usr/share/zaproxy/zap.sh"
ZAP_PORT = 8080
ZAP_API_KEY = "anahtar"
ZAP_PROXY = f"http://127.0.0.1:{ZAP_PORT}"

def start_zap():

    cmd = f"{ZAP_PATH} -daemon -port {ZAP_PORT} -config api.key={ZAP_API_KEY} -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true"
    print(f"[+] ZAP başlatılıyor (os.system ile): {cmd}")
    os.system(cmd + " > /dev/null 2>&1 &")

def wait_for_zap(timeout=120):

    start_time = time.time()
    while time.time() - start_time < timeout:
        result = os.popen("netstat -tulnp | grep :8080").read()
        if result.strip():
            return True
        time.sleep(2)
    return False

def correct_nmap_command(command):
    known_commands = ["nmap", "-sn", "-p", "-sV", "-O", "-A", "-sS", "-sU", "-f", "--script=vuln"]
    command_parts = command.split()
    corrected_command = []
    fixed = False
    add_verbose = "-v" not in command_parts

    for part in command_parts:
        closest_match = difflib.get_close_matches(part, known_commands, n=1, cutoff=0.7)
        if closest_match:
            corrected_command.append(closest_match[0])
            if closest_match[0] != part:
                fixed = True
        else:
            corrected_command.append(part)
    if add_verbose:
        corrected_command.append("-v")
    return " ".join(corrected_command), fixed

def run_nmap_scan(command):
    try:
        corrected_command, fixed = correct_nmap_command(command)

        if fixed:
            message = f"Düzeltildi: {corrected_command} (Orijinal komut hatalıydı ve düzeltildi.)"
        else:
            message = f"Çalıştırılıyor: {corrected_command}"

        result = subprocess.run(corrected_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        scan_result = result.stdout if result.stdout else result.stderr

        full_result = f"{message}\n\n{scan_result}"
        pdf_filename = generate_pdf_report(corrected_command, scan_result)

        return full_result, pdf_filename
    except Exception as e:
        return f"Bir hata oluştu: {e}", None

def generate_pdf_report(command, result):
    pdf_filename = "nmap_report.pdf"
    c = canvas.Canvas(pdf_filename, pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(100, 750, "Nmap Tarama Raporu")
    c.drawString(100, 730, f"Calistirilan Komut: {command}")
    c.drawString(100, 710, "Tarama Sonuclari")

    y_position = 690
    for line in result.split("\n"):
        c.drawString(100, y_position, line)
        y_position -= 15
        if y_position < 50:
            c.showPage()
            y_position = 750

    c.save()
    return pdf_filename

def start_msf_rpc():
    os.system("nohup msfrpcd -P msfpassword -S -U msf -p 55553 -a 127.0.0.1 &")
    time.sleep(5)

def get_msf_pid():
    pid = os.popen("pgrep -f 'msfrpcd'").read().strip()
    return pid

def stop_msf_rpc():
    pid = get_msf_pid()
    if pid:
        pids = pid.split('\n')
        for pid in pids:
            if pid.strip():
                os.kill(int(pid.strip()), 9)


def connect_metasploit():
    try:
        client = MsfRpcClient('msfpassword', port=55553, host='127.0.0.1')
        msf_version = client.core.version
        exploits_count = len(client.modules.exploits)

        msf_pid = get_msf_pid()
        first_pid = msf_pid.split()[0] if msf_pid else "Bilinmiyor"

        return {
            "status": "success",
            "version": f"Framework: {msf_version.get('version', 'Bilinmiyor')}, "
                       f"Ruby: {msf_version.get('ruby', 'Bilinmiyor')}, "
                       f"API: {msf_version.get('api', 'Bilinmiyor')}",
            "exploits": exploits_count,
            "pid": first_pid
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    scan_type = data.get("scan_type")
    command = data.get("command")

    if scan_type == "nmap" and command:
        result, pdf_filename = run_nmap_scan(command)
    elif scan_type == "metasploit":
        start_msf_rpc()
        result = connect_metasploit()
        pdf_filename = None
    elif scan_type == "wireshark":
        result = {"status": "error", "message": "wireshark"}
        pdf_filename = None
    elif scan_type == "sql_injection":
        result = {"status": "info", "message": "SQL Injection taraması başlatıldı."}
        pdf_filename = None
    elif scan_type == "ZAP PROXY":
        zap_options = data.get("zap_options", {})
        target_ip = data.get("target_ip", "https://example.com")  

        start_zap()
        print("[+] ZAP'ın hazır olması bekleniyor...")
        if not wait_for_zap(timeout=120):
            print("[-] ZAP belirtilen sürede ayağa kalkmadı.")
            return

        zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})


        zap.urlopen(target_ip)
        time.sleep(2)

        spider_results = []
        ajax_results = []
        raw_ajax_results = []
        alerts = []
        ajax_urls = []

        if zap_options.get("spider"):
            spider_id = zap.spider.scan(target_ip)
            while int(zap.spider.status(spider_id)) < 100:
                time.sleep(2)
            spider_results = zap.spider.results(spider_id)

        if zap_options.get("ajax"):
            zap.ajaxSpider.scan(target_ip)
            while zap.ajaxSpider.status != 'stopped':
                time.sleep(5)

            raw_ajax_results = zap.ajaxSpider.results(start=0, count=50)
            print("[+] AJAX RAW RESULTS:")
            print(raw_ajax_results)


            for item in raw_ajax_results:
                if isinstance(item, dict):
                    request_header = item.get('requestHeader', '')
                    lines = request_header.split('\n')
                    for line in lines:
                        if line.lower().startswith('get') or line.lower().startswith('post'):
                            parts = line.split()
                            if len(parts) >= 2:
                                ajax_results.append(parts[1])

        if zap_options.get("active"):
            scan_id = zap.ascan.scan(target_ip)
            while int(zap.ascan.status(scan_id)) < 100:
                time.sleep(5)
            alerts = zap.core.alerts(baseurl=target_ip)


        result = {
            "status": "success",
            "spider_results": spider_results,
            "ajax_results": ajax_results,
            "alerts": alerts
        }


        os.system("fuser -k 8080/tcp")

        pdf_filename = None

    else:
        result = {"status": "error", "message": "Lütfen geçerli bir test türü seçin."}
        pdf_filename = None

    return jsonify({"result": result, "pdf": pdf_filename})

@app.route("/download_pdf", methods=["GET"])
def download_pdf():
    pdf_filename = "nmap_report.pdf"
    if os.path.exists(pdf_filename):
        return send_file(pdf_filename, as_attachment=True)
    else:
        return "PDF bulunamadı", 404

atexit.register(stop_msf_rpc)


@app.route("/add_comment_injection", methods=["POST"])
def add_comment_injection():
    if 'injection_user' not in session:
        return jsonify({"status": "unauthorized"})
    data = request.get_json()
    comment = data.get("comment")
    try:
        conn = pymysql.connect(
            host='localhost', user='root', password='', database='mytestdb',
            cursorclass=pymysql.cursors.DictCursor
        )
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO comments (comment_text) VALUES (%s)", (comment,))
            conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Yorum kaydedildi"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/search_injection", methods=["POST"])
def search_injection():
    if 'injection_user' not in session:
        return jsonify({"status": "unauthorized"})
    data = request.get_json()
    payload = data.get("payload")
    try:
        conn = pymysql.connect(
            host='localhost', user='root', password='', database='mytestdb',
            cursorclass=pymysql.cursors.DictCursor
        )
        with conn.cursor() as cursor:
            query = f"SELECT id, comment_text FROM comments WHERE comment_text LIKE '%{payload}%'"
            cursor.execute(query)
            results = cursor.fetchall()
        conn.close()
        return jsonify({"status": "success", "query": query, "results": results})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/login_injection", methods=["POST"])
def login_injection():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    try:
        conn = pymysql.connect(
            host='localhost',
            user='root',
            password='',
            database='mytestdb',
            cursorclass=pymysql.cursors.DictCursor,
            client_flag=CLIENT.MULTI_STATEMENTS
        )

        with conn.cursor() as cursor:
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            print("Çalıştırılan Sorgu:", query)
            cursor.execute(query)
            user = cursor.fetchone()
        conn.close()
        if user:
            session['injection_user'] = username
            return jsonify({"status": "success", "message": f"Giriş başarılı: {user['username']}"})
        else:
            return jsonify({"status": "fail", "message": "Giriş başarısız"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/start_capture", methods=["POST"])
def start_capture():
    data = request.get_json()
    interface = data.get("interface", "eth0")
    duration = int(data.get("duration", 10))
    filename = f"capture_{int(time.time())}.pcap"
    filepath = os.path.join("captures", filename)

    os.makedirs("captures", exist_ok=True)

    try:
        cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", filepath]
        subprocess.run(cmd, check=True)
        return jsonify({"status": "success", "filename": filename})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/download_capture/<filename>")
def download_capture(filename):
    filepath = os.path.join("captures", filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        return "Dosya bulunamadı", 404




if __name__ == "__main__":
    app.run(debug=True)
