#!/usr/bin/env python
import sys
import subprocess
import paramiko
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QTextEdit, QPushButton, QLabel, QLineEdit, QHBoxLayout
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QThread, pyqtSignal

class NetworkScanThread(QThread):
    progress_signal = pyqtSignal(float)
    result_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanning = False
        self.start_ip = "10.0.0.1"  # Default start IP address
        self.end_ip = "10.0.0.254"  # Default end IP address

    def set_custom_range(self, start_ip, end_ip):
        self.start_ip = start_ip
        self.end_ip = end_ip

    def check_ssh_enabled(self, ip_address):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Set the connection timeout to 2 seconds
            client.connect(ip_address, port=22, timeout=2)
            client.close()
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException, TimeoutError):
            return False

    def run(self):
        start_octets = list(map(int, self.start_ip.split('.')))
        end_octets = list(map(int, self.end_ip.split('.')))

        total_ips = (end_octets[0] - start_octets[0] + 1) * (end_octets[1] - start_octets[1] + 1) * \
                    (end_octets[2] - start_octets[2] + 1) * (end_octets[3] - start_octets[3] + 1)
        completed_ips = 0

        headers = "IP Address      | Hostname          | Port 22 Status | SSH Status\n"
        underline_header = "----------------+------------------+---------------+-----------\n"
        results = headers + underline_header

        for o1 in range(start_octets[0], end_octets[0] + 1):
            for o2 in range(start_octets[1], end_octets[1] + 1):
                for o3 in range(start_octets[2], end_octets[2] + 1):
                    for o4 in range(start_octets[3], end_octets[3] + 1):
                        if not self.scanning:
                            self.finished_signal.emit()
                            return

                        ip_address = f"{o1}.{o2}.{o3}.{o4}"
                        ping_command = f"ping -c 2 -W 2 {ip_address}"
                        ping_result = subprocess.run(ping_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        if ping_result.returncode == 0:
                            port_status = self.get_port_status(ip_address)
                            ssh_status = self.check_ssh_enabled(ip_address)
                            result_line = f"{ip_address.ljust(15)} | {self.get_hostname(ip_address).ljust(15)} | {port_status} | {'Enabled' if ssh_status else 'Disabled'}\n"
                            results += result_line
                            completed_ips += 1
                            progress = completed_ips / total_ips * 100.0
                            self.progress_signal.emit(progress)
                            self.result_signal.emit(results)

        results += "Scan Completed.\n"
        self.result_signal.emit(results)
        self.finished_signal.emit()

    def get_hostname(self, ip_address):
        command = f"nmap -sn {ip_address}"
        nmap_output = subprocess.getoutput(command)
        hostname = "N/A"
        hostname_line = [line for line in nmap_output.splitlines() if "Nmap scan report for" in line]
        if hostname_line:
            hostname = hostname_line[0].split("Nmap scan report for ")[1]
        return hostname

    def get_port_status(self, ip_address):
        nmap_command = f"nmap -p 22 {ip_address}"
        nmap_result = subprocess.run(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if "22/tcp open" in nmap_result.stdout.decode():
            return "OPEN"
        return "CLOSED"

class NetworkScanApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Network Scan GUI")
        self.setGeometry(100, 100, 400, 400)  # Set window size to 400x400
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout()
        self.progress_label = QLabel("0%", alignment=Qt.AlignCenter)
        layout.addWidget(self.progress_label)

        self.results_textedit = QTextEdit()
        font = QFont("Monospace", 10)  # Use the Monospace font
        self.results_textedit.setFont(font)
        self.results_textedit.setLineWrapMode(QTextEdit.NoWrap)  # Disable line wrap
        layout.addWidget(self.results_textedit)

        # Create input boxes for custom start and end IP addresses
        self.start_ip_input = QLineEdit("10.0.0.1")
        self.end_ip_input = QLineEdit("10.0.0.254")
        ip_input_layout = QHBoxLayout()
        ip_input_layout.addWidget(QLabel("Start IP:"))
        ip_input_layout.addWidget(self.start_ip_input)
        ip_input_layout.addWidget(QLabel("End IP:"))
        ip_input_layout.addWidget(self.end_ip_input)
        layout.addLayout(ip_input_layout)

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.toggle_scan)
        layout.addWidget(self.scan_button)

        self.exit_button = QPushButton("Exit")
        self.exit_button.clicked.connect(self.exit_app)
        layout.addWidget(self.exit_button)

        self.central_widget.setLayout(layout)

        self.network_scan_thread = NetworkScanThread()
        self.network_scan_thread.progress_signal.connect(self.update_progress_label)
        self.network_scan_thread.result_signal.connect(self.update_results_textedit)
        self.network_scan_thread.finished_signal.connect(self.scan_finished)

        self.scanning = False
        self.update_results()

    def toggle_scan(self):
        if not self.scanning:
            # Retrieve the custom start and end IP addresses from the input boxes
            start_ip = self.start_ip_input.text()
            end_ip = self.end_ip_input.text()

            self.scanning = True
            self.scan_button.setText("Stop Scan")
            self.exit_button.setEnabled(False)
            self.update_results()
            self.network_scan_thread.scanning = True
            self.network_scan_thread.set_custom_range(start_ip, end_ip)  # Add this line to pass the custom IP range
            self.network_scan_thread.start()
        else:
            self.scanning = False
            self.scan_button.setText("Start Scan")
            self.exit_button.setEnabled(True)
            self.network_scan_thread.scanning = False

    def update_progress_label(self, progress):
        self.progress_label.setText(f"{progress:.1f}%")

    def update_results(self):
        headers = "IP Address      | Hostname          | Port 22 Status | SSH Status\n"
        underline_header = "----------------+------------------+---------------+-----------\n"
        self.results_textedit.setPlainText(headers + underline_header)

    def update_results_textedit(self, results):
        self.results_textedit.setPlainText(results)

    def scan_finished(self):
        self.scanning = False
        self.scan_button.setText("Start Scan")
        self.exit_button.setEnabled(True)
        self.network_scan_thread.scanning = False
        self.results_textedit.append("Scan Completed.")

    def exit_app(self):
        self.network_scan_thread.scanning = False
        self.network_scan_thread.wait()
        self.save_to_file()
        self.close()

    def save_to_file(self):
        with open("network_scan_results.txt", "w") as file:
            file.write(self.results_textedit.toPlainText())

def main():
    app = QApplication(sys.argv)
    window = NetworkScanApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
