import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from scapy.all import sniff, IP, TCP, UDP, ICMP


class PacketCaptureWorker(QThread):
    packet_received = pyqtSignal(object)

    def run(self):
        def packet_callback(packet):
            if IP in packet:
                self.packet_received.emit(packet)

        # Start sniffing the network
        sniff(prn=packet_callback, store=0)


class PacketCaptureApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

        # Initialize packet counters
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0

        # Create and start the packet capture worker
        self.worker = PacketCaptureWorker()
        self.worker.packet_received.connect(self.handle_packet_received)
        self.worker.start()

    def init_ui(self):
        self.setWindowTitle("Packet Capture App")

        self.start_button = QPushButton("Start Capture", self)
        self.start_button.clicked.connect(self.start_capture)

        self.stop_button = QPushButton("Stop Capture", self)
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)

        self.packet_count_label = QLabel("Packet Counts:", self)

        vbox = QVBoxLayout()
        vbox.addWidget(self.start_button)
        vbox.addWidget(self.stop_button)
        vbox.addWidget(self.packet_count_label)

        self.setLayout(vbox)

    def start_capture(self):
        # Reset packet counters
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0

        # Enable "Stop Capture" button and disable "Start Capture" button
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def stop_capture(self):
        # Enable "Start Capture" button and disable "Stop Capture" button
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def handle_packet_received(self, packet):
        # Process the received packet and update counters
        if TCP in packet:
            self.tcp_count += 1
        elif UDP in packet:
            self.udp_count += 1
        elif ICMP in packet:
            self.icmp_count += 1

        # Update packet count label
        self.update_packet_count_label()

    def update_packet_count_label(self):
        count_text = (
            f"TCP: {self.tcp_count} | UDP: {self.udp_count} | ICMP: {self.icmp_count}"
        )
        self.packet_count_label.setText(count_text)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketCaptureApp()
    window.show()
    sys.exit(app.exec_())
