import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QPushButton, QWidget
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from scapy.all import *
import time
import seaborn as sns
import pandas as pd
from collections import Counter
import matplotlib.pyplot as plt


class PacketAnalyzerApp(QMainWindow):
    def __init__(self):
        super(PacketAnalyzerApp, self).__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle("Packet Analyzer App")
        self.setGeometry(100, 100, 800, 600)

        # Create a central widget and set the layout
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()

        # Create a button to start the packet analysis
        self.start_button = QPushButton("Start Analysis", self)
        self.start_button.clicked.connect(self.start_analysis)

        # Apply a modern stylesheet to the button
        self.start_button.setStyleSheet(
            """
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 10px 20px;
                font-size: 18px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """
        )

        layout.addWidget(self.start_button)

        # Create a canvas for the matplotlib plots
        self.canvas = PlotCanvas(self, width=5, height=4)

        layout.addWidget(self.canvas)

        central_widget.setLayout(layout)

    def start_analysis(self):
        # Initialize packet counters
        udp_count = 0
        tcp_count = 0
        ip_count = 0
        others_count = 0

        # Initialize time and count lists for plotting
        time_points = []
        udp_counts = []
        tcp_counts = []
        ip_counts = []
        others_counts = []

        # Track the counts of source and destination IP addresses
        source_ip_counts = Counter()
        destination_ip_counts = Counter()

        # Define the packet handling function
        def packet_handler(packet):
            nonlocal udp_count, tcp_count, ip_count, others_count

            if IP in packet:
                ip_count += 1

                if TCP in packet:
                    tcp_count += 1

                elif UDP in packet:
                    udp_count += 1

                else:
                    others_count += 1

                # Track source and destination IP addresses
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
                source_ip_counts[source_ip] += 1
                destination_ip_counts[destination_ip] += 1

        # Start sniffing packets for a specified duration
        duration_seconds = 30  # Adjust the duration as needed
        start_time = time.time()

        while time.time() - start_time < duration_seconds:
            sniff(prn=packet_handler, store=0, count=100)  # Adjust count as needed

            # Append data to lists for plotting after each iteration
            time_points.append(time.time() - start_time)
            udp_counts.append(udp_count)
            tcp_counts.append(tcp_count)
            ip_counts.append(ip_count)
            others_counts.append(others_count)

            # Update the plot
            self.canvas.plot(
                time_points, udp_counts, tcp_counts, ip_counts, others_counts
            )

            # Process events to keep the GUI responsive
            QApplication.processEvents()

        # Plot the final graphs
        self.plot_final_graphs(
            time_points,
            udp_counts,
            tcp_counts,
            ip_counts,
            others_counts,
            source_ip_counts,
            destination_ip_counts,
        )

    def plot_final_graphs(
        self,
        time_points,
        udp_counts,
        tcp_counts,
        ip_counts,
        others_counts,
        source_ip_counts,
        destination_ip_counts,
    ):
        plt.figure(figsize=(15, 10))

        # Line plot for protocol counts
        plt.subplot(2, 2, 1)
        plt.plot(time_points, udp_counts, label="UDP")
        plt.plot(time_points, tcp_counts, label="TCP")
        plt.plot(time_points, ip_counts, label="IP")
        plt.plot(time_points, others_counts, label="Others")
        plt.xlabel("Time (seconds)")
        plt.ylabel("Packet Count")
        plt.title("Packet Analysis over Time")
        plt.legend()
        plt.grid(True)

        # Pie chart for protocol distribution
        plt.subplot(2, 2, 2)
        labels = ["UDP", "TCP", "IP", "Others"]
        sizes = [udp_counts[-1], tcp_counts[-1], ip_counts[-1], others_counts[-1]]
        plt.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
        plt.title("Protocol Distribution")

        # Bar chart for top source IP addresses
        plt.subplot(2, 2, 3)
        top_source_ips = source_ip_counts.most_common(5)
        source_ips, source_counts = zip(*top_source_ips)
        plt.bar(source_ips, source_counts, color="blue", alpha=0.7)
        plt.xlabel("Source IP Address")
        plt.ylabel("Packet Count")
        plt.title("Top Source IP Addresses")

        # Bar chart for top destination IP addresses
        plt.subplot(2, 2, 4)
        top_destination_ips = destination_ip_counts.most_common(5)
        destination_ips, destination_counts = zip(*top_destination_ips)
        plt.bar(destination_ips, destination_counts, color="orange", alpha=0.7)
        plt.xlabel("Destination IP Address")
        plt.ylabel("Packet Count")
        plt.title("Top Destination IP Addresses")

        plt.tight_layout()
        plt.show()


class PlotCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = fig.add_subplot(111)

        FigureCanvas.__init__(self, fig)
        self.setParent(parent)

    def plot(self, time_points, udp_counts, tcp_counts, ip_counts, others_counts):
        self.axes.clear()
        self.axes.plot(time_points, udp_counts, label="UDP")
        self.axes.plot(time_points, tcp_counts, label="TCP")
        self.axes.plot(time_points, ip_counts, label="IP")
        self.axes.plot(time_points, others_counts, label="Others")

        self.axes.set_xlabel("Time (seconds)")
        self.axes.set_ylabel("Packet Count")
        self.axes.set_title("Packet Analysis over Time")
        self.axes.legend()
        self.axes.grid(True)

        self.draw()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketAnalyzerApp()
    window.show()
    sys.exit(app.exec_())
