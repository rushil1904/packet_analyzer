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

        # Time series heatmap for protocol activity
        df = pd.DataFrame(
            {
                "UDP": udp_counts,
                "TCP": tcp_counts,
                "IP": ip_counts,
                "Others": others_counts,
            },
            index=time_points,
        )
        sns.heatmap(
            df.T,
            cmap="viridis",
            annot=True,
            fmt="d",
            cbar_kws={"label": "Packet Count"},
        )
        plt.title("Protocol Activity over Time")
        plt.xlabel("Time")
        plt.ylabel("Protocol")
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
