import tkinter as tk
from tkinter import ttk
from scapy.all import *
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from threading import Thread
import time

class PacketAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Analyzer GUI")

        # GUI components
        self.interface_label = ttk.Label(root, text="Select Interface:")
        self.interface_combobox = ttk.Combobox(root, values=self.get_network_interfaces())

        self.start_button = ttk.Button(root, text="Start Capture", command=self.start_capture)
        self.stop_button = ttk.Button(root, text="Stop Capture", command=self.stop_capture)

        self.packet_stats_label = ttk.Label(root, text="Packet Statistics:")
        self.packet_stats_text = tk.Text(root, height=10, width=50)

        # Matplotlib figure for real-time visualization
        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=root)
        self.canvas_widget = self.canvas.get_tk_widget()

        # GUI layout
        self.interface_label.grid(row=0, column=0, padx=10, pady=10)
        self.interface_combobox.grid(row=0, column=1, padx=10, pady=10)
        self.start_button.grid(row=1, column=0, columnspan=2, pady=10)
        self.stop_button.grid(row=2, column=0, columnspan=2, pady=10)
        self.packet_stats_label.grid(row=3, column=0, columnspan=2, pady=10)
        self.packet_stats_text.grid(row=4, column=0, columnspan=2, pady=10)
        self.canvas_widget.grid(row=0, column=2, rowspan=5, padx=10, pady=10)

        # Initialize variables
        self.is_capture_running = False

        # Global variables for statistics
        self.packet_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.timestamps = []
        self.packet_count_data = {"TCP": [], "UDP": [], "ICMP": [], "Other": []}

        # Lock for thread-safe access to global variables
        self.lock = threading.Lock()

        # Dictionary to map protocol numbers to protocol names
        self.protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
        }

    def get_network_interfaces(self):
        # Function to retrieve available network interfaces
        return [iface[0] for iface in get_if_list()]

    def start_capture(self):
        # Function to start packet capture
        self.is_capture_running = True
        interface = self.interface_combobox.get()

        def capture_packets():
            # Function to capture packets in a separate thread
            while self.is_capture_running:
                packet = sniff(iface=interface, count=1, prn=self.packet_analyzer)

        # Start packet capture in a separate thread
        self.capture_thread = Thread(target=capture_packets)
        self.capture_thread.start()

    def stop_capture(self):
        # Function to stop packet capture
        self.is_capture_running = False
        self.capture_thread.join()

    def packet_analyzer(self, packet):
        # Function to analyze packets
        if IP in packet:
            with self.lock:
                protocol_num = packet[IP].proto
                protocol = self.protocols.get(protocol_num, "Other")
                self.packet_counts[protocol] += 1
                self.timestamps.append(time.time())

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            print(f"Source Port: {src_port}, Destination Port: {dst_port}, TCP Flags: {flags}")
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")

    def update_packet_stats(self):
        # Function to update packet statistics
        with self.lock:
            stats_text = ""
            for protocol, count in self.packet_counts.items():
                stats_text += f"{protocol}: {count}\n"
                self.packet_count_data[protocol].append(count)
                self.packet_counts[protocol] = 0  # Reset packet count for the next interval

            # Ensure that timestamps have the same length as the data lists in packet_count_data
            for protocol in self.packet_count_data:
                while len(self.packet_count_data[protocol]) < len(self.timestamps):
                    self.packet_count_data[protocol].append(0)  # Fill with zeros if needed

            self.timestamps.append(time.time())

            # Update real-time visualization
            self.update_real_time_visualization()

            # Update packet statistics text in GUI
            self.packet_stats_text.delete(1.0, tk.END)
            self.packet_stats_text.insert(tk.END, stats_text)

    def update_real_time_visualization(self):
        # Function to update real-time visualization using matplotlib
        self.ax.clear()
        self.ax.set_title("Packet Statistics Over Time")
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Packet Count")
        for protocol in self.packet_count_data:
            self.ax.plot(self.timestamps, self.packet_count_data[protocol], label=protocol)
        self.ax.legend()
        self.canvas.draw()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzerGUI(root)
    root.mainloop()
