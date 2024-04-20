import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff

class NetworkTrafficAnalyzer(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Network Traffic Analyzer")
        self.geometry("700x500")

        self.init_ui()

    def init_ui(self):
        # Text box for displaying network packets
        self.txt_display = scrolledtext.ScrolledText(self, wrap=tk.WORD, height=25, width=80)
        self.txt_display.grid(row=0, column=0, columnspan=3, padx=10, pady=10)

        # Start button
        self.btn_start = tk.Button(self, text="Start Capture", command=self.start_capture)
        self.btn_start.grid(row=1, column=0, sticky=tk.W+tk.E, padx=10)

        # Stop button
        self.btn_stop = tk.Button(self, text="Stop Capture", command=self.stop_capture)
        self.btn_stop.grid(row=1, column=1, sticky=tk.W+tk.E, padx=10)

        # Clear button
        self.btn_clear = tk.Button(self, text="Clear", command=self.clear_text)
        self.btn_clear.grid(row=1, column=2, sticky=tk.W+tk.E, padx=10)

    def start_capture(self):
        """ Start packet capturing """
        self.capture = True
        self.sniff_packets()

    def stop_capture(self):
        """ Stop packet capturing """
        self.capture = False

    def sniff_packets(self):
        """ Sniff network packets """
        if self.capture:
            packet = sniff(count=1, prn=lambda x:x.summary())
            self.txt_display.insert(tk.END, f"{packet[0]}\n")
            self.txt_display.see(tk.END)
            self.after(10, self.sniff_packets)  # Continue to sniff

    def clear_text(self):
        """ Clear the text field """
        self.txt_display.delete(1.0, tk.END)

if __name__ == "__main__":
    app = NetworkTrafficAnalyzer()
    app.mainloop()
