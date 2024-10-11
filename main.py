import tkinter as tk
from scapy.all import sniff, conf
from tkinter import messagebox
from PIL import Image, ImageTk
from scapy.all import sniff, IP, TCP, UDP
from reportlab.lib.pagesizes import letter, inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
import datetime
import threading
import os
import webbrowser
import tempfile

def project_info():
    html_code = """
    <!DOCTYPE html>
<html>
<head>
    <title>Project Information</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f2f2f2;
        }

        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 50px 20px;
            background-color: #fff;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.2);
            border-radius: 4px;
            position: relative;
        }
         .photo {
            position: absolute;
            top: 20px;
            right: 20px;
            width: 100px;
            height: 100px;
            background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAYEAAAMHCAYAAAD/7r7zAAAAA);
            background-size: cover;
            border-radius: 50%;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.2);
        }
        
        h1 {
            font-size: 36px;
            margin-bottom: 30px;
        }

        p {
            font-size: 18px;
            line-height: 1.5;
            margin-bottom: 20px;
        }

        table {
            width: 100%; 
            margin-bottom: 20px; 
            border-collapse: collapse;
        }

        table td,
        table th {
            padding: 10px;
            text-align: left;
            border: 1px solid #ddd;
        }

        table th {
            background-color: #f2f2f2;
            font-size: 18px;
        }

        @media only screen and (max-width: 600px) { 
            .container {
                 padding: 30px 10px;
            }
            h1 {
                font-size: 24px;
            }
            p {
                font-size: 16px;
            }
            .photo {
                width: 100px;
                height: 100px;
# line lost
                right: 10px;
            }
            table td,
            table th { 
                padding: 5px; 
                font-size: 16px;
            }
            table th { 
                font-size: 16px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
    <div class="photo"></div>
        <h1>Project Information</h1>
        <p>This project was developed by the following team members: ST#IS#6727
                                                                    ST#IS#6728
                                                                    ST#IS#6729
                                                                    ST#IS#6730
                                                                    </P>
        <table>
            <thead>
                <tr>
                    <th>Project Details</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Project Name</td>
                    <td>Intrusion Detection System</td>
                </tr>
                <tr>
                    <td>Project Description</td> 
                    <td>Developing a system to monitor network traffic </td>
                </tr>
                <tr>
                    <td>Project Start Date</td>
                    <td>01-AUGUST-2024</td>
                </tr>
                <tr>
                    <td>Project End Date</td>
                    <td>10-SEPT-2024</td>
                </tr>
                <tr>
                    <td>Project Status</td>
                    <td><strong>Completed</strong></td>
                </tr>
            </tbody>
        </table>
        <h2>Developer Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Email</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Rithvik Shaga</td>
                    <td>rithvik8770@gmail.com</td>
                </tr>
        </table>

        <h2>Company Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Company</th>
                    <th>Contact Mail</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Name</td>
                    <td>Supraja Technologies</td>
                </tr>
                <tr>
                    <td>Email</td>
                    <td>contact@suprajatechnologies.com</td>          
        </table>
    """
    
    # Save the HTML content to a temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html') as temp_file:
        temp_file.write(html_code)
        temp_file_path = temp_file.name
    
    # Open the temporary HTML file in the default web browser
    webbrowser.open('file://' + os.path.realpath(temp_file_path))

# List to hold detected attack details
detected_attacks = []

# Set to track seen alerts
seen_alerts = set()

# Flag to control sniffing
sniffing_active = False

# CVSS scores and OWASP mappings for different attack types
attack_details_dict = {
    "SSH Brute Force Attack": {
        "cvss_score": "8.1 (High)",
        "owasp_category": "Identification and Authentication Failures"
    },
    "HTTP DoS Attack": {
        "cvss_score": "7.5 (High)",
        "owasp_category": "Application Denial of Service"
    },
    "SQL Injection Attempt": {
        "cvss_score": "9.8 (Critical)",
        "owasp_category": "Injection"
    }
    # Add more attack types and details here
}

# Define a function to analyze packets
def analyze_packet(packet):
    if IP in packet:
        dst_ip = packet[IP].dst

        if TCP in packet:
            dst_port = packet[TCP].dport
            
            # Detection logic for SSH brute force attack on port 22
            if dst_port == 22:
                detect_attack("SSH Brute Force Attack", dst_ip)
            
            # Detection logic for HTTP DoS attack (example: large number of requests)
            elif dst_port == 80 or dst_port == 443:
                detect_attack("HTTP DoS Attack", dst_ip)
            
            # Add more specific TCP-based attack detections as needed
        
        elif UDP in packet:
            dst_port = packet[UDP].dport
            
            # Detection logic for UDP-based attacks (example: DNS amplification)
            if dst_port == 53:
                detect_attack("UDP-based Attack (DNS Amplification)", dst_ip)



# Function to detect and log attacks
def detect_attack(attack_type, dst_ip):
    # Check if this alert has been shown before
    alert_key = (attack_type, dst_ip)
    if alert_key in seen_alerts:
        return
    
    attack_details = {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dst_ip": dst_ip,
        "attack_type": attack_type,
        "cvss_score": attack_details_dict.get(attack_type, {}).get("cvss_score", "Unknown"),
        "owasp_category": attack_details_dict.get(attack_type, {}).get("owasp_category", "Unknown")
    }
    detected_attacks.append(attack_details)
    
    # Add alert to seen alerts set
    seen_alerts.add(alert_key)
    
    alert_message = (
        f"Suspicious traffic detected: \n"
        f"Type: {attack_details['attack_type']}\n"
        f"Destination IP: {dst_ip}\n"
        f"CVSS Score: {attack_details['cvss_score']}\n"
        f"OWASP Category: {attack_details['owasp_category']}\n"
    )
    messagebox.showwarning("Alert", alert_message)

# Start sniffing network traffic
def start_sniffing():
    global sniffing_active
    sniffing_active = True
    
    try:
        # Attempt layer 2 sniffing (requires Npcap or WinPcap)
        sniff(filter="tcp or udp", prn=analyze_packet, store=0, stop_filter=lambda x: not sniffing_active)
    except RuntimeError as e:
        print("Layer 2 sniffing failed: ", e)
        print("Switching to Layer 3 sniffing (IP layer)...")
        
        # Fallback to Layer 3 sniffing
        conf.L3socket  # Change to L3 socket for layer 3 packet sniffing
        sniff(filter="tcp or udp", prn=analyze_packet, store=0, stop_filter=lambda x: not sniffing_active)

# Stop sniffing network traffic
def stop_sniffing():
    global sniffing_active
    sniffing_active = False
# Generate PDF report
def generate_pdf_report():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"IDS_Report_{timestamp}.pdf"
    doc = SimpleDocTemplate(report_filename, pagesize=letter)

   
   # Title Page 
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    title = Paragraph("Intrusion Detection System Report", title_style)
    generated_time = Paragraph(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Table of detected attacks
    table_data = [["Time", "Attack Type", "Destination IP", "CVSS Score", "OWASP Category"]]
    for attack in detected_attacks:
        row = [
            attack["time"], 
            attack["attack_type"], 
            attack["dst_ip"], 
            attack["cvss_score"],
            attack["owasp_category"]
        ]
        table_data.append(row)
    
    table_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        #missing
                #missing
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ])
    table = Table(table_data, colWidths=[1.5 * inch, 2 * inch, 1.5 * inch, 1 * inch, 2 * inch])
    table.setStyle(table_style)

    # Build the PDF
    elements = [title, Spacer(1, 12), generated_time, Spacer(1, 12), table]
    doc.build(elements)

    messagebox.showinfo("Report Generated", f"Report saved as {report_filename}")

# GUI Application class
class IDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System")
        self.root.configure(bg='black')
        self.root.geometry("600x550")

        self.header_label = tk.Label(root, text="Intrusion Detection System", bg="#26619c", fg="white", font=("Arial", 18, "bold"))
        self.header_label.pack(pady=10)

        self.info_button = tk.Button(root, text="Project Info", font=("Times new roman", 14, "bold"), bg="#26619c", fg="white", command=project_info)
        self.info_button.pack(pady=20)

        # Load and display the image
        image_path = os.path.join(os.path.dirname(__file__), "logo.jpg")
        image = Image.open(image_path)
        image = image.resize((200, 200), Image.Resampling.LANCZOS)
        self.logo = ImageTk.PhotoImage(image)
        self.image_label = tk.Label(root, image=self.logo, bg="black")
        self.image_label.pack(pady=10)

        self.start_button = tk.Button(root, text="Start IDS", command=self.start_ids, bg="#26619c", fg="white")
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(root, text="Stop IDS", command=self.stop_ids, state=tk.DISABLED, bg="#26619c", fg="white")
        self.stop_button.pack(pady=10)

        self.report_button = tk.Button(root, text="Generate Report", command=generate_pdf_report, bg="#26619c", fg="white")
        self.report_button.pack(pady=10)

    def start_ids(self):
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniff_thread = threading.Thread(target=start_sniffing)
        self.sniff_thread.start()

    def stop_ids(self):
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        stop_sniffing()
        try:
            self.sniff_thread.join()
        except AttributeError:
            pass

# Main function
def main():
    root = tk.Tk()
    app = IDSApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
