import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout, QCheckBox, QComboBox
import click


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set window title
        self.setWindowTitle("Capture, Convert and Portscan")

        # Create main widget
        self.main_widget = QWidget()

        # Create input label and text box for capture function
        capture_label = QLabel("Enter URL:")
        self.capture_text = QLineEdit()
        self.capture_text.setPlaceholderText("http://example.com")

        # Create button for capture function
        capture_button = QPushButton("Capture")
        capture_button.clicked.connect(self.capture)

        # Create output label and text box for capture function
        self.capture_output_label = QLabel("Capture output:")
        self.capture_output_text = QTextEdit()
        self.capture_output_text.setReadOnly(True)

        # Create input label and text box for convert function
        convert_label = QLabel("Enter data:")
        self.convert_text = QTextEdit()
        self.convert_text.setPlaceholderText("Enter data to convert")

        # Create dropdown menu for conversion type selection
        convert_type_label = QLabel("Select conversion type:")
        self.convert_type_dropdown = QComboBox()
        self.convert_type_dropdown.addItem("URL")
        self.convert_type_dropdown.addItem("HTML")
        self.convert_type_dropdown.addItem("Base64")
        self.convert_type_dropdown.addItem("ASCII")
        self.convert_type_dropdown.addItem("Hex")
        self.convert_type_dropdown.addItem("Octal")
        self.convert_type_dropdown.addItem("Binary")
        self.convert_type_dropdown.addItem("MD5")
        self.convert_type_dropdown.addItem("SHA1")
        self.convert_type_dropdown.addItem("SHA256")
        self.convert_type_dropdown.addItem("BLAKE2B-160")
        self.convert_type_dropdown.addItem("GZIP")
        self.convert_type_dropdown.setCurrentIndex(2)

        # Create button for convert function
        convert_button = QPushButton("Convert")
        convert_button.clicked.connect(self.convert)

        # Create output label and text box for convert function
        self.convert_output_label = QLabel("Convert output:")
        self.convert_output_text = QTextEdit()
        self.convert_output_text.setReadOnly(True)

        # Create input label and check box for portscan function
        portscan_label = QLabel("Enter URL:")
        self.portscan_text = QLineEdit()
        self.portscan_text.setPlaceholderText("http://example.com")
        self.common_ports_checkbox = QCheckBox("Scan only the most common HTTP ports (80, 8080, and 443)")

        # Create button for portscan function
        portscan_button = QPushButton("Portscan")
        portscan_button.clicked.connect(self.portscan)

        # Create output label and text box for portscan function
        self.portscan_output_label = QLabel("Portscan output:")
        self.portscan_output_text = QTextEdit()
        self.portscan_output_text.setReadOnly(True)

        # Add widgets to main widget
        capture_layout = QHBoxLayout()
        capture_layout.addWidget(capture_label)
        capture_layout.addWidget(self.capture_text)
        capture_layout.addWidget(capture_button)
        capture_output_layout = QHBoxLayout()
        capture_output_layout.addWidget(self.capture_output_label)
        capture_output_layout.addWidget(self.capture_output_text)
        convert_type_layout = QHBoxLayout()
        convert_type_layout.addWidget(convert_type_label)
        convert_type_layout.addWidget(self.convert_type_dropdown)
        convert_layout = QHBoxLayout()
        convert_layout.addWidget(convert_label)
        convert_layout.addWidget(self.convert_text)
        convert_layout.addWidget(convert_button)
        convert_output_layout = QHBoxLayout()
        convert_output_layout.addWidget(self.convert_output_label)
        convert_output_layout.addWidget(self.convert_output_text)
        portscan_layout = QHBoxLayout()
        portscan_layout.addWidget(portscan_label)
        portscan_layout.addWidget(self.portscan_text)
        portscan_layout.addWidget(self.common_ports_checkbox)
        portscan_layout.addWidget(portscan_button)
        portscan_output_layout = QHBoxLayout()
        portscan_output_layout.addWidget(self.portscan_output_label)
        portscan_output_layout.addWidget(self.portscan_output_text)
        layout = QVBoxLayout()
        layout.addLayout(capture_layout)
        layout.addLayout(capture_output_layout)
        layout.addLayout(convert_type_layout)
        layout.addLayout(convert_layout)
        layout.addLayout(convert_output_layout)
        layout.addLayout(portscan_layout)
        layout.addLayout(portscan_output_layout)
        self.main_widget.setLayout(layout)

        # Set main widget as central widget
        self.setCentralWidget(self.main_widget)

    def capture(self):
        """
        Captures the request headers for a given URL.
        """
        url = self.capture_text.text()
        apply_capture(url)
        self.capture_output_text.clear()
        self.capture_output_text.insertPlainText("Request headers captured.")

    def convert(self):
        """
        Applies a specified decoding or hashing function to input data.
        """
        data = self.convert_text.toPlainText()
        transformation_type = self.convert_type_dropdown.currentText()
        try:
            result = apply_transformation(data.encode('utf-8'), transformation_type)
        except Exception as e:
            self.convert_output_text.clear()
            self.convert_output_text.insertPlainText(f"Error: {str(e)}")
        else:
            self.convert_output_text.clear()
            self.convert_output_text.insertPlainText(result.decode('utf-8'))

    def portscan(self):
        """
        Performs a TCP port scan on a specified hostname or URL and a range of ports.
        """
        url = self.portscan_text.text()
        common_ports = self.common_ports_checkbox.isChecked()
        open_ports = apply_scan_ports(url, common_ports)
        self.portscan_output_text.clear()
        self.portscan_output_text.insertPlainText("Open Ports:\n")
        for port in open_ports:
            self.portscan_output_text.insertPlainText(f"{port}\n")


if __name__ == "__main__":
    # Initialize application
    app = QApplication(sys.argv)

    # Create and show main window
    window = MainWindow()
    window.show()

    # Run event loop
    sys.exit(app.exec_())

       
