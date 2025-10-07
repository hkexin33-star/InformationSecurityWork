import random
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton,
                             QTextEdit, QGroupBox, QMessageBox)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon
import T1_SDES as SDES


class SDESGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.sdes = SDES.SDES()
        self.is_encrypt_mode = True

        # 设置窗口
        self.setWindowTitle("S-DES加密解密工具")
        self.setMinimumSize(1200, 900)

        # 设置样式
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f4f8;
            }
            QLabel#titleLabel {
                font-size: 24px;
                font-weight: bold;
                color: #3B82F6;
                margin: 10px 0px;
            }
            QLabel#subtitleLabel {
                font-size: 30px;
                color: #64748b;
                margin-bottom: 20px;
            }
            QLabel {
                font-size: 30px;
                color: #334155;
            }
            QLineEdit {
                padding: 8px;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                font-size: 30px;
            }
            QLineEdit:focus {
                border-color: #3B82F6;
                background-color: #f8fafc;
            }
            QPushButton {
                background-color: #3B82F6;
                color: white;
                padding: 8px 16px;
                border-radius: 6px;
                font-size: 30px;
                border: none;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            QPushButton:pressed {
                background-color: #1d4ed8;
            }
            QPushButton#decryptBtn {
                background-color: #10B981;
            }
            QPushButton#decryptBtn:hover {
                background-color: #059669;
            }
            QPushButton#decryptBtn:pressed {
                background-color: #065f46;
            }
            QPushButton#randomBtn {
                background-color: #e2e8f0;
                color: #334155;
                padding: 8px;
            }
            QPushButton#randomBtn:hover {
                background-color: #cbd5e1;
            }
            QGroupBox {
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                margin-top: 10px;
                padding: 15px;
                background-color: white;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                top: 0px;
                color: #334155;
                font-weight: bold;
            }
            QTextEdit {
                background-color: #1e293b;
                color: #e2e8f0;
                font-family: Consolas, Monaco, monospace;
                font-size: 30px;
                border-radius: 6px;
                padding: 8px;
            }
        """)

        # 创建主部件和布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # 添加标题
        title_label = QLabel("S-DES加密解密工具")
        title_label.setObjectName("titleLabel")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 50px; font-weight: bold;")
        main_layout.addWidget(title_label)

        subtitle_label = QLabel(
            "简化数据加密标准(Simplified Data Encryption Standard)的实现，支持8位二进制明文/密文与10位二进制密钥的加解密操作")
        subtitle_label.setObjectName("subtitleLabel")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("font-size: 28px; font-weight: bold;")
        subtitle_label.setWordWrap(True)
        main_layout.addWidget(subtitle_label)

        # 操作模式选择
        mode_layout = QHBoxLayout()
        mode_layout.setSpacing(10)

        self.encrypt_btn = QPushButton("加密")
        self.encrypt_btn.setStyleSheet("font-size: 32px; font-weight: bold;")
        self.encrypt_btn.setIcon(QIcon.fromTheme("lock", QIcon()))
        self.encrypt_btn.setCheckable(True)
        self.encrypt_btn.setChecked(True)
        self.encrypt_btn.clicked.connect(self.set_encrypt_mode)

        self.decrypt_btn = QPushButton("解密")
        self.decrypt_btn.setStyleSheet("font-size: 32px; font-weight: bold;")
        self.decrypt_btn.setObjectName("decryptBtn")
        self.decrypt_btn.setIcon(QIcon.fromTheme("unlock", QIcon()))
        self.decrypt_btn.setCheckable(True)
        self.decrypt_btn.clicked.connect(self.set_decrypt_mode)

        mode_layout.addWidget(self.encrypt_btn)
        mode_layout.addWidget(self.decrypt_btn)
        mode_layout.setAlignment(Qt.AlignCenter)
        main_layout.addLayout(mode_layout)

        # 输入区域
        input_group = QGroupBox("输入")
        input_group.setStyleSheet("font-size: 30px")
        input_layout = QVBoxLayout()
        input_layout.setSpacing(15)

        # 操作类型显示
        self.mode_label = QLabel("操作类型: 加密")
        input_layout.addWidget(self.mode_label)

        # 数据输入
        data_layout = QHBoxLayout()
        self.data_label = QLabel("请输入8位二进制明文:")
        self.data_input = QLineEdit()
        self.data_input.setPlaceholderText("例如: 10110101")
        self.random_data_btn = QPushButton("随机")
        self.random_data_btn.setObjectName("randomBtn")
        self.random_data_btn.clicked.connect(self.generate_random_data)

        data_layout.addWidget(self.data_label, 1)
        data_layout.addWidget(self.data_input, 3)
        data_layout.addWidget(self.random_data_btn, 0)
        input_layout.addLayout(data_layout)

        # 密钥输入
        key_layout = QHBoxLayout()
        key_label = QLabel("请输入10位二进制密钥:")
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("例如: 1010000010")
        self.random_key_btn = QPushButton("随机")
        self.random_key_btn.setObjectName("randomBtn")
        self.random_key_btn.clicked.connect(self.generate_random_key)

        key_layout.addWidget(key_label, 1)
        key_layout.addWidget(self.key_input, 3)
        key_layout.addWidget(self.random_key_btn, 0)
        input_layout.addLayout(key_layout)

        # 执行按钮
        self.process_btn = QPushButton("执行加密")
        self.process_btn.setIcon(QIcon.fromTheme("system-run", QIcon()))
        self.process_btn.clicked.connect(self.process)
        input_layout.addWidget(self.process_btn)

        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)

        # 结果区域
        self.result_group = QGroupBox("结果")
        self.result_group.setVisible(False)
        result_layout = QVBoxLayout()

        self.result_text_label = QLabel("密文:")
        self.result_value = QLabel("")
        self.result_value.setFont(QFont("Consolas", 30))
        self.result_value.setStyleSheet("color: #3B82F6; font-weight: bold;")

        result_layout.addWidget(self.result_text_label)
        result_layout.addWidget(self.result_value)
        self.result_group.setLayout(result_layout)
        main_layout.addWidget(self.result_group)

        # 详细过程区域
        details_layout = QVBoxLayout()

        self.toggle_details_btn = QPushButton("显示详细过程")
        self.toggle_details_btn.setObjectName("toggleBtn")
        self.toggle_details_btn.clicked.connect(self.toggle_details)
        details_layout.addWidget(self.toggle_details_btn)

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setVisible(False)
        details_layout.addWidget(self.details_text)

        main_layout.addLayout(details_layout)

        # 填充空间
        main_layout.addStretch()

    def set_encrypt_mode(self):
        """设置为加密模式"""
        self.is_encrypt_mode = True
        self.encrypt_btn.setChecked(True)
        self.decrypt_btn.setChecked(False)
        self.mode_label.setText("操作类型: 加密")
        self.data_label.setText("请输入8位二进制明文:")
        self.process_btn.setText("执行加密")
        self.result_text_label.setText("密文:")
        self.result_group.setVisible(False)
        self.reset_input_styles()

    def set_decrypt_mode(self):
        """设置为解密模式"""
        self.is_encrypt_mode = False
        self.encrypt_btn.setChecked(False)
        self.decrypt_btn.setChecked(True)
        self.mode_label.setText("操作类型: 解密")
        self.data_label.setText("请输入8位二进制密文:")
        self.process_btn.setText("执行解密")
        self.result_text_label.setText("明文:")
        self.result_group.setVisible(False)
        self.reset_input_styles()

    def generate_random_data(self):
        """生成随机8位二进制数据"""
        data = ''.join(str(random.randint(0, 1)) for _ in range(8))
        self.data_input.setText(data)

    def generate_random_key(self):
        """生成随机10位二进制密钥"""
        key = ''.join(str(random.randint(0, 1)) for _ in range(10))
        self.key_input.setText(key)

    def reset_input_styles(self):
        """重置输入框样式"""
        self.data_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            font-size: 30px;
        """)
        self.key_input.setStyleSheet("""
            padding: 8px;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            font-size: 30px;
        """)

    def highlight_invalid_input(self, widget):
        """高亮显示无效输入"""
        widget.setStyleSheet("""
            padding: 8px;
            border: 1px solid #ef4444;
            border-radius: 6px;
            font-size: 30px;
            background-color: #fee2e2;
        """)

    def toggle_details(self):
        """显示或隐藏详细过程"""
        self.details_text.setVisible(not self.details_text.isVisible())
        if self.details_text.isVisible():
            self.toggle_details_btn.setText("隐藏详细过程")
        else:
            self.toggle_details_btn.setText("显示详细过程")

    def process(self):
        """处理加密或解密"""
        self.reset_input_styles()
        data = self.data_input.text().strip()
        key = self.key_input.text().strip()

        # 验证输入
        if not data or not all(c in '01' for c in data) or len(data) != 8:
            self.highlight_invalid_input(self.data_input)
            QMessageBox.warning(self, "输入错误", "请输入8位二进制数字(仅0和1)")
            return

        if not key or not all(c in '01' for c in key) or len(key) != 10:
            self.highlight_invalid_input(self.key_input)
            QMessageBox.warning(self, "输入错误", "请输入10位二进制数字(仅0和1)")
            return

        # 执行加密或解密
        try:
            if self.is_encrypt_mode:
                result = self.sdes.encrypt(data, key)
            else:
                result = self.sdes.decrypt(data, key)

            # 显示结果
            self.result_value.setText(result)
            self.result_group.setVisible(True)

            # 显示详细过程
            self.details_text.setText(self.sdes.get_log())
        except Exception as e:
            QMessageBox.critical(self, "错误", f"处理过程中发生错误: {str(e)}")

