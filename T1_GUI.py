# 扩展后的 PyQt5 GUI：集成第1~5关
# 功能：
# - 基本 8-bit 加解密（保留原有界面）
# - ASCII 模式（第3关）：对字符串逐字节加解密
# - 暴力破解（第4关）：后台多线程暴力破解，进度条显示，结果表格显示，支持导出 CSV
# - 碰撞分析（第5关）：对单个明文统计不同密钥产生相同密文的情况，并可绘制直方图
#
# 依赖：PyQt5, matplotlib
# 使用方法：python3 T1_Main.py

from PyQt5.QtWidgets import (
    QWidget, QLabel, QLineEdit, QPushButton, QTextEdit, QVBoxLayout, QHBoxLayout,
    QGridLayout, QApplication, QComboBox, QFileDialog, QProgressBar, QTableWidget,
    QTableWidgetItem, QTabWidget, QMessageBox, QSpinBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
import sys
import csv
import time
from typing import List, Tuple, Dict

# 绘图支持
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# 导入增强后的 SDES 实现（请确保 T1_SDES.py 在同目录）
from T1_SDES import SDES


# ---------------------------
# 后台线程：暴力破解（用于避免阻塞 UI）
# ---------------------------
class BruteForceThread(QThread):
    progress_update = pyqtSignal(int)  # 已完成的密钥数量
    finished_signal = pyqtSignal(list, float)  # (matching_keys_list, elapsed_seconds)

    def __init__(self, sdes: SDES, pairs: List[Tuple[str, str]], use_threads: bool = True, max_workers: int = 8):
        super().__init__()
        self.sdes = sdes
        self.pairs = pairs
        self.use_threads = use_threads
        self.max_workers = max_workers
        self._is_interrupted = False

    def run(self):
        start_time = time.perf_counter()
        matches = []

        # We'll iterate keys in main thread of worker and update progress periodically.
        # If there are multiple pairs, check all.
        total_keys = 1024
        report_interval = 32  # 每多少个 key 更新一次进度

        # To leverage sdes's built-in multi-threaded test_key, we can call its non-threaded path here
        # but to control progress we iterate ourselves.
        for k in range(total_keys):
            if self._is_interrupted:
                break
            k_bin = format(k, '010b')
            ok_all = True
            for p8, c8 in self.pairs:
                # Use the encrypt method (which resets sdes log). To avoid logs flooding, we won't fetch logs here.
                c_calc = self.sdes.encrypt(p8, k_bin)
                if c_calc != c8:
                    ok_all = False
                    break
            if ok_all:
                matches.append(k_bin)

            # periodic progress update
            if k % report_interval == 0 or k == total_keys - 1:
                self.progress_update.emit(k + 1)

        elapsed = time.perf_counter() - start_time
        self.finished_signal.emit(matches, elapsed)

    def interrupt(self):
        """请求线程中断（友好停止）"""
        self._is_interrupted = True


# ---------------------------
# 后台线程：碰撞分析（用于避免阻塞 UI）
# ---------------------------
class CollisionThread(QThread):
    progress_update = pyqtSignal(int)
    finished_signal = pyqtSignal(dict, float)  # mapping: ciphertext -> [keys...]

    def __init__(self, sdes: SDES, plaintext8: str):
        super().__init__()
        self.sdes = sdes
        self.plaintext8 = plaintext8
        self._is_interrupted = False

    def run(self):
        start_time = time.perf_counter()
        mapping: Dict[str, List[str]] = {}
        total_keys = 1024
        report_interval = 32

        for k in range(total_keys):
            if self._is_interrupted:
                break
            k_bin = format(k, '010b')
            c = self.sdes.encrypt(self.plaintext8, k_bin)
            mapping.setdefault(c, []).append(k_bin)

            if k % report_interval == 0 or k == total_keys - 1:
                self.progress_update.emit(k + 1)

        collisions = {c: keys for c, keys in mapping.items() if len(keys) > 1}
        elapsed = time.perf_counter() - start_time
        self.finished_signal.emit(collisions, elapsed)

    def interrupt(self):
        self._is_interrupted = True


# ---------------------------
# Matplotlib 图表容器（用于嵌入 GUI）
# ---------------------------
class MplCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=3, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = fig.add_subplot(111)
        super().__init__(fig)


# ---------------------------
# 主窗口类（对外默认类名 SDESGUI，和原版本约定一致）
# ---------------------------
class SDESGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("S-DES 实验界面（集成 第3/4/5 关）")
        self.setMinimumSize(1000, 700)
        self.sdes = SDES()

        # 主布局采用选项卡，分区清晰
        self.tabs = QTabWidget()
        self.tab_basic = QWidget()
        self.tab_ascii = QWidget()
        self.tab_bruteforce = QWidget()
        self.tab_collision = QWidget()

        self.tabs.addTab(self.tab_basic, "基本加/解密")
        self.tabs.addTab(self.tab_ascii, "ASCII 模式（第3关）")
        self.tabs.addTab(self.tab_bruteforce, "暴力破解（第4关）")
        self.tabs.addTab(self.tab_collision, "碰撞分析（第5关）")

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)

        # 初始化各 Tab 的 UI
        self.init_basic_tab()
        self.init_ascii_tab()
        self.init_bruteforce_tab()
        self.init_collision_tab()

    # ---------------------------
    # 基本加/解密 Tab（保留原有功能）
    # ---------------------------
    def init_basic_tab(self):
        layout = QGridLayout()
        self.tab_basic.setLayout(layout)

        lbl_input = QLabel("明文/密文 (8-bit):")
        self.input_bits = QLineEdit()
        self.input_bits.setPlaceholderText("例如：10110101")

        lbl_key = QLabel("密钥 (10-bit):")
        self.input_key = QLineEdit()
        self.input_key.setPlaceholderText("例如：1010000010")

        lbl_mode = QLabel("模式:")
        self.combo_mode = QComboBox()
        self.combo_mode.addItems(["加密", "解密"])

        btn_execute = QPushButton("执行")
        btn_execute.clicked.connect(self.on_basic_execute)

        btn_rand_key = QPushButton("随机密钥")
        btn_rand_key.clicked.connect(self.on_generate_random_key)

        self.basic_result = QLineEdit()
        self.basic_result.setReadOnly(True)

        self.basic_log = QTextEdit()
        self.basic_log.setReadOnly(True)

        layout.addWidget(lbl_input, 0, 0)
        layout.addWidget(self.input_bits, 0, 1, 1, 3)
        layout.addWidget(lbl_key, 1, 0)
        layout.addWidget(self.input_key, 1, 1)
        layout.addWidget(btn_rand_key, 1, 2)
        layout.addWidget(lbl_mode, 2, 0)
        layout.addWidget(self.combo_mode, 2, 1)
        layout.addWidget(btn_execute, 2, 2)
        layout.addWidget(QLabel("输出 (8-bit):"), 3, 0)
        layout.addWidget(self.basic_result, 3, 1, 1, 2)
        layout.addWidget(QLabel("详细过程日志:"), 4, 0)
        layout.addWidget(self.basic_log, 5, 0, 1, 4)

    def on_basic_execute(self):
        data = self.input_bits.text().strip()
        key = self.input_key.text().strip()
        mode = self.combo_mode.currentText()
        if len(key) != 10 or any(ch not in '01' for ch in key):
            QMessageBox.warning(self, "输入错误", "请输入 10-bit 密钥（仅0/1）")
            return
        if len(data) != 8 or any(ch not in '01' for ch in data):
            QMessageBox.warning(self, "输入错误", "请输入 8-bit 明文或密文（仅0/1）")
            return

        if mode == "加密":
            c = self.sdes.encrypt(data, key)
            self.basic_result.setText(c)
            self.basic_log.setPlainText(self.sdes.get_log())
        else:
            p = self.sdes.decrypt(data, key)
            self.basic_result.setText(p)
            self.basic_log.setPlainText(self.sdes.get_log())

    def on_generate_random_key(self):
        import random
        rand_key = ''.join(random.choice('01') for _ in range(10))
        self.input_key.setText(rand_key)

    # ---------------------------
    # ASCII Tab（第3关）
    # ---------------------------
    def init_ascii_tab(self):
        layout = QGridLayout()
        self.tab_ascii.setLayout(layout)

        lbl_plain = QLabel("ASCII 明文:")
        self.ascii_plain_edit = QLineEdit()
        self.ascii_plain_edit.setPlaceholderText("例如：Hello!")

        lbl_key2 = QLabel("密钥 (10-bit):")
        self.ascii_key = QLineEdit()
        self.ascii_key.setPlaceholderText("例如：1010000010")

        btn_encrypt_ascii = QPushButton("加密（每字节 -> 8-bit 密文列）")
        btn_encrypt_ascii.clicked.connect(self.on_ascii_encrypt)

        self.ascii_cipher_display = QTextEdit()
        self.ascii_cipher_display.setReadOnly(True)

        btn_decrypt_ascii = QPushButton("解密（从 8-bit 列）")
        btn_decrypt_ascii.clicked.connect(self.on_ascii_decrypt)

        self.ascii_decrypted_display = QLineEdit()
        self.ascii_decrypted_display.setReadOnly(True)

        layout.addWidget(lbl_plain, 0, 0)
        layout.addWidget(self.ascii_plain_edit, 0, 1, 1, 3)
        layout.addWidget(lbl_key2, 1, 0)
        layout.addWidget(self.ascii_key, 1, 1)
        layout.addWidget(btn_encrypt_ascii, 1, 2)
        layout.addWidget(btn_decrypt_ascii, 1, 3)
        layout.addWidget(QLabel("密文 (每字节 8-bit 列，逗号分隔):"), 2, 0)
        layout.addWidget(self.ascii_cipher_display, 3, 0, 1, 4)
        layout.addWidget(QLabel("解密还原的 ASCII:"), 4, 0)
        layout.addWidget(self.ascii_decrypted_display, 4, 1, 1, 3)

    def on_ascii_encrypt(self):
        plaintext = self.ascii_plain_edit.text()
        key = self.ascii_key.text().strip()
        if len(key) != 10 or any(ch not in '01' for ch in key):
            QMessageBox.warning(self, "输入错误", "请输入 10-bit 密钥（仅0/1）")
            return
        blocks = self.sdes.encrypt_ascii_to_bitblocks(plaintext, key)
        self.ascii_cipher_display.setPlainText(", ".join(blocks))

    def on_ascii_decrypt(self):
        text = self.ascii_cipher_display.toPlainText().strip()
        key = self.ascii_key.text().strip()
        if not text:
            QMessageBox.warning(self, "输入错误", "请先在上方生成或粘贴 8-bit 列表")
            return
        # 支持多种分隔
        parts = [p.strip() for p in text.replace('\n', ',').split(',') if p.strip()]
        # 验证
        for p in parts:
            if len(p) != 8 or any(ch not in '01' for ch in p):
                QMessageBox.warning(self, "输入错误", f"发现非法 8-bit 块: {p}")
                return
        plaintext = self.sdes.decrypt_bitblocks_to_ascii(parts, key)
        self.ascii_decrypted_display.setText(plaintext)

    # ---------------------------
    # 暴力破解 Tab（第4关）
    # ---------------------------
    def init_bruteforce_tab(self):
        layout = QGridLayout()
        self.tab_bruteforce.setLayout(layout)

        # 输入若干明密文对（列表）
        lbl_pairs = QLabel("已知明密文对 (每行一个，格式: 8-bit_plaintext,8-bit_ciphertext)：")
        self.pairs_text = QTextEdit()
        self.pairs_text.setPlaceholderText("例如：\n10110101,01100110\n01010101,11001010")

        lbl_workers = QLabel("并行线程数 (用于加速，后台任务仍在单独线程中):")
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 64)
        self.workers_spin.setValue(8)

        btn_start_bruteforce = QPushButton("开始暴力破解")
        btn_start_bruteforce.clicked.connect(self.on_start_bruteforce)
        btn_stop_bruteforce = QPushButton("停止暴力破解")
        btn_stop_bruteforce.clicked.connect(self.on_stop_bruteforce)
        self.btn_stop_bruteforce = btn_stop_bruteforce

        self.bruteforce_progress = QProgressBar()
        self.bruteforce_progress.setRange(0, 1024)
        self.bruteforce_progress.setValue(0)

        lbl_results = QLabel("候选密钥 (10-bit):")
        self.results_table = QTableWidget(0, 2)
        self.results_table.setHorizontalHeaderLabels(["候选密钥", "备注"])
        self.results_table.horizontalHeader().setStretchLastSection(True)

        btn_export_csv = QPushButton("导出候选密钥为 CSV")
        btn_export_csv.clicked.connect(self.on_export_bruteforce_csv)

        # Chart Canvas
        self.bruteforce_canvas = MplCanvas(self, width=4, height=3, dpi=100)

        layout.addWidget(lbl_pairs, 0, 0, 1, 4)
        layout.addWidget(self.pairs_text, 1, 0, 1, 4)
        layout.addWidget(lbl_workers, 2, 0)
        layout.addWidget(self.workers_spin, 2, 1)
        layout.addWidget(btn_start_bruteforce, 2, 2)
        layout.addWidget(btn_stop_bruteforce, 2, 3)
        layout.addWidget(self.bruteforce_progress, 3, 0, 1, 4)
        layout.addWidget(lbl_results, 4, 0)
        layout.addWidget(self.results_table, 5, 0, 1, 2)
        layout.addWidget(btn_export_csv, 5, 2)
        layout.addWidget(self.bruteforce_canvas, 5, 3)

        # state
        self.brute_thread = None
        self.current_matches: List[str] = []

    def on_start_bruteforce(self):
        raw = self.pairs_text.toPlainText().strip()
        if not raw:
            QMessageBox.warning(self, "输入错误", "请先输入至少一行已知明密文对")
            return
        pairs = []
        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        for idx, line in enumerate(lines):
            if ',' not in line:
                QMessageBox.warning(self, "格式错误", f"第 {idx + 1} 行格式不正确，应为 'plaintext, ciphertext'")
                return
            p, c = [part.strip() for part in line.split(',', 1)]
            if len(p) != 8 or len(c) != 8 or any(ch not in '01' for ch in p + c):
                QMessageBox.warning(self, "格式错误", f"第 {idx + 1} 行包含非法 8-bit：{line}")
                return
            pairs.append((p, c))

        # 如果已经有运行中的线程，先停止
        if self.brute_thread and self.brute_thread.isRunning():
            QMessageBox.information(self, "正在运行", "已有暴力破解任务在运行，请先停止或等待其完成")
            return

        workers = self.workers_spin.value()
        self.brute_thread = BruteForceThread(self.sdes, pairs, use_threads=True, max_workers=workers)
        self.brute_thread.progress_update.connect(self.on_bruteforce_progress)
        self.brute_thread.finished_signal.connect(self.on_bruteforce_finished)
        self.bruteforce_progress.setValue(0)
        self.results_table.setRowCount(0)
        self.current_matches = []
        self.bruteforce_canvas.axes.clear()
        self.bruteforce_canvas.draw()
        self.brute_thread.start()

    def on_stop_bruteforce(self):
        if self.brute_thread and self.brute_thread.isRunning():
            self.brute_thread.interrupt()
            QMessageBox.information(self, "已请求停止", "将尽快停止暴力破解任务（线程在下一个检查点停止）")
        else:
            QMessageBox.information(self, "无任务", "当前没有运行中的暴力破解任务")

    def on_bruteforce_progress(self, done_count: int):
        self.bruteforce_progress.setValue(done_count)

    def on_bruteforce_finished(self, matches: List[str], elapsed: float):
        self.current_matches = matches
        # 更新表格
        self.results_table.setRowCount(len(matches))
        for i, k in enumerate(matches):
            self.results_table.setItem(i, 0, QTableWidgetItem(k))
            self.results_table.setItem(i, 1, QTableWidgetItem("候选"))
        # 更新进度条为完成
        self.bruteforce_progress.setValue(1024)
        QMessageBox.information(self, "暴力破解完成", f"完成。耗时 {elapsed:.4f} 秒。候选密钥数: {len(matches)}")
        # 绘制简单柱状图（候选密钥数量）
        self.bruteforce_canvas.axes.clear()
        self.bruteforce_canvas.axes.bar(['candidates'], [len(matches)])
        self.bruteforce_canvas.axes.set_ylabel('候选密钥数')
        self.bruteforce_canvas.draw()

    def on_export_bruteforce_csv(self):
        if not self.current_matches:
            QMessageBox.warning(self, "无数据", "当前没有候选密钥可导出")
            return
        path, _ = QFileDialog.getSaveFileName(self, "保存候选密钥 CSV", "bruteforce_candidates.csv", "CSV Files (*.csv)")
        if not path:
            return
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['candidate_key_10bit', 'note'])
            for k in self.current_matches:
                writer.writerow([k, 'candidate'])
        QMessageBox.information(self, "导出完成", f"已导出到 {path}")

    # ---------------------------
    # 碰撞分析 Tab（第5关）
    # ---------------------------
    def init_collision_tab(self):
        layout = QGridLayout()
        self.tab_collision.setLayout(layout)

        lbl_plain = QLabel("分析明文 (8-bit):")
        self.collision_plain = QLineEdit()
        self.collision_plain.setPlaceholderText("例如：10110101")

        btn_start_collision = QPushButton("开始碰撞分析")
        btn_start_collision.clicked.connect(self.on_start_collision)
        btn_stop_collision = QPushButton("停止分析")
        btn_stop_collision.clicked.connect(self.on_stop_collision)
        self.btn_stop_collision = btn_stop_collision

        self.collision_progress = QProgressBar()
        self.collision_progress.setRange(0, 1024)
        self.collision_progress.setValue(0)

        lbl_results = QLabel("碰撞结果（密文 -> 数量 / 示例密钥）")
        self.collision_text = QTextEdit()
        self.collision_text.setReadOnly(True)

        btn_export_collision_csv = QPushButton("导出碰撞结果为 CSV")
        btn_export_collision_csv.clicked.connect(self.on_export_collision_csv)

        # Chart canvas
        self.collision_canvas = MplCanvas(self, width=5, height=3, dpi=100)

        layout.addWidget(lbl_plain, 0, 0)
        layout.addWidget(self.collision_plain, 0, 1)
        layout.addWidget(btn_start_collision, 0, 2)
        layout.addWidget(btn_stop_collision, 0, 3)
        layout.addWidget(self.collision_progress, 1, 0, 1, 4)
        layout.addWidget(lbl_results, 2, 0)
        layout.addWidget(self.collision_text, 3, 0, 1, 4)
        layout.addWidget(btn_export_collision_csv, 4, 0)
        layout.addWidget(self.collision_canvas, 3, 4, 2, 2)

        self.collision_thread = None
        self.current_collisions: Dict[str, List[str]] = {}

    def on_start_collision(self):
        p = self.collision_plain.text().strip()
        if len(p) != 8 or any(ch not in '01' for ch in p):
            QMessageBox.warning(self, "输入错误", "请输入 8-bit 明文（仅0/1）")
            return

        if self.collision_thread and self.collision_thread.isRunning():
            QMessageBox.information(self, "正在运行", "已有碰撞分析任务在运行，请先停止或等待其完成")
            return

        self.collision_thread = CollisionThread(self.sdes, p)
        self.collision_thread.progress_update.connect(self.on_collision_progress)
        self.collision_thread.finished_signal.connect(self.on_collision_finished)
        self.collision_progress.setValue(0)
        self.collision_text.clear()
        self.current_collisions = {}
        self.collision_canvas.axes.clear()
        self.collision_canvas.draw()
        self.collision_thread.start()

    def on_stop_collision(self):
        if self.collision_thread and self.collision_thread.isRunning():
            self.collision_thread.interrupt()
            QMessageBox.information(self, "已请求停止", "将尽快停止碰撞分析任务")
        else:
            QMessageBox.information(self, "无任务", "当前没有运行中的碰撞分析任务")

    def on_collision_progress(self, done_count: int):
        self.collision_progress.setValue(done_count)

    def on_collision_finished(self, collisions: Dict[str, List[str]], elapsed: float):
        self.current_collisions = collisions
        lines = []
        for c, keys in collisions.items():
            lines.append(f"{c} -> {len(keys)} keys; 示例 keys: {keys[:5]}")
        if not lines:
            lines = ["未发现碰撞（即每个密文仅由单一密钥产生）"]
        self.collision_text.setPlainText("\n".join(lines))
        self.collision_progress.setValue(1024)
        QMessageBox.information(self, "分析完成", f"碰撞分析完成，耗时 {elapsed:.4f} 秒。碰撞数量: {len(collisions)}")

        # 绘制直方图：x轴为碰撞大小（键数），y轴为该碰撞大小出现次数
        sizes = [len(keys) for keys in collisions.values()]
        if sizes:
            hist = {}
            for s in sizes:
                hist[s] = hist.get(s, 0) + 1
            xs = sorted(hist.keys())
            ys = [hist[x] for x in xs]
            self.collision_canvas.axes.clear()
            self.collision_canvas.axes.bar([str(x) for x in xs], ys)
            self.collision_canvas.axes.set_xlabel("碰撞键数")
            self.collision_canvas.axes.set_ylabel("发生次数")
            self.collision_canvas.draw()

    def on_export_collision_csv(self):
        if not self.current_collisions:
            QMessageBox.warning(self, "无数据", "当前没有碰撞结果可导出")
            return
        path, _ = QFileDialog.getSaveFileName(self, "保存碰撞结果 CSV", "collision_results.csv", "CSV Files (*.csv)")
        if not path:
            return
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['ciphertext_8bit', 'num_keys', 'example_keys'])
            for c, keys in self.current_collisions.items():
                writer.writerow([c, len(keys), ";".join(keys[:10])])
        QMessageBox.information(self, "导出完成", f"已导出到 {path}")


# ---------------------------
# 如果作为独立运行则启动 app（保留以便调试）
# ---------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    font = QFont("SimHei")
    app.setFont(font)
    win = SDESGUI()
    win.show()
    sys.exit(app.exec_())








# import random
# from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout,
#                              QHBoxLayout, QLabel, QLineEdit, QPushButton,
#                              QTextEdit, QGroupBox, QMessageBox)
# from PyQt5.QtCore import Qt
# from PyQt5.QtGui import QFont, QIcon
# import T1_SDES as SDES


# class SDESGUI(QMainWindow):
#     def __init__(self):
#         super().__init__()
#         self.sdes = SDES.SDES()
#         self.is_encrypt_mode = True

#         # 设置窗口
#         self.setWindowTitle("S-DES加密解密工具")
#         self.setMinimumSize(1200, 900)

#         # 设置样式
#         self.setStyleSheet("""
#             QMainWindow {
#                 background-color: #f0f4f8;
#             }
#             QLabel#titleLabel {
#                 font-size: 24px;
#                 font-weight: bold;
#                 color: #3B82F6;
#                 margin: 10px 0px;
#             }
#             QLabel#subtitleLabel {
#                 font-size: 30px;
#                 color: #64748b;
#                 margin-bottom: 20px;
#             }
#             QLabel {
#                 font-size: 30px;
#                 color: #334155;
#             }
#             QLineEdit {
#                 padding: 8px;
#                 border: 1px solid #cbd5e1;
#                 border-radius: 6px;
#                 font-size: 30px;
#             }
#             QLineEdit:focus {
#                 border-color: #3B82F6;
#                 background-color: #f8fafc;
#             }
#             QPushButton {
#                 background-color: #3B82F6;
#                 color: white;
#                 padding: 8px 16px;
#                 border-radius: 6px;
#                 font-size: 30px;
#                 border: none;
#             }
#             QPushButton:hover {
#                 background-color: #2563eb;
#             }
#             QPushButton:pressed {
#                 background-color: #1d4ed8;
#             }
#             QPushButton#decryptBtn {
#                 background-color: #10B981;
#             }
#             QPushButton#decryptBtn:hover {
#                 background-color: #059669;
#             }
#             QPushButton#decryptBtn:pressed {
#                 background-color: #065f46;
#             }
#             QPushButton#randomBtn {
#                 background-color: #e2e8f0;
#                 color: #334155;
#                 padding: 8px;
#             }
#             QPushButton#randomBtn:hover {
#                 background-color: #cbd5e1;
#             }
#             QGroupBox {
#                 border: 1px solid #e2e8f0;
#                 border-radius: 8px;
#                 margin-top: 10px;
#                 padding: 15px;
#                 background-color: white;
#             }
#             QGroupBox::title {
#                 subcontrol-origin: margin;
#                 left: 10px;
#                 top: 0px;
#                 color: #334155;
#                 font-weight: bold;
#             }
#             QTextEdit {
#                 background-color: #1e293b;
#                 color: #e2e8f0;
#                 font-family: Consolas, Monaco, monospace;
#                 font-size: 30px;
#                 border-radius: 6px;
#                 padding: 8px;
#             }
#         """)

#         # 创建主部件和布局
#         central_widget = QWidget()
#         self.setCentralWidget(central_widget)
#         main_layout = QVBoxLayout(central_widget)
#         main_layout.setContentsMargins(20, 20, 20, 20)
#         main_layout.setSpacing(15)

#         # 添加标题
#         title_label = QLabel("S-DES加密解密工具")
#         title_label.setObjectName("titleLabel")
#         title_label.setAlignment(Qt.AlignCenter)
#         title_label.setStyleSheet("font-size: 50px; font-weight: bold;")
#         main_layout.addWidget(title_label)

#         subtitle_label = QLabel(
#             "简化数据加密标准(Simplified Data Encryption Standard)的实现，支持8位二进制明文/密文与10位二进制密钥的加解密操作")
#         subtitle_label.setObjectName("subtitleLabel")
#         subtitle_label.setAlignment(Qt.AlignCenter)
#         subtitle_label.setStyleSheet("font-size: 28px; font-weight: bold;")
#         subtitle_label.setWordWrap(True)
#         main_layout.addWidget(subtitle_label)

#         # 操作模式选择
#         mode_layout = QHBoxLayout()
#         mode_layout.setSpacing(10)

#         self.encrypt_btn = QPushButton("加密")
#         self.encrypt_btn.setStyleSheet("font-size: 32px; font-weight: bold;")
#         self.encrypt_btn.setIcon(QIcon.fromTheme("lock", QIcon()))
#         self.encrypt_btn.setCheckable(True)
#         self.encrypt_btn.setChecked(True)
#         self.encrypt_btn.clicked.connect(self.set_encrypt_mode)

#         self.decrypt_btn = QPushButton("解密")
#         self.decrypt_btn.setStyleSheet("font-size: 32px; font-weight: bold;")
#         self.decrypt_btn.setObjectName("decryptBtn")
#         self.decrypt_btn.setIcon(QIcon.fromTheme("unlock", QIcon()))
#         self.decrypt_btn.setCheckable(True)
#         self.decrypt_btn.clicked.connect(self.set_decrypt_mode)

#         mode_layout.addWidget(self.encrypt_btn)
#         mode_layout.addWidget(self.decrypt_btn)
#         mode_layout.setAlignment(Qt.AlignCenter)
#         main_layout.addLayout(mode_layout)

#         # 输入区域
#         input_group = QGroupBox("输入")
#         input_group.setStyleSheet("font-size: 30px")
#         input_layout = QVBoxLayout()
#         input_layout.setSpacing(15)

#         # 操作类型显示
#         self.mode_label = QLabel("操作类型: 加密")
#         input_layout.addWidget(self.mode_label)

#         # 数据输入
#         data_layout = QHBoxLayout()
#         self.data_label = QLabel("请输入8位二进制明文:")
#         self.data_input = QLineEdit()
#         self.data_input.setPlaceholderText("例如: 10110101")
#         self.random_data_btn = QPushButton("随机")
#         self.random_data_btn.setObjectName("randomBtn")
#         self.random_data_btn.clicked.connect(self.generate_random_data)

#         data_layout.addWidget(self.data_label, 1)
#         data_layout.addWidget(self.data_input, 3)
#         data_layout.addWidget(self.random_data_btn, 0)
#         input_layout.addLayout(data_layout)

#         # 密钥输入
#         key_layout = QHBoxLayout()
#         key_label = QLabel("请输入10位二进制密钥:")
#         self.key_input = QLineEdit()
#         self.key_input.setPlaceholderText("例如: 1010000010")
#         self.random_key_btn = QPushButton("随机")
#         self.random_key_btn.setObjectName("randomBtn")
#         self.random_key_btn.clicked.connect(self.generate_random_key)

#         key_layout.addWidget(key_label, 1)
#         key_layout.addWidget(self.key_input, 3)
#         key_layout.addWidget(self.random_key_btn, 0)
#         input_layout.addLayout(key_layout)

#         # 执行按钮
#         self.process_btn = QPushButton("执行加密")
#         self.process_btn.setIcon(QIcon.fromTheme("system-run", QIcon()))
#         self.process_btn.clicked.connect(self.process)
#         input_layout.addWidget(self.process_btn)

#         input_group.setLayout(input_layout)
#         main_layout.addWidget(input_group)

#         # 结果区域
#         self.result_group = QGroupBox("结果")
#         self.result_group.setVisible(False)
#         result_layout = QVBoxLayout()

#         self.result_text_label = QLabel("密文:")
#         self.result_value = QLabel("")
#         self.result_value.setFont(QFont("Consolas", 30))
#         self.result_value.setStyleSheet("color: #3B82F6; font-weight: bold;")

#         result_layout.addWidget(self.result_text_label)
#         result_layout.addWidget(self.result_value)
#         self.result_group.setLayout(result_layout)
#         main_layout.addWidget(self.result_group)

#         # 详细过程区域
#         details_layout = QVBoxLayout()

#         self.toggle_details_btn = QPushButton("显示详细过程")
#         self.toggle_details_btn.setObjectName("toggleBtn")
#         self.toggle_details_btn.clicked.connect(self.toggle_details)
#         details_layout.addWidget(self.toggle_details_btn)

#         self.details_text = QTextEdit()
#         self.details_text.setReadOnly(True)
#         self.details_text.setVisible(False)
#         details_layout.addWidget(self.details_text)

#         main_layout.addLayout(details_layout)

#         # 填充空间
#         main_layout.addStretch()

#     def set_encrypt_mode(self):
#         """设置为加密模式"""
#         self.is_encrypt_mode = True
#         self.encrypt_btn.setChecked(True)
#         self.decrypt_btn.setChecked(False)
#         self.mode_label.setText("操作类型: 加密")
#         self.data_label.setText("请输入8位二进制明文:")
#         self.process_btn.setText("执行加密")
#         self.result_text_label.setText("密文:")
#         self.result_group.setVisible(False)
#         self.reset_input_styles()

#     def set_decrypt_mode(self):
#         """设置为解密模式"""
#         self.is_encrypt_mode = False
#         self.encrypt_btn.setChecked(False)
#         self.decrypt_btn.setChecked(True)
#         self.mode_label.setText("操作类型: 解密")
#         self.data_label.setText("请输入8位二进制密文:")
#         self.process_btn.setText("执行解密")
#         self.result_text_label.setText("明文:")
#         self.result_group.setVisible(False)
#         self.reset_input_styles()

#     def generate_random_data(self):
#         """生成随机8位二进制数据"""
#         data = ''.join(str(random.randint(0, 1)) for _ in range(8))
#         self.data_input.setText(data)

#     def generate_random_key(self):
#         """生成随机10位二进制密钥"""
#         key = ''.join(str(random.randint(0, 1)) for _ in range(10))
#         self.key_input.setText(key)

#     def reset_input_styles(self):
#         """重置输入框样式"""
#         self.data_input.setStyleSheet("""
#             padding: 8px;
#             border: 1px solid #cbd5e1;
#             border-radius: 6px;
#             font-size: 30px;
#         """)
#         self.key_input.setStyleSheet("""
#             padding: 8px;
#             border: 1px solid #cbd5e1;
#             border-radius: 6px;
#             font-size: 30px;
#         """)

#     def highlight_invalid_input(self, widget):
#         """高亮显示无效输入"""
#         widget.setStyleSheet("""
#             padding: 8px;
#             border: 1px solid #ef4444;
#             border-radius: 6px;
#             font-size: 30px;
#             background-color: #fee2e2;
#         """)

#     def toggle_details(self):
#         """显示或隐藏详细过程"""
#         self.details_text.setVisible(not self.details_text.isVisible())
#         if self.details_text.isVisible():
#             self.toggle_details_btn.setText("隐藏详细过程")
#         else:
#             self.toggle_details_btn.setText("显示详细过程")

#     def process(self):
#         """处理加密或解密"""
#         self.reset_input_styles()
#         data = self.data_input.text().strip()
#         key = self.key_input.text().strip()

#         # 验证输入
#         if not data or not all(c in '01' for c in data) or len(data) != 8:
#             self.highlight_invalid_input(self.data_input)
#             QMessageBox.warning(self, "输入错误", "请输入8位二进制数字(仅0和1)")
#             return

#         if not key or not all(c in '01' for c in key) or len(key) != 10:
#             self.highlight_invalid_input(self.key_input)
#             QMessageBox.warning(self, "输入错误", "请输入10位二进制数字(仅0和1)")
#             return

#         # 执行加密或解密
#         try:
#             if self.is_encrypt_mode:
#                 result = self.sdes.encrypt(data, key)
#             else:
#                 result = self.sdes.decrypt(data, key)

#             # 显示结果
#             self.result_value.setText(result)
#             self.result_group.setVisible(True)

#             # 显示详细过程
#             self.details_text.setText(self.sdes.get_log())
#         except Exception as e:
#             QMessageBox.critical(self, "错误", f"处理过程中发生错误: {str(e)}")

