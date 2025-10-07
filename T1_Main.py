import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFont
import T1_GUI as gui

if __name__ == "__main__":
    app = QApplication(sys.argv)

    # 确保中文显示正常（系统须安装 SimHei）
    font = QFont("SimHei")
    app.setFont(font)

    window = gui.SDESGUI()
    window.show()
    sys.exit(app.exec_())






# import sys
# from PyQt5.QtWidgets import QApplication
# from PyQt5.QtGui import QFont
# import T1_GUI as gui


# if __name__ == "__main__":
#     app = QApplication(sys.argv)

#     # 确保中文显示正常
#     font = QFont("SimHei")
#     app.setFont(font)

#     window = gui.SDESGUI()
#     window.show()
#     sys.exit(app.exec_())
