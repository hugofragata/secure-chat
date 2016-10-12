import sys
from PyQt4 import QtCore, QtGui

import t
try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s


class AppChat(QtGui.QMainWindow, t.Ui_MainWindow):
    def __init__(self, parent=None):
        super(AppChat, self).__init__(parent)
        self.setupUi(self)
        self.sendButton.clicked.connect(self.sendMsg)
        self.msgBox.installEventFilter(self)

    def sendMsg(self):
        text = self.msgBox.toPlainText()
        self.textBrowser.append(text)

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.KeyPress and obj == self.msgBox:
            if event.key() == QtCore.Qt.Key_Return:
                self.sendMsg()
                self.msgBox.clear()
                return True
        return QtGui.QMainWindow.eventFilter(self, obj, event)


def main():
    app = QtGui.QApplication(sys.argv)
    form = AppChat()
    form.show()
    app.exec_()


if __name__ == '__main__':
    main()
