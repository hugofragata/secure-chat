import sys
from loginDialog import *
import socket
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
        self.login_dialog = QtGui.QDialog()
        diag_ui = Ui_Dialog()
        diag_ui.setupUi(self.login_dialog)
        self.sendButton.clicked.connect(self.sendMsg)
        self.msgBox.installEventFilter(self)
        self.login_dialog.exec_()
        self.sock = socket.create_connection(("localhost",8080))


    def sendMsg(self):
        text = self.msgBox.toPlainText()
        self.textBrowser.append(text)
        self.msgBox.clear()
        self.sock.send(text+"\n\n")
        #callback()texto

    def updateChat(self, text):
        self.textBrowser.append(text)
        #TODO: append das verificacoes
        pass

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.KeyPress and obj == self.msgBox:
            if event.key() == QtCore.Qt.Key_Return:
                self.sendMsg()
                return True
        return QtGui.QMainWindow.eventFilter(self, obj, event)


def main():
    app = QtGui.QApplication(sys.argv)
    form = AppChat()
    form.show()
    app.exec_()


if __name__ == '__main__':
    main()
