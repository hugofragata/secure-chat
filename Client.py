import sys
from loginDialog import *
from ConnectionManager import ConnectionManager, ConnectionManagerError
import t
try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s


class AppChat(QtGui.QMainWindow, t.Ui_MainWindow):
    def __init__(self, parent=None):
        super(AppChat, self).__init__(parent)
        self.comm = None
        self.setupUi(self)
        self.login_dialog = QtGui.QDialog()
        self.diag_ui = Ui_Dialog()
        self.diag_ui.setupUi(self.login_dialog)
        self.diag_ui.pushButton.clicked.connect(self.login)
        self.sendButton.clicked.connect(self.sendMsg)
        self.msgBox.installEventFilter(self)
        teste = self.login_dialog.exec_()
        if teste == 0:
            quit()
        #self.sock = socket.create_connection(("localhost", 8080))

    def login(self):
        address = str(self.diag_ui.address.text())
        port = str(self.diag_ui.port.text())
        username = str(self.diag_ui.userName.text())
        if address and port and username:
            if not ConnectionManager.is_ip_address(address):
                return
            if not self.valid_port(port):
                return
            try:
                self.comm = ConnectionManager(address, port)
            except ConnectionManagerError:
                return
            else:
                return self.login_dialog.accept()
        else:
            #lineEdits vazios
            return

    def sendMsg(self):
        text = self.msgBox.toPlainText()
        if not text or text=="\n":
            return
        self.textBrowser.append(text)
        self.comm.send_message(text)
        self.msgBox.clear()

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

    @staticmethod
    def valid_port(s):
        try:
            p = int(s)
            if 0 < p <= 65535:
                return True
            else:
                return False
        except ValueError:
            return False


def main():
    app = QtGui.QApplication(sys.argv)
    form = AppChat()
    form.show()
    app.exec_()


if __name__ == '__main__':
    main()
