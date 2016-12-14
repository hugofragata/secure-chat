# encoding: utf-8
import sys
from loginDialog import *
from ConnectionManager import ConnectionManager, ConnectionManagerError
from CustomListItem import UserListItem
import t
from User import SuperUser
try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s


class AppChat(QtGui.QMainWindow, t.Ui_MainWindow):
    def __init__(self, parent=None, ccutils=None):
        super(AppChat, self).__init__(parent)
        self.ccutils = ccutils
        self.comm = None
        self.setupUi(self)
        self.login_dialog = QtGui.QDialog()
        self.diag_ui = Ui_Dialog()
        self.diag_ui.setupUi(self.login_dialog)
        self.diag_ui.pushButton.clicked.connect(self.login)
        self.diag_ui.cartaoAuth.clicked.connect(self.ccChoose)
        self.sendButton.clicked.connect(self.sendMsg)
        self.listWidget.itemDoubleClicked.connect(self.connect_to_user)
        self.msgBox.installEventFilter(self)
        self.actionRSA_WITH_AES_128.triggered.connect(self.change_client_clientRSA)
        self.actionECDHE_WITH_AES_128.triggered.connect(self.change_client_clientDH)

        self.cipher_suite = None
        if ccutils is None:
            self.diag_ui.cartaoAuth.setDisabled(True)

        accept = self.login_dialog.exec_()
        if accept == 0:
            quit()
        if not self.comm.s_connect(cipher_suite=self.cipher_suite):
            self.show_error("ERRO a ligar ao servidor")
            quit()
        self.comm.get_user_lists()

    def login(self):
        QtGui.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
        address = str(self.diag_ui.address.text())
        port = str(self.diag_ui.port.text())
        username = str(self.diag_ui.userName.text())
        if not self.diag_ui.cartaoAuth.isChecked() and not username:
            QtGui.QApplication.restoreOverrideCursor()
            return
        if not address or not port:
            QtGui.QApplication.restoreOverrideCursor()
            return
        if not ConnectionManager.is_ip_address(address) or not self.valid_port(port):
            QtGui.QApplication.restoreOverrideCursor()
            return
        if self.diag_ui.cartaoAuth.isChecked():
            user = SuperUser(ccutils=self.ccutils)
        else:
            user = SuperUser(username)
        try:
            self.comm = ConnectionManager(address, port, self, user)
        except ConnectionManagerError:
            QtGui.QApplication.restoreOverrideCursor()
            self.show_error("Connection ERROR")
            return
        else:
            self.connect(self.comm, self.comm.signal, self.updateChat)
            self.connect(self.comm, self.comm.list_signal, self.list_users)
            self.connect(self.comm, self.comm.error_signal, self.show_error)
            self.connect(self.comm, self.comm.change_list, self.change_listitem)
            self.connect(self.comm, self.comm.append_msg_id, self.append_id)
            if self.diag_ui.radioButton.isChecked():
                self.cipher_suite = 1
            else:
                self.cipher_suite = 2
            QtGui.QApplication.restoreOverrideCursor()
            return self.login_dialog.accept()

    def change_client_clientRSA(self):
        if self.actionECDHE_WITH_AES_128.isChecked():
            self.actionECDHE_WITH_AES_128.toggle()

    def change_client_clientDH(self):
        if self.actionRSA_WITH_AES_128.isChecked():
            self.actionRSA_WITH_AES_128.toggle()

    def sendMsg(self):
        text = self.msgBox.toPlainText()
        if not text or text == "\n":
            return
        self.textBrowser.append("(eu)> " + text)
        self.comm.send_client_comm(str(text))
        self.msgBox.clear()

    def list_users(self, user_list):
        self.listWidget.clear()
        for user in user_list:
            if user['id'] == self.comm.user.id:
                continue
            item = UserListItem(user['name'], user['id'])
            self.listWidget.addItem(item)

    def ccChoose(self):
        if self.diag_ui.cartaoAuth.isChecked():
            self.diag_ui.userName.setDisabled(True)
        else:
            self.diag_ui.userName.setDisabled(False)

    def append_id(self, id, recieved):
        if recieved:
            self.textBrowser.append("<span><p style=\"font-size:6pt; color:green;\">> " + QtCore.QString.fromLatin1(id, len(id)) + "</p></span>")
        else:
            self.textBrowser.append(
                "<span ><p style=\"font-size:6pt; color:red;\">> " + QtCore.QString.fromLatin1(id, len(id)) + "</p></span>")
        return

    def change_listitem(self, uid):
        for i in xrange(self.listWidget.count()):
            item = self.listWidget.item(i)
            if item.user_id == uid:
                if item.num == 0:
                    new_text = item.user_name + " (new messages)"
                    item.setText(new_text)
                    item.num += 1
                else:
                    new_text = item.user_name + " (" + str(item.num) + ")"
                    item.setText(new_text)
                    item.num += 1
                item.setTextColor(QtGui.QColor(_fromUtf8("red")))

    def connect_to_user(self, item):
        self.textBrowser.clear()
        self.textBrowser.setPlainText("Connecting to " + item.user_name)
        if self.actionRSA_WITH_AES_128.isChecked():
            self.comm.start_client_connect(item.user_id, cipher_suite=1)
        elif self.actionECDHE_WITH_AES_128.isChecked():
            self.comm.start_client_connect(item.user_id, cipher_suite=2)
        else:
            self.comm.start_client_connect(item.user_id, cipher_suite=1)
        item.setText(item.user_name)
        item.num = 0
        item.setTextColor(QtGui.QColor(_fromUtf8("black")))
        self.setWindowTitle("I am " + self.comm.user.name + ", talking to " + item.user_name)

    def updateChat(self, text):
        self.textBrowser.append("<span>" + self.comm.peers[self.comm.peer_connected].name + "> " + QtCore.QString.fromLatin1(text, len(text)) + "</span>")

    def show_error(self, error):
        errorDiag = QtGui.QMessageBox()
        errorDiag.setIcon(QtGui.QMessageBox.Critical)
        errorDiag.setText(error)
        errorDiag.setWindowTitle("Error")
        errorDiag.setStandardButtons(QtGui.QMessageBox.Ok)
        errorDiag.exec_()

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


def main(ccUtils=None):
    app = QtGui.QApplication(sys.argv)
    form = AppChat(ccutils=ccUtils)
    form.show()
    app.exec_()


if __name__ == '__main__':
    main()
