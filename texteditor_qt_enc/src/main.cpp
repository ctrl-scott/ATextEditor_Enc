// src/main.cpp
// Qt6 editor with standard About dialog, async libsodium encryption, atomic saves,
// password dialog with strength meter, read-only toggle, drag-and-drop, and Help dialog.
//
// No contractions are used in comments or strings.

#include <QApplication>
#include <QMainWindow>
#include <QTextEdit>
#include <QToolBar>
#include <QMenuBar>
#include <QStatusBar>
#include <QFileDialog>
#include <QAction>
#include <QFile>
#include <QTextStream>
#include <QMessageBox>
#include <QLabel>
#include <QWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QDateTime>
#include <QEvent>
#include <QMouseEvent>
#include <QKeyEvent>
#include <QInputDialog>
#include <QByteArray>
#include <QProgressDialog>
#include <QPointer>
#include <thread>
#include <QSaveFile>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QtEndian>

#include <algorithm>   // std::max
#include <cstring>     // std::memcmp

#include <sodium.h>    // libsodium


#include <QSettings>
#include <QDialog>
#include <QVBoxLayout>
#include <QLabel>
#include <QCheckBox>
#include <QDialogButtonBox>

static bool ensureExportAffirmationAccepted(QWidget *parent = nullptr) {
    QSettings s("scottinalabama", "A Text Editor");
    if (s.value("export/affirmed", false).toBool()) return true;

    QDialog dlg(parent);
    dlg.setWindowTitle("Export Affirmation");
    dlg.setModal(true);
    dlg.resize(520, 260);

    auto *v = new QVBoxLayout(&dlg);
    auto *text = new QLabel(
        "Please affirm the following before using this application:\n\n"
        "• I am an American.\n"
        "• I will not export, re-export, or transfer this application to any country, person, or entity prohibited under United States law.");
    text->setWordWrap(true);
    v->addWidget(text);

    auto *cb = new QCheckBox("I affirm that I am an American and that I will not export this application.");
    v->addWidget(cb);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    buttons->button(QDialogButtonBox::Ok)->setEnabled(false);
    v->addWidget(buttons);

    QObject::connect(cb, &QCheckBox::toggled, buttons->button(QDialogButtonBox::Ok), &QWidget::setEnabled);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() == QDialog::Accepted) {
        s.setValue("export/affirmed", true);
        return true;
    }
    return false;
}


// Forward declaration implemented in src/help.cpp
void showHelpDialog(QWidget *parent);

// -----------------------------
// Small helpers
// -----------------------------
static void wipeQByteArray(QByteArray &ba) {
    if (!ba.isEmpty()) {
        sodium_memzero(ba.data(), (size_t)ba.size());
        ba.clear();
    }
}
static void wipeQString(QString &s) {
    QByteArray tmp = s.toUtf8();
    sodium_memzero(tmp.data(), (size_t)tmp.size());
    s.fill(u'\0');
    s.clear();
}

// -----------------------------
// Password dialog (enter or create)
// -----------------------------
#include <QDialog>
#include <QLineEdit>
#include <QCheckBox>
#include <QProgressBar>

class PasswordDialog : public QDialog {
    Q_OBJECT
public:
    enum Mode { Enter, Create };

    explicit PasswordDialog(Mode mode, QWidget *parent = nullptr)
        : QDialog(parent), mode_(mode)
    {
        setWindowTitle(mode_ == Enter ? "Enter Password" : "Set Password");
        setModal(true);
        setMinimumWidth(380);

        auto *v = new QVBoxLayout(this);
        v->setContentsMargins(16, 14, 16, 14);
        v->setSpacing(10);

        pass1_ = new QLineEdit;
        pass1_->setEchoMode(QLineEdit::Password);
        pass1_->setPlaceholderText(mode_ == Enter ? "Password" : "New password");
        v->addWidget(pass1_);

        if (mode_ == Create) {
            pass2_ = new QLineEdit;
            pass2_->setEchoMode(QLineEdit::Password);
            pass2_->setPlaceholderText("Confirm password");
            v->addWidget(pass2_);
        }

        auto *row = new QHBoxLayout;
        showBox_ = new QCheckBox("Show");
        row->addWidget(showBox_);
        capsHint_ = new QLabel("");
        capsHint_->setStyleSheet("color:#a33; font-size:12px");
        row->addStretch(1);
        row->addWidget(capsHint_);
        v->addLayout(row);

        meter_ = new QProgressBar;
        meter_->setRange(0, 100);
        meter_->setValue(0);
        meter_->setTextVisible(true);
        v->addWidget(meter_);

        auto *btns = new QHBoxLayout;
        btns->addStretch(1);
        auto *ok = new QPushButton("OK");
        auto *cancel = new QPushButton("Cancel");
        btns->addWidget(ok);
        btns->addWidget(cancel);
        v->addLayout(btns);

        connect(showBox_, &QCheckBox::toggled, this, [=](bool on){
            const auto mode = on ? QLineEdit::Normal : QLineEdit::Password;
            pass1_->setEchoMode(mode);
            if (pass2_) pass2_->setEchoMode(mode);
        });
        connect(ok, &QPushButton::clicked, this, &PasswordDialog::onAccept);
        connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
        connect(pass1_, &QLineEdit::textChanged, this, &PasswordDialog::updateStrength);
        if (pass2_) connect(pass2_, &QLineEdit::textChanged, this, &PasswordDialog::updateStrength);

        // Heuristic Caps Lock hint
        pass1_->installEventFilter(this);
        if (pass2_) pass2_->installEventFilter(this);

        updateStrength();
    }

    QByteArray takePasswordUtf8() {
        QString p1 = pass1_->text();
        QByteArray out = p1.toUtf8();

        wipeQString(p1);
        pass1_->clear();

        if (pass2_) {
            QString p2 = pass2_->text();
            wipeQString(p2);
            pass2_->clear();
        }
        return out;
    }

protected:
    bool eventFilter(QObject *watched, QEvent *ev) override {
        if ((watched == pass1_ || watched == pass2_) && ev->type() == QEvent::KeyPress) {
            auto *ke = static_cast<QKeyEvent*>(ev);
            const QString t = ke->text();
            if (t.size() == 1) {
                const QChar c = t[0];
                const bool isAlpha = c.isLetter();
                const bool shift = ke->modifiers() & Qt::ShiftModifier;
                if (isAlpha) {
                    if (!shift && c.isUpper()) {
                        capsHint_->setText("Caps Lock may be on");
                    } else if (shift && c.isLower()) {
                        capsHint_->setText("Caps Lock may be on");
                    } else {
                        capsHint_->clear();
                    }
                }
            }
        }
        return QDialog::eventFilter(watched, ev);
    }

private slots:
    void onAccept() {
        if (mode_ == Create) {
            if (pass1_->text().isEmpty()) {
                QMessageBox::warning(this, "Password required", "Please enter a password.");
                return;
            }
            if (pass1_->text() != pass2_->text()) {
                QMessageBox::warning(this, "Mismatch", "Passwords do not match.");
                return;
            }
        }
        accept();
    }

    void updateStrength() {
        QString p = pass1_->text();
        int classes = 0;
        bool hasLower=false, hasUpper=false, hasDigit=false, hasOther=false;
        for (QChar c : p) {
            if (c.isLower()) hasLower = true;
            else if (c.isUpper()) hasUpper = true;
            else if (c.isDigit()) hasDigit = true;
            else hasOther = true;
        }
        classes += hasLower; classes += hasUpper; classes += hasDigit; classes += hasOther;
        int score = std::min(100, (int)p.size() * 6 + classes * 10);
        if (p.size() < 8) score = std::min(score, 30);
        meter_->setValue(score);
        meter_->setFormat(QString("Strength: %1").arg(score));
    }

private:
    Mode mode_;
    QLineEdit *pass1_ = nullptr;
    QLineEdit *pass2_ = nullptr;
    QCheckBox *showBox_ = nullptr;
    QProgressBar *meter_ = nullptr;
    QLabel *capsHint_ = nullptr;
};

// -----------------------------
// Main window with encryption
// -----------------------------
class EditorWindow : public QMainWindow {
    Q_OBJECT
public:
    EditorWindow() {
        setWindowTitle("A Text Editor");
        resize(900, 600);

        editor = new QTextEdit(this);
        editor->setAcceptRichText(false);
        editor->setLineWrapMode(QTextEdit::WidgetWidth);
        setCentralWidget(editor);

        auto *fileMenu = menuBar()->addMenu("&File");
        auto *editMenu = menuBar()->addMenu("&Edit");
        auto *helpMenu = menuBar()->addMenu("&Help");

        auto *tb = addToolBar("Toolbar");
        tb->setMovable(false);

        actNew      = new QAction("New",  this);
        actOpen     = new QAction("Open", this);
        actSave     = new QAction("Save", this);
        actOpenEnc  = new QAction("Open Encrypted…", this);
        actSaveEnc  = new QAction("Save Encrypted As…", this);
        actReadOnly = new QAction("Read Only", this);
        actReadOnly->setCheckable(true);
        actHelp     = new QAction("Help Contents", this);
        actAbout    = new QAction("About Editor", this);

        fileMenu->addAction(actNew);
        fileMenu->addAction(actOpen);
        fileMenu->addAction(actSave);
        fileMenu->addSeparator();
        fileMenu->addAction(actOpenEnc);
        fileMenu->addAction(actSaveEnc);

        editMenu->addAction(actReadOnly);

        helpMenu->addAction(actHelp);
        helpMenu->addSeparator();
        helpMenu->addAction(actAbout);

        tb->addAction(actNew);
        tb->addAction(actOpen);
        tb->addAction(actSave);
        tb->addSeparator();
        tb->addAction(actOpenEnc);
        tb->addAction(actSaveEnc);
        tb->addSeparator();
        tb->addAction(actReadOnly);
        tb->addSeparator();
        tb->addAction(actHelp);
        tb->addAction(actAbout);

        posLabel = new QLabel("Line 1, Column 1", this);
        statusBar()->addWidget(posLabel);

        connect(actNew,     &QAction::triggered, this, &EditorWindow::newFile);
        connect(actOpen,    &QAction::triggered, this, &EditorWindow::openFile);
        connect(actSave,    &QAction::triggered, this, &EditorWindow::saveFile);
        connect(actOpenEnc, &QAction::triggered, this, &EditorWindow::openFileEncrypted);
        connect(actSaveEnc, &QAction::triggered, this, &EditorWindow::saveFileEncrypted);
        connect(actReadOnly,&QAction::toggled,   this, &EditorWindow::toggleReadOnly);

        connect(actHelp,  &QAction::triggered, this, [this]{ showHelpDialog(this); });
        connect(actAbout, &QAction::triggered, this, &EditorWindow::showAboutDialog);

        connect(editor, &QTextEdit::cursorPositionChanged, this, &EditorWindow::updateCaretLabel);

        // Drag and drop
        setAcceptDrops(true);

        updateCaretLabel();
    }

protected:
    void dragEnterEvent(QDragEnterEvent *e) override {
        if (e->mimeData()->hasUrls()) e->acceptProposedAction();
    }
    void dropEvent(QDropEvent *e) override {
        if (!e->mimeData()->hasUrls()) return;
        const auto urls = e->mimeData()->urls();
        if (urls.isEmpty()) return;
        const QString path = urls.first().toLocalFile();
        if (path.isEmpty()) return;

        if (looksEncrypted(path)) {
            decryptPathAsync(path);
        } else {
            openPlainPath(path);
        }
    }

private slots:
    void newFile() {
        editor->clear();
        currentPath.clear();
        statusBar()->showMessage("New file", 1500);
        updateCaretLabel();
    }

    void openFile() {
        const QString path = QFileDialog::getOpenFileName(this, "Open",
                                                          QString(),
                                                          "Text files (*.txt);;All files (*.*)");
        if (path.isEmpty()) return;
        openPlainPath(path);
    }

    void saveFile() {
        QString path = currentPath;
        if (path.isEmpty()) {
            path = QFileDialog::getSaveFileName(this, "Save As",
                                                QString(),
                                                "Text files (*.txt);;All files (*.*)");
            if (path.isEmpty()) return;
        }
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::critical(this, "Save failed", file.errorString());
            return;
        }
        QTextStream out(&file);
        out.setAutoDetectUnicode(true);
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
        out.setEncoding(QStringConverter::Utf8);
#endif
        out << editor->toPlainText();
        file.close();
        editor->document()->setModified(false);
        currentPath = path;
        statusBar()->showMessage("Saved: " + path, 2000);
    }

    void openFileEncrypted() {
        const QString path = QFileDialog::getOpenFileName(
            this, "Open Encrypted",
            QString(),
            "Encrypted files (*.qte *.enc);;All files (*.*)");
        if (path.isEmpty()) return;
        decryptPathAsync(path);
    }

    void saveFileEncrypted() {
        const QString path = QFileDialog::getSaveFileName(
            this, "Save Encrypted As",
            QString(),
            "Encrypted files (*.qte);;All files (*.*)");
        if (path.isEmpty()) return;

        PasswordDialog dlg(PasswordDialog::Create, this);
        if (dlg.exec() != QDialog::Accepted) return;
        QByteArray pw = dlg.takePasswordUtf8();

        const QByteArray plain = editor->toPlainText().toUtf8();

        // Busy modal (heap; auto-delete on close)
        QPointer<QProgressDialog> prog = new QProgressDialog("Encrypting...", QString(), 0, 0, this);
        prog->setWindowModality(Qt::ApplicationModal);
        prog->setCancelButton(nullptr);
        prog->setAttribute(Qt::WA_DeleteOnClose, true);
        prog->show();

        QString pathCopy = path;
        QByteArray pwCopy = pw;
        QByteArray plainCopy = plain;

        std::thread([this, pathCopy, pwCopy, plainCopy, prog]() mutable {
            sodium_mlock(pwCopy.data(), (size_t)pwCopy.size());
            bool ok = encryptToPath(pathCopy, pwCopy, plainCopy, opsLimit_, memLimit_);
            sodium_munlock(pwCopy.data(), (size_t)pwCopy.size());
            wipeQByteArray(pwCopy);
            sodium_memzero((void*)plainCopy.data(), (size_t)plainCopy.size());

            QMetaObject::invokeMethod(this, [this, ok, pathCopy, prog]() {
                if (prog) prog->close();
                if (!ok) QMessageBox::critical(this, "Encrypt failed", "Could not encrypt and save the file.");
                else {
                    statusBar()->showMessage("Encrypted and saved: " + pathCopy, 2500);
                    editor->document()->setModified(false);
                    currentPath = pathCopy;
                }
            });
        }).detach();

        // Wipe local buffers now
        sodium_memzero((void*)plain.data(), (size_t)plain.size());
        wipeQByteArray(pw);
    }

    void updateCaretLabel() {
        const auto c = editor->textCursor();
        const int line = c.blockNumber() + 1;
        const int col  = c.positionInBlock() + 1;
        posLabel->setText(QString("Line %1, Column %2").arg(line).arg(col));
    }

    void toggleReadOnly(bool on) {
        editor->setReadOnly(on);
        statusBar()->showMessage(on ? "Read-only mode enabled" : "Read-only mode disabled", 1500);
    }

    void showAboutDialog() {
        QMessageBox box(this);
        box.setWindowTitle("About Editor");
        box.setIcon(QMessageBox::Information);
        box.setTextFormat(Qt::RichText);

        const QString qtVer  = QString("Qt %1").arg(QT_VERSION_STR);
        const QString appVer = "Version 1.2.0";
        const QString build  = QString("Built: %1").arg(QDateTime::currentDateTime().toString(Qt::ISODate));
        const QString desc   =
            "A minimal, cross-platform text editor built with Qt Widgets.<br>"
            "Features: New/Open/Save, encrypted Open/Save, asynchronous I/O, and a Help section.";

        box.setText(QString("<b>Qt-Used, ChatGPT used, Education used: A Text Editor</b><br>%1<br>%2<br%3<br><br>%4")
                    .arg(appVer, qtVer, build, desc));

        QPushButton *helpBtn = box.addButton("Help…", QMessageBox::ActionRole);
        box.addButton(QMessageBox::Close);

        box.exec();
        if (box.clickedButton() == helpBtn) {
            showHelpDialog(this);
        }
    }

private:
    // ----- Encryption format -----
    // MAGIC(4) | VERSION(1) | SALT(16) | NONCE(24) | OPS(u32 LE) | MEM(u32 LE) | CIPHERTEXT
    static constexpr char MAGIC[4] = {'Q','T','E','1'};
    static constexpr unsigned char VERSION = 0x01;

    // Default KDF parameters (Argon2id via libsodium)
    const uint32_t opsLimit_ = crypto_pwhash_OPSLIMIT_MODERATE;
    const uint32_t memLimit_ = crypto_pwhash_MEMLIMIT_MODERATE;

    // I/O helpers
    void openPlainPath(const QString &path) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QMessageBox::critical(this, "Open failed", file.errorString());
            return;
        }
        QTextStream in(&file);
        in.setAutoDetectUnicode(true);
        editor->setPlainText(in.readAll());
        file.close();
        editor->document()->setModified(false);
        currentPath = path;
        statusBar()->showMessage("Opened: " + path, 2000);
        updateCaretLabel();
    }

    bool looksEncrypted(const QString &path) const {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) return false;
        char magic[4] = {};
        bool ok = f.read(magic, 4) == 4 && std::memcmp(magic, MAGIC, 4) == 0;
        f.close();
        if (ok) return true;
        return path.endsWith(".qte", Qt::CaseInsensitive) || path.endsWith(".enc", Qt::CaseInsensitive);
    }

    void decryptPathAsync(const QString &path) {
        PasswordDialog dlg(PasswordDialog::Enter, this);
        if (dlg.exec() != QDialog::Accepted) return;
        QByteArray pw = dlg.takePasswordUtf8();

        QPointer<QProgressDialog> prog = new QProgressDialog("Decrypting...", QString(), 0, 0, this);
        prog->setWindowModality(Qt::ApplicationModal);
        prog->setCancelButton(nullptr);
        prog->setAttribute(Qt::WA_DeleteOnClose, true);
        prog->show();

        QString pathCopy = path;
        QByteArray pwCopy = pw;

        std::thread([this, pathCopy, pwCopy, prog]() mutable {
            sodium_mlock(pwCopy.data(), (size_t)pwCopy.size());
            QByteArray plain;
            bool ok = decryptFromPath(pathCopy, pwCopy, plain);
            sodium_munlock(pwCopy.data(), (size_t)pwCopy.size());
            wipeQByteArray(pwCopy);

            QMetaObject::invokeMethod(this, [this, ok, pathCopy, plain, prog]() mutable {
                if (prog) prog->close();
                if (!ok || plain.isEmpty()) {
                    QMessageBox::critical(this, "Decrypt failed", "Could not decrypt file. Password may be incorrect or file is corrupted.");
                    return;
                }
                editor->setPlainText(QString::fromUtf8(plain));
                wipeQByteArray(const_cast<QByteArray&>(plain));
                editor->document()->setModified(false);
                currentPath.clear();
                statusBar()->showMessage("Decrypted and opened: " + pathCopy, 2500);
                updateCaretLabel();
            });
        }).detach();

        wipeQByteArray(pw);
    }

    // Encrypt to path using QSaveFile atomically, writing header and ciphertext.
    bool encryptToPath(const QString &path, const QByteArray &pwUtf8, const QByteArray &plaintext,
                       uint32_t opsLimit, uint32_t memLimit) const
    {
        unsigned char salt[crypto_pwhash_SALTBYTES];
        randombytes_buf(salt, sizeof salt);

        unsigned char key[crypto_secretbox_KEYBYTES];
        if (crypto_pwhash(key, sizeof key,
                          pwUtf8.constData(), (unsigned long long)pwUtf8.size(),
                          salt,
                          opsLimit, memLimit,
                          crypto_pwhash_ALG_DEFAULT) != 0) {
            sodium_memzero(key, sizeof key);
            return false;
        }

        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, sizeof nonce);

        QByteArray ciphertext;
        ciphertext.resize(crypto_secretbox_MACBYTES + plaintext.size());

        if (crypto_secretbox_easy(
                reinterpret_cast<unsigned char*>(ciphertext.data()),
                reinterpret_cast<const unsigned char*>(plaintext.constData()),
                (unsigned long long)plaintext.size(),
                nonce, key) != 0) {
            sodium_memzero(key, sizeof key);
            return false;
        }

        QSaveFile file(path);
        if (!file.open(QIODevice::WriteOnly)) {
            sodium_memzero(key, sizeof key);
            sodium_memzero(nonce, sizeof nonce);
            sodium_memzero((void*)ciphertext.data(), (size_t)ciphertext.size());
            return false;
        }

        quint32 opsLE = qToLittleEndian((quint32)opsLimit);
        quint32 memLE = qToLittleEndian((quint32)memLimit);

        bool ok = true;
        ok &= file.write(MAGIC, 4) == 4;
        ok &= file.write(reinterpret_cast<const char*>(&VERSION), 1) == 1;
        ok &= file.write(reinterpret_cast<const char*>(salt), sizeof salt) == (qint64)sizeof salt;
        ok &= file.write(reinterpret_cast<const char*>(nonce), sizeof nonce) == (qint64)sizeof nonce;
        ok &= file.write(reinterpret_cast<const char*>(&opsLE), sizeof opsLE) == (qint64)sizeof opsLE;
        ok &= file.write(reinterpret_cast<const char*>(&memLE), sizeof memLE) == (qint64)sizeof memLE;
        ok &= file.write(ciphertext) == ciphertext.size();

        if (ok) ok = file.commit();
        else file.cancelWriting();

        sodium_memzero(key, sizeof key);
        sodium_memzero(nonce, sizeof nonce);
        sodium_memzero((void*)ciphertext.data(), (size_t)ciphertext.size());

        return ok;
    }

    bool decryptFromPath(const QString &path, const QByteArray &pwUtf8, QByteArray &outPlain) const {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) return false;

        char magic[4];
        if (file.read(magic, 4) != 4 || std::memcmp(magic, MAGIC, 4) != 0) {
            file.close();
            return false;
        }
        unsigned char version = 0;
        if (file.read(reinterpret_cast<char*>(&version), 1) != 1 || version != VERSION) {
            file.close();
            return false;
        }
        unsigned char salt[crypto_pwhash_SALTBYTES];
        if (file.read(reinterpret_cast<char*>(salt), sizeof salt) != (qint64)sizeof salt) {
            file.close();
            return false;
        }
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        if (file.read(reinterpret_cast<char*>(nonce), sizeof nonce) != (qint64)sizeof nonce) {
            file.close();
            return false;
        }
        quint32 opsLE=0, memLE=0;
        if (file.read(reinterpret_cast<char*>(&opsLE), sizeof opsLE) != (qint64)sizeof opsLE) { file.close(); return false; }
        if (file.read(reinterpret_cast<char*>(&memLE), sizeof memLE) != (qint64)sizeof memLE) { file.close(); return false; }
        uint32_t opsLimit = qFromLittleEndian(opsLE);
        uint32_t memLimit = qFromLittleEndian(memLE);

        const qint64 cipherLen = file.size() - 4 - 1 - sizeof(salt) - sizeof(nonce) - sizeof(opsLE) - sizeof(memLE);
        if (cipherLen < crypto_secretbox_MACBYTES) { file.close(); return false; }
        QByteArray ciphertext = file.read(cipherLen);
        file.close();

        unsigned char key[crypto_secretbox_KEYBYTES];
        if (crypto_pwhash(key, sizeof key,
                          pwUtf8.constData(), (unsigned long long)pwUtf8.size(),
                          salt,
                          opsLimit, memLimit,
                          crypto_pwhash_ALG_DEFAULT) != 0) {
            sodium_memzero(key, sizeof key);
            sodium_memzero((void*)ciphertext.data(), (size_t)ciphertext.size());
            return false;
        }

        outPlain.resize(cipherLen - crypto_secretbox_MACBYTES);
        if (crypto_secretbox_open_easy(
                reinterpret_cast<unsigned char*>(outPlain.data()),
                reinterpret_cast<const unsigned char*>(ciphertext.constData()),
                (unsigned long long)ciphertext.size(),
                nonce, key) != 0) {
            sodium_memzero(key, sizeof key);
            sodium_memzero((void*)ciphertext.data(), (size_t)ciphertext.size());
            outPlain.clear();
            return false;
        }

        sodium_memzero(key, sizeof key);
        sodium_memzero((void*)ciphertext.data(), (size_t)ciphertext.size());
        return true;
    }

private:
    QTextEdit *editor = nullptr;
    QLabel *posLabel = nullptr;
    QAction *actNew = nullptr;
    QAction *actOpen = nullptr;
    QAction *actSave = nullptr;
    QAction *actOpenEnc = nullptr;
    QAction *actSaveEnc = nullptr;
    QAction *actReadOnly = nullptr;
    QAction *actHelp = nullptr;
    QAction *actAbout = nullptr;
    QString currentPath;
};

// -----------------------------
// main()
// -----------------------------
#include <QtGlobal>
#ifdef Q_CC_MSVC
#  pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#endif


int main(int argc, char *argv[]) {
    if (sodium_init() < 0) { fprintf(stderr, "libsodium initialization failed\n"); return 1; }
    QApplication app(argc, argv);

    if (!ensureExportAffirmationAccepted(nullptr)) {
        return 0;  // Exit if not affirmed
    }

    EditorWindow w;
    w.show();
    return app.exec();
}


// int main(int argc, char *argv[]) {
//     if (sodium_init() < 0) {
//         fprintf(stderr, "libsodium initialization failed\n");
//         return 1;
//     }
//     QApplication app(argc, argv);
//     EditorWindow w;
//     w.show();
//     return app.exec();
// }

// Keep this because Q_OBJECT classes are defined in this .cpp:
#include "main.moc"
