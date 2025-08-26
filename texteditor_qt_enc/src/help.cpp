// src/help.cpp
// Help dialog with tabs: Glossary, Qt Library, Libsodium Library, Sources (APA).
// No contractions are used in comments or strings.

#include <QDialog>
#include <QTabWidget>
#include <QTextBrowser>
#include <QDialogButtonBox>
#include <QVBoxLayout>
#include <QPointer>

static QString glossaryHtml() {
    return R"HTML(
<h2>Glossary</h2>
<dl>
  <dt>Action (QAction)</dt>
  <dd>An invokable command object used by menus and toolbars. Actions can be checked and can carry shortcuts.</dd>

  <dt>Atomic save (QSaveFile)</dt>
  <dd>Technique that writes to a temporary file and replaces the target on commit in order to avoid partial writes and data loss.</dd>

  <dt>Ciphertext</dt>
  <dd>Data produced by encryption. It is unintelligible without the correct key and algorithm.</dd>

  <dt>Dialog (QDialog)</dt>
  <dd>A top-level window used for short-lived tasks, often modal. Can host forms, messages, or help content.</dd>

  <dt>Drag and Drop</dt>
  <dd>Mechanism that allows moving or copying data via mouse gestures between widgets and applications using MIME data.</dd>

  <dt>Encryption (symmetric)</dt>
  <dd>Process of transforming plaintext into ciphertext using a shared secret key.</dd>

  <dt>Key derivation (crypto_pwhash)</dt>
  <dd>Deriving a high-entropy key from a low-entropy password using a memory-hard function with salt and tunable parameters.</dd>

  <dt>Memory-hard function</dt>
  <dd>A function that intentionally requires significant memory to compute in order to resist hardware attacks.</dd>

  <dt>Menu (QMenu)</dt>
  <dd>A pull-down list of actions. Typically attached to a QMenuBar.</dd>

  <dt>Meta-object system</dt>
  <dd>Runtime type information in Qt that supports signals and slots, properties, and dynamic invocation.</dd>

  <dt>Nonce</dt>
  <dd>A number-used-once. For XSalsa20-Poly1305 it must be unique per key to ensure security.</dd>

  <dt>Password hashing</dt>
  <dd>Transforming a password into a verifier or a key using a slow, memory-hard algorithm such as Argon2id.</dd>

  <dt>Plaintext</dt>
  <dd>The original readable data prior to encryption.</dd>

  <dt>Progress dialog (QProgressDialog)</dt>
  <dd>A modal dialog that communicates background progress. It should be owned on the heap when used with threads.</dd>

  <dt>QTextEdit</dt>
  <dd>Multiline text editor widget that can operate in plain text or rich text modes.</dd>

  <dt>QWidget</dt>
  <dd>Base class of all user-interface objects in Qt Widgets.</dd>

  <dt>Signals and Slots</dt>
  <dd>Type-safe callback mechanism in Qt that connects object events (signals) to handlers (slots or callables).</dd>

  <dt>Salt</dt>
  <dd>Random value mixed with a password prior to hashing or key derivation to prevent precomputation attacks.</dd>

  <dt>Secretbox</dt>
  <dd>Authenticated encryption primitive that combines a stream cipher with a MAC (XSalsa20-Poly1305 in libsodium).</dd>

  <dt>Tool bar (QToolBar)</dt>
  <dd>A container for quick-access actions represented by buttons and separators.</dd>
</dl>
)HTML";
}

static QString qtLinksHtml() {
    return R"HTML(
<h2>Qt Library</h2>
<p>Selected documentation links for this application:</p>
<ul>
  <li><a href="https://doc.qt.io/qt-6/" target="_blank">Qt 6 Documentation Home</a></li>
  <li><a href="https://doc.qt.io/qt-6/qtextedit.html" target="_blank">QTextEdit</a></li>
  <li><a href="https://doc.qt.io/qt-6/qsavefile.html" target="_blank">QSaveFile</a></li>
  <li><a href="https://doc.qt.io/qt-6/signalsandslots.html" target="_blank">Signals and Slots</a></li>
  <li><a href="https://doc.qt.io/qt-6/dnd.html" target="_blank">Drag and Drop</a></li>
</ul>
<p>Additional classes used include QAction, QMenu, QMenuBar, QToolBar, QLabel, QDialog, QProgressDialog, and QTabWidget.</p>
)HTML";
}

static QString sodiumLinksHtml() {
    return R"HTML(
<h2>Libsodium Library</h2>
<p>Core documentation for primitives used in this application:</p>
<ul>
  <li><a href="https://doc.libsodium.org/" target="_blank">Libsodium Documentation Home</a></li>
  <li><a href="https://doc.libsodium.org/password_hashing" target="_blank">Password hashing (crypto_pwhash, Argon2id)</a></li>
  <li><a href="https://doc.libsodium.org/secret-key_cryptography/secretbox" target="_blank">Authenticated encryption (crypto_secretbox)</a></li>
  <li><a href="https://doc.libsodium.org/usage" target="_blank">Usage basics and linking</a></li>
  <li><a href="https://doc.libsodium.org/quickstart" target="_blank">Quickstart and FAQ</a></li>
</ul>
<p>crypto_pwhash parameters are tunable (operations and memory limits) and should match the security profile of the deployment.</p>
)HTML";
}

static QString sourcesApaHtml() {
    return R"HTML(
<h2>Sources (APA)</h2>
<ol>
  <li>The Qt Company. (2025). <i>Qt 6 documentation</i>. https://doc.qt.io/qt-6/</li>
  <li>The Qt Company. (2025). <i>QTextEdit Class</i>. https://doc.qt.io/qt-6/qtextedit.html</li>
  <li>The Qt Company. (2025). <i>QSaveFile Class</i>. https://doc.qt.io/qt-6/qsavefile.html</li>
  <li>The Qt Company. (2025). <i>Signals and slots</i>. https://doc.qt.io/qt-6/signalsandslots.html</li>
  <li>The Qt Company. (2025). <i>Drag and drop</i>. https://doc.qt.io/qt-6/dnd.html</li>
  <li>libsodium developers. (2025). <i>Libsodium documentation</i>. https://doc.libsodium.org/</li>
  <li>libsodium developers. (2025). <i>Password hashing</i>. https://doc.libsodium.org/password_hashing</li>
  <li>libsodium developers. (2025). <i>Secret-key cryptography: secretbox</i>. https://doc.libsodium.org/secret-key_cryptography/secretbox</li>
  <li>Internet Engineering Task Force. (2021). <i>RFC 9106: Argon2 memory-hard function for password hashing and proof-of-work applications</i>. https://www.rfc-editor.org/rfc/rfc9106</li>
  <li>Kitware. (2025). <i>CMake: Qt6 integration and qt_add_executable</i>. https://cmake.org/cmake/help/latest/module/Qt6.html</li>
</ol>
<p>Accessed August 25, 2025.</p>
)HTML";
}

static QString codeReferenceHtml() {
    return R"HTML(
<h2>Code Reference</h2>
<h3>Files</h3>
<ul>
  <li><b>src/main.cpp</b>: Editor UI, file I/O, encryption/decryption.</li>
  <li><b>src/help.cpp</b>: Help dialog tabs and content.</li>
  <li><b>CMakeLists.txt</b>: Qt6 Widgets + libsodium; AUTOMOC via qt_add_executable.</li>
</ul>

<h3>Constants</h3>
<ul>
  <li><code>MAGIC = "QTE1"</code>, <code>VERSION = 0x01</code></li>
  <li><code>opsLimit_</code>, <code>memLimit_</code>: Argon2id KDF cost parameters.</li>
</ul>

<h3>Helpers</h3>
<ul>
  <li><code>wipeQByteArray</code>: Securely clears a buffer.</li>
  <li><code>wipeQString</code>: Best-effort wipe of temporary UTF-8 and clear.</li>
</ul>

<h3>PasswordDialog</h3>
<ul>
  <li><i>Purpose</i>: Enter or set a password; show/hide; caps-lock hint; strength meter.</li>
  <li><i>API</i>: <code>takePasswordUtf8()</code> returns UTF-8 bytes and clears inputs.</li>
</ul>

<h3>EditorWindow</h3>
<ul>
  <li><i>Actions</i>: New, Open, Save, Open Encrypted, Save Encrypted As, Read Only, Help Contents, About.</li>
  <li><i>Plaintext I/O</i>: <code>openPlainPath</code>, <code>saveFile</code>.</li>
  <li><i>Encrypted I/O</i>: <code>encryptToPath</code>, <code>decryptFromPath</code>, <code>decryptPathAsync</code>.</li>
  <li><i>DnD</i>: <code>dragEnterEvent</code>, <code>dropEvent</code>.</li>
  <li><i>Status</i>: <code>updateCaretLabel</code>, read-only toggle, About dialog.</li>
</ul>

<h3>Encryption format</h3>
<pre>
MAGIC(4) | VERSION(1) | SALT(16) | NONCE(24) | OPS(u32 LE) | MEM(u32 LE) | CIPHERTEXT
KDF: crypto_pwhash (Argon2id).  AEAD: crypto_secretbox (XSalsa20-Poly1305).
</pre>

<h3>Concurrency and safety</h3>
<ul>
  <li>Background work runs on <code>std::thread</code>; UI updates arrive via <code>QMetaObject::invokeMethod</code>.</li>
  <li>Progress dialogs are heap-allocated and guarded by <code>QPointer</code>.</li>
  <li>Sensitive buffers are wiped using libsodium primitives.</li>
</ul>

<h3>External APIs</h3>
<ul>
  <li><b>Qt</b>: QTextEdit, QFileDialog, QFile, QTextStream, QSaveFile, QProgressDialog, QAction, QMenu, QMenuBar, QToolBar, QStatusBar, QMessageBox.</li>
  <li><b>libsodium</b>: sodium_init, sodium_memzero, sodium_mlock/unlock, randombytes_buf, crypto_pwhash, crypto_secretbox_easy/open_easy.</li>
</ul>

<h3>Keywords</h3>
<ul>
  <li><code>Q_OBJECT</code>: enables signals/slots; requires AUTOMOC or <code>#include "main.moc"</code>.</li>
  <li><code>override</code>, <code>constexpr</code>, <code>static</code>, <code>const</code>: standard C++ specifiers as used in the code.</li>
</ul>
)HTML";
}
static QString chatGPTHtml() {
  return R"HTML(
<h2>ChatGPT</h2>
<ol>
  <li><a href="https://chatgpt.com/share/68ac7667-56b8-800c-9dd2-d7a6de259642" target="_blank">[1]A Text Editor - Original Construction<br/> </a></li>
    <li><a href="https://chatgpt.com/share/68ac938b-ba18-800c-bc0a-39e03c794571" target="_blank">[2] A Text Editor - Code Review with Legal Information:<br/> </a></li>
	  <li><a href="https://chatgpt.com/share/68adb36f-158c-800c-810b-9cecd78f9dbf" target="_blank">[3] A Text Editor - More on Affirmation and signatures within application not libsodium<br/> </a></li>
</ol>
)HTML";
}


// Public entry point callable from main.cpp
void showHelpDialog(QWidget *parent) {
    QPointer<QDialog> dlg = new QDialog(parent);
    dlg->setAttribute(Qt::WA_DeleteOnClose, true);
    dlg->setWindowTitle("Help");
    dlg->resize(820, 680);

    auto *tabs = new QTabWidget(dlg);

    auto makePage = [](const QString &html) {
        auto *tb = new QTextBrowser;
        tb->setOpenExternalLinks(true);
        tb->setHtml(html);
        return tb;
    };

    tabs->addTab(makePage(glossaryHtml()), "Glossary");
    tabs->addTab(makePage(qtLinksHtml()), "Qt Library");
    tabs->addTab(makePage(sodiumLinksHtml()), "Libsodium");
    tabs->addTab(makePage(sourcesApaHtml()), "Sources (APA)");
    tabs->addTab(makePage(codeReferenceHtml()), "Code Reference");
    tabs->addTab(makePage(chatGPTHtml()), "ChatGPT");

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    QObject::connect(buttons, &QDialogButtonBox::rejected, dlg.data(), &QDialog::reject);
    QObject::connect(buttons, &QDialogButtonBox::accepted, dlg.data(), &QDialog::accept);

    auto *layout = new QVBoxLayout(dlg);
    layout->addWidget(tabs);
    layout->addWidget(buttons);

    dlg->open();
}
