# Project 2 - Secure Password Manager

## Team

- Yuchen Ye 2023901708
- Haitian Gao 2023903116

A local Python CLI with Argon2id master-password verification, an Argon2-derived
AES-256-GCM vault key, and a secrets password generator. Bonus A encrypts one
entry for a teammate's public key. No network service is used.

**课堂演示入口：[全部 pm 命令及逐步验证](#pm-demo-guide)**。
The English sections explain setup and security choices; the Chinese guide
below gives the complete classroom demonstration with expected results.

## Click to run in VS Code

Select the project's .venv Python interpreter, then open Run and Debug.
Choose a numbered configuration and click the green play button. The command
arguments are already supplied; enter passwords in VS Code's integrated terminal.
Configurations 01–05 cover the main demonstration, 06–08 the sharing bonus,
09 deletion, 10 password rotation, and 11 the full test suite.
The demonstration uses local/presentation.vault.json. Run init to start each rehearsal.
After extracting the ZIP on a new machine, create the environment and local/
directory with the setup commands below before starting the demonstration.

## Run

Python 3.11 or newer:

~~~bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
mkdir local

python cli.py --vault local/demo.vault.json init
python cli.py --vault local/demo.vault.json add github alice --generate 24
python cli.py --vault local/demo.vault.json list
python cli.py --vault local/demo.vault.json show github
python cli.py --vault local/demo.vault.json remove github
python cli.py --vault local/demo.vault.json change-master
python cli.py generate --length 24
~~~

Without --generate, add prompts for an existing account password.
Commands get, delete, and gen alias show, remove, and generate.
The --vault option goes before the command; its default is vault.json.
Each command unlocks the vault again. Password prompts use getpass and do
not echo in a normal terminal.

### Short commands in VS Code's terminal

On macOS/Linux, enter this line separately and press Enter to define pm for
the current terminal. It selects the same vault as the Run and Debug menu:

~~~bash
alias pm='.venv/bin/python cli.py --vault local/presentation.vault.json'
~~~

Every numbered Run and Debug action has a CLI equivalent:

| Action | Short command |
| --- | --- |
| 01 Reset all demo data and create the vault | pm init |
| 02 Add GitHub with a generated password | pm add github demo-user --generate 24 |
| 03 List entries | pm list |
| 04 Retrieve GitHub | pm get github |
| 05 Generate a 24-character password | pm gen --length 24 |
| 06 Generate a recipient key pair | pm keygen |
| 07 Share GitHub | pm share github |
| 08 Decrypt the share | pm unshare |
| 09 Delete GitHub | pm delete github |
| 10 Change the master password | pm change-master |
| 11 Run the full test suite | pm test |

To choose the account password yourself, use pm add github alice instead.
The short bonus commands default to local/presentation-private.pem,
local/presentation-public.pem, and local/presentation.share.json. Explicit
key and output paths remain available as shown in the bonus example below.
If you already use a pm alias with a different --vault path, short commands
continue to use that vault; the Run and Debug menu selects its own configured path.

For classroom demonstrations, init resets the selected vault and **all contents
of local/ in the terminal's current directory**, including other demo vaults,
private/public keys, share files, and nested folders. It asks for a new master
password twice and does not ask for the old one. After successful initialization,
local/ contains only the new selected vault if its path is inside local/.
Code and the virtual environment are outside the cleanup scope.

Invalid or cancelled password input leaves the old files intact. During creation,
the old local/ is temporarily moved aside; a creation failure or interruption
restores it. On success the old demo files are removed. This discards their
contents rather than recovering them. An explicitly selected vault outside
local/ is also replaced; other files outside local/ are kept.

Master passwords and private-key passphrases require at least 12 characters.
Generated passwords accept lengths 12–4096 and include lowercase, uppercase,
digits, and symbols. Existing account passwords may be shorter; that does
not make them strong. Commands that retrieve or generate passwords print
them, so use a private terminal.

Keep generated files in the Git-ignored local/ directory. The default vault,
*.vault.json, *.pem, *.share.json, environments, and temporary files are also
ignored; arbitrary custom paths are not automatically safe to commit.
A Docker allowlist excludes vaults, keys, and local environments from builds.

## Why these choices

### 1. Why Argon2id for the master password, not SHA-256 or AES?

We use argon2-cffi. PasswordHasher.hash() stores a $argon2id$... verifier with
the algorithm, parameters, random salt, and hash. On unlock,
PasswordHasher.verify() checks the entered password. The verifier is one-way;
guesses can still be tested.

SHA-256 is fast, so an attacker can try many guesses cheaply. Argon2id makes
each guess cost memory and CPU. Its salt prevents precomputed tables from
being reused across vaults with the same password. It slows guessing but
does not make a weak password safe.

AES is reversible. We only need to check the master password, not recover it;
encrypting it would introduce another key-storage problem. Account passwords
must be recoverable for the user, so they are encrypted instead.

### 2. Why derive the key instead of saving a key file?

Argon2's hash_secret_raw with Type.ID derives a 32-byte AES key from the master
password and a separate random 16-byte salt. Saving a random key beside the
vault would let someone copying the folder get both the key and ciphertext.
We never save the vault encryption key. The public salt alone cannot unlock it.

The verifier and KDF have independent salts. We never store the derived key
as the password verifier. Both Argon2 operations use three iterations,
64 MiB memory, parallelism 4, and 32-byte output. A production application
should benchmark its devices and review these parameters over time.

### 3. Why AES-GCM rather than encryption without authentication?

We use cryptography's AESGCM with a 256-bit key, a fresh random 12-byte nonce
on each save, and a full 16-byte tag appended by the library. All services,
usernames, and account passwords are encrypted together. Authentication
rejects modified ciphertext instead of returning corrupted data.
Reusing a nonce with the same key would be dangerous.

The version, algorithm names, KDF parameters, verifier, salt, and nonce form
a validated header. Its canonical JSON and an application label are passed
as associated data (AAD), so these public fields are authenticated too.
Wrong passwords and authentication failures expose no decrypted entries.

Changes to authenticated values fail. JSON whitespace and key order can
change harmlessly because canonicalization preserves the same meaning.
GCM cannot detect deletion or restoration of an older valid backup.

### 4. Why secrets, not the default random generator?

The default random generator is for simulation, and its output can be
predictable from its state. The secrets.choice() and secrets.SystemRandom()
functions use OS-backed cryptographically secure randomness. We pick one
character per class, fill the rest, and securely shuffle. Salts and nonces
come from os.urandom.

### 5. What is protected, and what is not?

A stolen vault exposes a salted Argon2id verifier, public metadata, and
ciphertext. Recovering account passwords still requires guessing the master
password. Offline guessing remains possible with no server to rate-limit it.
Choose a long, unique master passphrase; a 12-character minimum is not a
strength guarantee.

The tool does **not** protect against weak master passwords, keyloggers,
malware or memory inspection on an unlocked computer, shoulder surfing,
terminal viewing, or screen recordings. It cannot reliably erase immutable
Python strings or control OS swap and crash dumps. Our code does not
deliberately write plaintext credentials to files.

It also cannot prevent deletion, rollback, or lost updates from concurrent
writers. Use one command at a time and keep encrypted backups. There is no
backdoor to recover a forgotten master password.

## Bonus A - Share one entry

The recipient creates an RSA-3072 pair with public exponent 65537. The private
key uses passphrase-encrypted PKCS8 via BestAvailableEncryption. Each teammate
keeps their private key and passphrase private and exchanges only the public
key. Check the public key with the teammate through a trusted channel.

For the local demo, pm gen --length 24 can generate the private-key passphrase.
Copy its output, run pm keygen, and paste it into both hidden passphrase prompts.
Later, pm unshare asks for this passphrase. The generator produces a password;
keygen creates the RSA key files. No separate automatic-passphrase command is
needed, and the application does not save a plaintext copy of the passphrase.
Generate the key pair once per rehearsal. keygen and share refuse existing
paths; use --out with a new path for another share within the same rehearsal.
Starting again with init removes the old keys and shares in local/ too.

A local demonstration using the vault above:

~~~bash
python cli.py keygen --private local/recipient-private.pem --public local/recipient-public.pem
python cli.py --vault local/demo.vault.json add school alice --generate 24
python cli.py --vault local/demo.vault.json share school --public-key local/recipient-public.pem --out local/school.share.json
python cli.py unshare local/school.share.json --private-key local/recipient-private.pem
~~~

Only school is shared. The sender gives the encrypted share file to the
recipient, who uses their private key and its passphrase; the sender's master
password is not needed. These commands do not send messages.

We use hybrid encryption: a fresh random AES-256-GCM key encrypts the entry;
RSA-OAEP with SHA-256 encrypts that key. Direct RSA has a small message limit,
so wrapping a fixed-size key supports long entries too. The share header
is authenticated as AAD. The RSA key files cannot unlock the master vault.

Wrong keys, wrong passphrases, and tampering fail. Sharing does not prove
sender identity: anyone with the public key can create a share. There are
no signatures, revocation, or forward secrecy, and a recipient can copy
decrypted information. Bonus B (HIBP) is not implemented.

## Files and tests

Vault version 2 contains version, kdf, kdf_params, cipher, master_hash, salt,
nonce, and ciphertext. Base64 encodes binary fields; it is not encryption.
The verifier has its own salt; the separate salt field belongs to the KDF.

The parser rejects missing, duplicate, or extra fields, unsupported Argon2
profiles, malformed data, bad lengths, and files over 8 MiB. Checking the
profile before verification stops a modified hash from requesting arbitrary
memory or CPU. Saves flush a private temporary file before atomic replacement.
The CLI's init explicitly resets the selected vault and clears all of local/
for a fresh demonstration; the library's create method defaults to refusing
replacement. Key generation and sharing refuse existing paths. Unix file permissions
are owner-only; Windows protection depends on the account and filesystem.

Changing the master password updates the verifier and re-encrypts entries;
old backups retain their old password. Opening initial-draft version 1 is
rejected without rewriting it; init deliberately replaces the selected file
with a fresh version 2 vault instead. Automatic data migration is not included.

~~~bash
python cli.py test
# Equivalent: python -m unittest -v

# Alternative:
docker build -t project2-password-manager .
docker run --rm --network none --entrypoint python project2-password-manager -m unittest -v
~~~

On 11 November 2026, **54 tests passed in Docker/Python 3.11 and
macOS/Python 3.12**. The original five are retained. Tests cover independent
hash verification, CRUD and persistence, password rotation, crypto and header
tampering, malformed input, failed writes, Unicode, permissions, generation,
and actual CLI processes with terminal prompts. Reset tests also cover clearing
entries, replacing the master password, cancelled or invalid input, and failed
writes. Full-reset tests cover old keys/shares and nested demo files being removed,
preservation of project files, restoration after failed or interrupted creation,
and symlink boundaries. The short-command workflow reuses the password generator as the private-key
passphrase, then generates keys, shares, and decrypts using default paths.
Bonus tests cover wrong
recipients and passphrases, tampering, one-entry isolation, and long entries.

| Module | Responsibility |
| --- | --- |
| password_manager.py | Hash verification, KDF, authenticated vault |
| storage.py | Bounded JSON reads and private atomic writes |
| sharing.py | RSA key pairs and hybrid sharing |
| cli.py | Commands, hidden prompts, results and errors |
| test_*.py | Original, regression, sharing, and process-level tests |

Both members should explain this flow: create hashes the password and saves
an empty encrypted vault; open validates the header, verifies the hash,
derives the key, and checks GCM before returning entries. Every change is
saved encrypted.

## References

- [Teacher's brief and grading](https://kristenpire.github.io/epita-security-labs/project2/)
- [argon2-cffi 23.1.0](https://argon2-cffi.readthedocs.io/en/23.1.0/api.html)
- [cryptography AES-GCM](https://cryptography.io/en/46.0.3/hazmat/primitives/aead/)
- [cryptography RSA-OAEP](https://cryptography.io/en/46.0.3/hazmat/primitives/asymmetric/rsa/#encryption)
- [Python secrets](https://docs.python.org/3/library/secrets.html)

<a id="pm-demo-guide"></a>

## 全部 pm 命令与逐步演示

以下在 **VS Code 下方的集成终端**中操作。代码中的账号都是演示数据，
密码在提示处由操作者输入。每一步的命令单独执行，不要把整段演示一次粘贴运行。

### 0. 准备终端和 pm 快捷命令

在 VS Code 打开项目文件夹，选择项目的 `.venv` Python 解释器，
再点击“终端 → 新建终端”。终端当前位置应是包含 `cli.py` 的项目根目录。
新电脑先完成上方 Run 中的虚拟环境与依赖安装；已有 `.venv` 时无需重复创建。

macOS/Linux 先运行下面这行，确保演示文件夹存在：

~~~bash
mkdir -p local
~~~

然后**单独运行下面这一行并按回车**。这一行正常没有输出：

~~~bash
alias pm='.venv/bin/python cli.py --vault local/presentation.vault.json'
~~~

`pm` 是当前终端的快捷命令，会调用项目的 Python 和 `cli.py`。
它不依赖终端是否显示 `(.venv)`，因为解释器路径已经写在别名中。
关闭或新开终端后，需要重新运行这一行；仅在 VS Code 中选好 Python 不会定义 `pm`。

**准备验证：**先运行 `alias pm`，应能看到别名中指定的 Python、`cli.py` 和密码库路径；
再运行下面的帮助命令，应显示命令列表：

~~~bash
pm --help
~~~

上面的别名与 VS Code“运行和调试”菜单使用同一个 `presentation` 密码库。
如果你之前在使用 `local/demo1.vault.json`，继续演示那份库时，
把别名中的路径改成 `local/demo1.vault.json` 即可。不同文件是不同密码库；
切换别名不会移动账号，也不会更改 VS Code 菜单中的路径。

Windows PowerShell 可以在项目目录定义同样用途的函数：

~~~powershell
New-Item -ItemType Directory -Force local | Out-Null
function pm { & .\.venv\Scripts\python.exe .\cli.py --vault local/presentation.vault.json @args }
~~~

### 命令总表

`服务名`、`用户名`、`长度`和文件路径都是可替换的参数。
现场演示直接用下方各步骤中的具体命令。

| 命令 | 用途与参数 |
| --- | --- |
| `pm --help` | 列出全部命令 |
| `pm 命令 --help` | 查看某条命令的参数，例如 `pm share --help` |
| `pm init` | 清空当前目录下整个 `local/` 的内容，重建选中的密码库并设置新主密码 |
| `pm add 服务名 用户名` | 输入账户密码，添加账号；同名服务会更新原条目 |
| `pm add 服务名 用户名 --generate 长度` | 自动生成指定长度的账户密码并保存 |
| `pm list` | 列出服务名和用户名，不显示账户密码 |
| `pm get 服务名` | 查看该服务的用户名和账户密码；`pm show 服务名` 等效 |
| `pm gen` | 生成20个字符的随机密码，不保存为账号 |
| `pm gen --length 长度` | 生成指定长度的随机密码；`pm generate` 与 `pm gen` 等效 |
| `pm delete 服务名` | 删除条目；`pm remove 服务名` 等效 |
| `pm change-master` | 验证旧主密码，再设置新主密码并重新加密当前库 |
| `pm keygen` | 生成 RSA 公钥和用口令保护的私钥，提示输入两次私钥口令 |
| `pm keygen --private 路径 --public 路径` | 指定私钥、公钥的输出位置 |
| `pm share 服务名` | 使用默认公钥加密分享一条账号记录 |
| `pm share 服务名 --public-key 路径 --out 路径` | 指定接收者公钥和分享文件位置 |
| `pm unshare` | 使用默认私钥解密默认分享文件，提示输入私钥口令 |
| `pm unshare 文件路径 --private-key 路径` | 指定分享文件和接收者私钥 |
| `pm test` | 运行全部自动测试，不要求输入密码 |

密钥和分享文件的默认位置是 `local/presentation-private.pem`、
`local/presentation-public.pem` 和 `local/presentation.share.json`。
可选参数可以单独使用，例如只用 `--out` 更换分享文件位置。
这些默认位置独立于 `pm` 所选的密码库。

主密码和私钥口令至少12个字符；随机密码长度可选12–4096，默认20。
添加已有账号时，账户密码只要求非空，不受主密码的12字符下限限制。
隐藏密码提示中输入或粘贴后，屏幕不会显示字符或星号，直接按回车即可。

### 1. 创建密码库

~~~bash
pm init
~~~

依次在 `New master password:` 和 `Confirm master password:` 输入同一个新主密码。
首次应显示：

~~~text
Created encrypted vault: local/presentation.vault.json
Reset local demo files: local
~~~

**验证：**运行 `pm list`，输入刚设置的主密码。应成功返回终端提示符，
此时库为空，所以没有账号行。

本项目为方便从头演示，**每次 `pm init` 都清空当前目录下 `local/` 中的全部内容**：
旧账号、旧主密码验证信息、其他演示密码库、公钥、私钥、分享文件及子文件夹。
然后重新创建选中的空密码库；如果该库在 `local/` 中，清理后只保留这个新库。
原库存在时会显示 `Reset encrypted vault: ...`。

新主密码确认成功后才开始重置，创建失败或中途取消会恢复旧的 `local/`。
代码、README和虚拟环境保留。下一轮从本步开始后，按顺序重新添加账号、
生成密钥和分享即可，无需手动清理上轮文件。

### 2. 添加 GitHub 账号

~~~bash
pm add github alice
~~~

依次输入：

1. `Master password:`：第1步设置的密码库主密码。
2. `Account password:`：这次要保存的 GitHub 演示账号密码。

成功后应显示 `Saved: github`。

**验证：**运行 `pm list` 并输入主密码，应看到 `github: alice`。
如果想直接生成并保存24位账户密码，可改用：

~~~bash
pm add github alice --generate 24
~~~

这个版本只问主密码，随后显示 `Saved: github` 和 `Generated password: ...`。
运行 `pm get github`，应取回同一个生成的账户密码。
再次添加同一个 `github` 会更新其用户名和密码，不会新增第二条同名记录。
VS Code 第02项采用自动生成密码，用户名预设为 `demo-user`。

### 3. 查看账号和密码

~~~bash
pm get github
~~~

输入主密码后，应显示：

~~~text
Username: alice
Password: <刚才保存的账户密码>
~~~

**验证：**用户名和账户密码应与第2步保存的内容相同。
`pm show github` 的结果相同。展示中的尖括号内容是说明，不是实际输出。

取出时显示明文，是程序已经验证主密码并在内存中解密。
在 VS Code 资源管理器中展开 `local`，打开当前密码库文件，
磁盘保存的是公开参数、主密码验证哈希和密文；其中没有账号密码明文。

### 4. 列出账号，并验证错误主密码

~~~bash
pm list
~~~

输入正确主密码，应显示 `github: alice`，不显示账户密码。

**验证：**再运行一次 `pm list`，故意输入错误主密码。
应出现 `Error: ...`，没有账号列表。重新运行并输入正确主密码后，仍能正常列出账号。

### 5. 生成强密码

~~~bash
pm gen --length 24
~~~

无需输入主密码，会输出一行24个字符的随机密码。
不写 `--length` 的 `pm gen` 默认生成20个字符。

**验证：**输出长度应与指定值一致，并包含大写字母、小写字母、数字和符号。
再执行一次应生成新的随机结果；这个命令不会自动把结果存进 GitHub 条目。
长度和字符类别也由第11步的自动测试检查。

### 6. 删除 GitHub 账号，再为分享重新添加

~~~bash
pm delete github
~~~

输入主密码后，应显示 `Removed: github`。

**验证：**运行 `pm list`，不应再出现 `github`；
再运行 `pm get github`，输入主密码后应显示：

~~~text
Error: No entry for service: github
~~~

接下来要分享这条记录，所以先重新添加：

~~~bash
pm add github alice
~~~

按第2步输入主密码和账户密码，看到 `Saved: github` 后再继续。
也可以把删除放在分享演示之后，这样不需要重新添加。

### 7. 生成队友的公钥和私钥

首次演示时，先生成保护私钥的口令：

~~~bash
pm gen --length 24
~~~

复制这一行随机密码，然后执行：

~~~bash
pm keygen
~~~

1. `Private-key passphrase:`：粘贴刚才复制的随机密码，回车。
2. `Confirm private-key passphrase:`：再粘贴一次，回车。

应显示：

~~~text
Created encrypted private key: local/presentation-private.pem
Public key to exchange: local/presentation-public.pem
~~~

**验证：**在 VS Code 资源管理器中展开 `local`，应看到这两个文件；
第9步能否用对应口令解密分享，会进一步验证密钥可用。

24个字符是**保护私钥的口令**。真正的公私钥由 `keygen` 生成，采用 RSA-3072；
私钥经过加密并编码为 PEM，所以文件内容很长是正常的。
保管好这一口令，后面的 `unshare` 还要用到。项目不会把口令另存成明文文件。

如果本轮已经生成过密钥，跳过本步并继续使用原来的私钥口令。
重新运行 `pm gen` 不会更改已有私钥的口令；`keygen` 也不会覆盖已有密钥。
如果刚执行了 `pm init`，上轮在 `local/` 中的密钥已经清理，需重新生成。
实际两人分享时，由接收者在自己的机器上生成密钥，只把公钥交给发送者。
这里为了单人演示，在同一台电脑上模拟双方。

### 8. 用公钥分享 GitHub 账号

~~~bash
pm share github
~~~

在 `Master password:` 输入当前密码库主密码。
成功后应显示：

~~~text
Encrypted one entry: local/presentation.share.json
~~~

**验证：**展开 `local` 应看到分享文件，打开后是算法名称及加密数据，
看不到 GitHub 用户名和账户密码明文。此命令只生成文件，不会自动发给队友。
实际分享时把这个加密文件交给接收者；私钥和私钥口令由接收者自己保管。

如果默认分享文件已经存在，用一个新的文件名保存：

~~~bash
pm share github --out local/second.share.json
~~~

对应的解密命令是 `pm unshare local/second.share.json`，不要误读上一份分享。
已有分享文件不会被覆盖；也可以直接用现有文件重复演示解密。

### 9. 用私钥解密分享

~~~bash
pm unshare
~~~

看到 `Private-key passphrase:` 时，粘贴第7步用于保护私钥的口令并回车。
应显示：

~~~text
Service: github
Username: alice
Password: <分享时保存的账户密码>
~~~

**验证：**内容应与第8步分享时的 GitHub 条目一致。
可以再运行一次，故意输入错误的私钥口令；应出现 `Error: Cannot decrypt share: ...`，
不显示账号内容。使用正确口令重新运行后，仍能解密。
解密分享只需要接收者的私钥和其口令，不需要发送者的主密码。

### 10. 修改主密码

~~~bash
pm change-master
~~~

依次输入：

1. `Master password:`：当前主密码。
2. `New master password:`：至少12个字符的新主密码。
3. `Confirm master password:`：再输入一次新主密码。

应显示：

~~~text
Master password changed and vault re-encrypted
~~~

**验证：**运行 `pm list`，用新主密码应能列出原来的 GitHub 账号；
再运行 `pm get github`，账户密码应保持不变。
使用旧主密码运行 `pm list` 应报错，不能打开当前库。
主密码修改不改变第7步私钥的保护口令，已有分享文件仍用原私钥口令解密。

### 11. 运行全部自动测试

~~~bash
pm test
~~~

不用输入任何密码。测试会检查创建、增列取删、持久化、错误密码、重置、
换主密码、生成密码、文件篡改拒绝、公钥分享和 CLI 流程等。
测试使用临时数据，不会更改当前演示库或密钥。

**验证：**最后应看到类似结果，耗时以实际机器为准：

~~~text
Ran 54 tests in ...s

OK
~~~

`OK` 表示全部通过。出现 `FAIL`、`ERROR` 或 `FAILED` 就表示存在未通过的测试，
应查看对应测试名和错误信息。如果只看到少量测试，确认运行的是 `pm test`，
而不是编辑器右上角只运行某一个测试文件的按钮。

在不使用别名时，也可以运行 `python cli.py test` 或 `python -m unittest -v`；
使用当前选中的项目环境。macOS 可以直接运行 `.venv/bin/python cli.py test`。

### 其他参数与常见问题

**查看帮助：**`pm --help` 查看总表；`pm add --help`、`pm keygen --help`、
`pm share --help` 和 `pm unshare --help` 查看对应参数。

**临时选择另一个密码库：**全局 `--vault` 放在子命令前面。例如：

~~~bash
pm --vault local/another.vault.json init
~~~

这里最后指定的 `--vault` 覆盖别名内的默认路径，只影响这一条命令。
后续操作这个新库时也要指定同一路径，或另行修改别名。
**`init` 仍会清空整个 `local/`，并在指定位置创建新的空库**；
其他 `local/` 内的密码库也会删除。即使选中的库在 `local/` 以外，清理范围仍包含 `local/`。

**指定另一组密钥和分享位置：**以下三条按顺序执行，密码在提示处输入：

~~~bash
pm keygen --private local/teammate-private.pem --public local/teammate-public.pem
pm share github --public-key local/teammate-public.pem --out local/teammate.share.json
pm unshare local/teammate.share.json --private-key local/teammate-private.pem
~~~

**新终端显示 `zsh: command not found: pm`：**重新单独运行第0步的 alias 定义，
按回车后再输入 `pm` 命令。项目文件夹或 Python 解释器选择不会自动保存这个别名。

**找不到 `cli.py` 或 `.venv/bin/python`：**确认 VS Code 打开的是项目文件夹，
终端也在项目根目录；新电脑按上方 Run 创建环境并安装依赖。

**密码太短或两次不一致：**至少12个字符，两次输入相同。
错误或取消输入不会先清空已有库；按 `Control+C` 可以取消当前命令。

**`No entry for service: github`：**先用同一个密码库运行 `pm list` 核对服务名，
需要时用 `pm add github alice` 重新添加；默认服务名按输入的大小写匹配。

**密钥或分享文件已存在：**密钥可以直接复用；需要另一组密钥时用新的
`--private` 和 `--public` 路径。另一次分享用新的 `--out` 路径，解密时传入同一文件名。
开始新一轮演示时运行 `pm init`，会一起清理 `local/` 中的这些文件。

**分享解密失败：**核对分享文件、对应私钥和该私钥的口令是否配套。
24位随机口令、密码库主密码和 GitHub 账户密码用途不同，按各自提示输入。
