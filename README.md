# Project 2 - Secure Password Manager

## Team

- Yuchen Ye 2023901708
- Haitian Gao 2023903116

A local Python CLI with Argon2id master-password verification, an Argon2-derived
AES-256-GCM vault key, and a secrets password generator. Bonus A encrypts one
entry for a teammate's public key. No network service is used.

## Click to run in VS Code

Select the project's .venv Python interpreter, then open Run and Debug.
Choose a numbered configuration and click the green play button. The command
arguments are already supplied; enter passwords in VS Code's integrated terminal.
Configurations 01–05 cover the main demonstration, 06–08 the sharing bonus,
09 deletion, 10 password rotation, and 11 the full test suite.
The demonstration uses local/presentation.vault.json. Initialize it once.
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
New vaults, key pairs, and shares refuse existing paths. Unix file permissions
are owner-only; Windows protection depends on the account and filesystem.

Changing the master password updates the verifier and re-encrypts entries;
old backups retain their old password. Initial-draft version 1 is rejected
without overwriting it. Keep its original program if you have old data;
automatic migration is not included.

~~~bash
python -m unittest -v

# Alternative:
docker build -t project2-password-manager .
docker run --rm --network none --entrypoint python project2-password-manager -m unittest -v
~~~

On 11 November 2026, **44 tests passed in Docker/Python 3.11 and
macOS/Python 3.12**. The original five are retained. Tests cover independent
hash verification, CRUD and persistence, password rotation, crypto and header
tampering, malformed input, failed writes, Unicode, permissions, generation,
and actual CLI processes with terminal prompts. Bonus tests cover wrong
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
