# Authentication

<!--

passwords: strength, storage, transmission, forgotten password flow
supporting password managers
MFA
Taking care around auth responses/error messages
login throttling
CAPTCHA
security questions
passwordless protocols: OAuth, OpenID, …
HTTP authentication
Web Authentication API

-->

Authentication is the process of verifying that an entity - such as a user of a website - is who they claim to be. You'll most likely need to think about authentication if you want users to sign into your website.

If users can sign into your website, there are typically things signed-in users can do, or data they can access, that you don't want to make generally available. For example, signed in users might be able to:

- Make use of a service they have paid for.
- Spend money.
- Access private personal or corporate information.
- Interact socially with others in the persona associated with the account.

All these abilities, and more, make user account access an important target for attackers. If an attacker is able to sign into your site by pretending to be a legitimate user, the attacker could access and exploit, for example, the user's private data, financial credentials, or confidental corporate secrets. They could also impersonate the user on your site, causing reputational and potentially financial damage.

In this guide we'll looks at the main techniques available for authenticating users on the web, and good practices for them.

## Passwords

The original authentication method on the web, and probably still the most common, is the password.

Password authentication consists of two flows: registration (or signing up), and signing in.

We can picture registration, in its most basic form, as something like this:

![Registration using a password.](password-basic-register.svg)

1. The user supplies a new username and password, for example by entering it in a `<form>` element in the website.
2. The web page sends the username and password to the server, for example by submitting the form in a `POST` request.
3. The server creates a new record for this user in its database. The key is the username and the password is stored under it.

Signing in then looks something like this:

![Signing in using a password.](password-basic-signin.svg)

1. The user supplies the username and password.
2. The web page sends the username and password to the server.
3. The server retrieves the stored password for the user, and compares the stored password with the one it just received.

Looking at this flow, we can see some of the ways an attacker can impersonate the user.

1. **Guessing**: an attacker could try many different possible passwords for a user. Attackers typically use password lists which contain many of the most common passwords.
2. **Credential stuffing**: an attacker could buy a collection of username/password pairs from a previous data breach on a different site, and then try them on the target site in the hope that a user has used the same password for both sites.
3. **Interception**: an attacker could intercept the username and password while it is in transit from the browser to the server. One practical way to do this is to set up free Wifi hotspots in cafes or airports, and wait for victims to connect and then sign in to the target website.
4. **Database compromise**: an attacker could break into the server and retrieve the database of stored records.
5. **Phishing**: an attacker could trick the user into handing their password to the attacker. For example, an attacker might create a page that looks just like the target site's login page, and send the target user an email containing a link to the fake page, asking them to sign in.

In the next few sections we'll outline recommended practices for implementing password-based authentication. These are intended to reduce these threats, but as we'll see, it is impossible to eliminate them.

### Choosing passwords

The risk of guessing attacks can be reduced if users choose stronger passwords, and the policies websites follow can help with this.

When users choose new passwords, websites should:

- Have a generous maximum password length (_at least_ 64 characters).
- Allow any Unicode characters.
- Not require specific character types (for example, don't require a mix of upper and lower case, or punctuation). Rules like this can exclude many strong password choices (for example, passphrases), and users typically follow such rules in highly predictable ways.

Additionally, websites can reduce the risk of credential stuffing attacks by rejecting passwords that have been included in data breaches. For example, the [Have I Been Pwned](https://haveibeenpwned.com) website provides lists of passwords found in data breaches, and makes it available through an [API](https://haveibeenpwned.com/API/v3#PwnedPasswords).

Note, though, that this is far from a complete defense for the credential stuffing attack: for example, data breaches may not be public, or may happen after the password was chosen.

Websites should also consider using a passsword strength tool like [zxcvbn](https://github.com/zxcvbn-ts/zxcvbn): note that this particular tool also checks passwords against the Have I Been Pwned data.

You can read more details about password strength recommendations in the following articles:

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#implement-proper-password-strength-controls)
- [NIST Digital Identity Guidelines: Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Passwords Evolved: Authentication Guidance for the Modern Era - Troy Hunt](https://www.troyhunt.com/passwords-evolved-authentication-guidance-for-the-modern-era/)

--

- no password hints
- no regular changes
- notify users of abnormal behavior

### Sending passwords

To reduce the risk of an attacker intercepting passwords in transit, a site must use TLS for registration and login pages.

Additionally, sites must use TLS for all pages served to a logged-in user, or an attacker will be able to intercept the session identifier and hijack the session.

Sites are very strongly encouraged to use TLS for all pages, and many features of the modern web will not work for pages not served over TLS.

TODO: better docs on how to set this up? Using Let's Encrypt or a hosting service?

### Storing passwords

Password-based authentication must store passwords, of course, and must try to protect users even if an attacker gets access to the database containing the stored passwords.

#### Hashing passwords

Websites must not store passwords in plaintext form. Instead, when the user registers with a new password (or changes their password), the password is hashed and the hash is stored. When the user presents their password on sign-in, the site:

- retrieves the hash from the database
- hashes the password provided by the user
- compares the hashes.

A hash is a _one-way function_, meaning that it's not possible to derive the original input to a hash function from its output.

This means that if an attacker gets access to the database, they will typically try to extract passwords by hashing lists of common passwords and comparing the results with the entries in the database. For this reason the hash functions chosen for password storage are intentionally slow and difficult to optimize.

Hash functions that are designed for hashing passwords typically allow you to configure the amount of work involved to create the hash, so they can be made slower or faster depending on the expected capabilites of the attacker.

#### Precomputed hash tables

Rather than calculate hash tables themselves, attackers can look up the password corresponding to a hash in a precomputed table (also known as a [rainbow table](https://en.wikipedia.org/wiki/Rainbow_table)) mapping possible passwords to their hashes:

| Password | Hash        |
| -------- | ----------- |
| pa55w0rd | 56965E2A... |
| abcdef   | BEF57EC7... |
| letmein  | 1C8BFE8F... |

Although these tables may be very large, such attacks can be effective because table lookup is a fast operation.

#### Salt and pepper

To defeat attacks that use precomputed hash tables, _salt_ must be added to the password before it is hashed. Salt is a random value unique to each password. It does not have to be secret: salt is stored alongside the hashed password. However, it prevents an attacker from using precomputed hash values, because the salt means that a given password will hash to a different value.

As an additional defense, websites may also add _pepper_ to the hash function's input. Unlike salt, pepper is:

- Not unique: the same value is used for all the passwords in the database.
- A secret: it must not be stored in the database itself but in a separate location such as a hardware security module (HSM).

#### Hashing algorithms

Websites should use standard algorithms to hash passwords. These algorithms support all the features discussed above. The [OWASP guide to password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#password-hashing-algorithms) recommends, in order of preference:

1. [Argon2id](https://en.wikipedia.org/wiki/Argon2)
2. [scrypt](https://en.wikipedia.org/wiki/Scrypt)
3. [bcrypt](https://en.wikipedia.org/wiki/Bcrypt)
4. [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)

Websites should use password storage and verification functions provided by a reputable framework, rather than trying to implement their own. For example, [Django](https://docs.djangoproject.com/en/5.0/topics/auth/passwords/) uses PBKDF2 by default but enables you to use a different algorithm if you choose.

### Password managers

A password manager is an application that enables users to store passwords, so they don't have to remember them. Password managers may also autofill passwords in login forms and generate strong passwords for users.

Password managers are often implemented as browser extensions, and browsers also provide their own built-in password managers.

Typically, on a registration form, a password manager will:

- recognize when a user is being asked to create a new password and offer to generate one
- recognize when a user submits a registration form and offer to store the username and password, associated with the site.

On a login form, a password manager will recognize that the user is being asked to provide their username and password, and autofill them from its storage.

Password managers bring new risks to the security landscape by providing a new target for attackers. The risks are especially pronounced when passwords are synchronized across devices or stored off the device.

However, password manager help reduce the threat of guessing and credential stuffing attacks, by making it much easier for users to have strong passwords and reducing the degree of password reuse. They can also help with phishing attacks, since a password manager will know that `paypa1.com` is not `paypal.com`, and will not autofill its login form.

So, on balance, password managers provide a net benefit, and web developers should make it easier for them to work.

- Registration, login, and change password processes should each have their own `<form>` element.
- Forms should give a clear indication that the form has been submitted. This means either navigating to another page on submission, or simulating a navigation with `History.pushState()` or `History.replaceState()`.
- Individual `<input>` elements should use the correct `type`:
  - `"text"` or `"email"` for usernames
  - `"password"` for passwords.
- Individual `<input>` elements should use the correct `autocomplete` attribute:
  - `"username"` for username
  - `"new-password"` for creating a new password, in registration or password change forms
  - `"current-password"` for entering an existing password, in login or password change forms.
- Use hidden fields for information that the user does not have to enter, but that can provide a hint to password managers. For example, the user may not have to enter the username in a change password from, but the username can help a password manager know which password to enter.
- Follow the guidelines in "Choosing passwords" above, to ensure auto-generated passwords will be accepted by your system.

### MFA

Taking care around auth responses/error messages
login throttling
CAPTCHA
security questions
passwordless protocols: OAuth, OpenID, …
HTTP authentication
Web Authentication API

## The Web Authentication API

The Web Authentication API, often shortened to _WebAuthn_, is a JavaScript API provided in browsers which enables websites to authenticate users without the use of passwords.

A fundamental concept in WebAuthn is the _authenticator_. An authenticator is an entity that is inside or attached to the user's device, and that can perform the cryptographic operations needed to register and authenticate users, and securely store the cryptographic keys used in these operations.

An authenticator might be integrated into the device, like the Touch ID system in Apple devices or the Windows Hello system, or it might be a removable module like a Yubikey.

Instead of passwords, WebAuthn uses _public-key cryptography_ to authenticate users:

- To register users, the authenticator generates a public/private key pair representing the user's account on the website. The website front end sends the public key to the server, which stores it alongside the other registration information.
- To authenticate users, the authenticator uses the private key to generate digitally signed messages. The website front end sends these messages to the server, which uses the stored public key to verify the signatures. If verification succeeds, the user can be signed in.

WebAuthn has several advantages over passwords:

- It is much more convenient for users, who can, for example, use a biometric reader on their device to sign into a website instead of having to remember a password.
- Because it uses digital signatures instead of passwords, the user's secrets never have to leave their device, so there is much less risk of them being stolen.
- Because the digitally signed messages are specific to a domain, WebAuthn is resistant to phishing attacks. If an attacker tricks the user into entering their credentials on the attacker's site, the attacker cannot use those credentials on the real site, because the domain in the credentials will not match the real site.

There are two distinct flows involved in WebAuthn:

- _Registration_, in which a new user signs up.
- _Authentication_, in which a returning user signs in.

### Registration

The registration flow contains the following steps:

1. The user asks to sign up to a website, for example by clicking a "Sign up" button in the website's UI.

2. The website front end makes an HTTP request to the server for a _challenge_, which is a long random number.

3. The website front end calls `navigator.credentials.create()`, passing in the challenge sent by the server in step 2, and various other parameters, which may include:

   - Some information about the website for which the user is registering, which in WebAuthn is called the _relying party_. This includes a domain associated with the website, and a human-readable name for it.
   - Some information about the user, including a user ID, a username, and a display name.
   - Any preferences the website has for specific authenticators or types of authenticator.
   - Any preferences the website has for the cryptographic algorithm to use.
   - Whether and how the website wants the authenticator to provide evidence of its own authenticity: that is, for example, whether it is a real Yubikey device. This is called _attestation_.

4. The `navigator.credentials.create()` implementation asks the appropriate authenticator to create the cryptographic objects we'll need to create a registration.

   - The authenticator may first ask the user to authenticate themselves, for example using a biometric reader.
   - The authenticator then generates a new public/private key pair. This will be specific to both the user and the website, and is called the _credential_ key pair.
   - The authenticator will also generate an attestation. If the server did not ask for attestation, then the authenticator will generate an empty attestation: otherwise the attestation will typically consist of a digital signature, calculated using a separate attestation key, over the challenge from the server and the credential public key.
   - The authenticator stores the private half of the credential key pair, and returns the public half, along with the attestation, to `navigator.credentials.create()`. The `navigator.credentials.create()` method in turn returns these objects to the website front end code.

5. The website front end code sends the credential public key and the attestation to the server. The server verifies the attestation: if an attestation was requested, this involves verifying the signature it contains, and checking that the key used to create the signature is itself properly certified as belonging to the authenticator. If verification succeeds, the server creates an account for the new user, storing the credential public key along with the other account information.

### Authentication

The authentication flow consists of the following steps:

1. The user asks to sign into the website, for example by clicking a "Sign in" button in the website's UI.

2. The website front end makes an HTTP request to the server for a _challenge_, which is a long random number.

3. The website front end calls `navigator.credentials.get()`, passing in the challenge sent by the server in step 2, and various other parameters, which may include:

   - The domain for which the authentication will be valid
   - Whether the website requires or prefers the user to be verified, for example using biometrics or a PIN.
   - An identifier for the credential public key to use, if it is known. This can help in finding the authenticator to use.

4. The `navigator.credentials.get()` implementation asks the appropriate authenticator to create the cryptographic objects we'll need to authenticate the user.

### WebAuthn glossary

- _attestation_
- _authenticator_
- _challenge_
- _credential_
- _digital signature_
- _public key cryptography_
- _relying party_
- _replay attacks_

### Public key cryptography

Instead of passwords, WebAuthn relies on _public key cryptography_. In public key cryptography, a key is created in two parts, called a _key pair_. One of the parts is kept secret and is called the _private key_, while the other can be made public and is called the _public key_. If a message is encrypted with one key, it can only be decrypted with the other key.

This enables a message to be _digitally signed_:

- The signer encrypts the message with their private key, and sends the message and the encrypted message to the verifier.
- The verifier decrypts the message with the public key, and if it matched the original message, can be assured that the signature was generated by the corresponding private key.

### dfdfd

The domain will later be included in the signed messages used to authenticate the user, and will ensure that messages are specific to a domain, making phishing attacks much more difficult.
