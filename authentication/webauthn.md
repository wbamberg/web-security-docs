# The Web Authentication API

The Web Authentication API, often shortened to _WebAuthn_, is a JavaScript API provided in browsers which enables websites to authenticate users without the use of passwords.

A fundamental concept in WebAuthn is the _authenticator_. An authenticator is an entity that is inside or attached to the user's device, and that can perform the cryptographic operations needed to register and authenticate users, and securely store the cryptographic keys used in these operations.

An authenticator might be integrated into the device, like the Touch ID system in Apple devices or the Windows Hello system, or it might be a removable module like a Yubikey.

Instead of passwords, WebAuthn uses _public-key cryptography_ to authenticate users:

- To register users, the authenticator generates a public/private key pair representing the user's account on the website. The website front end sends the public key to the server, which stores it alongside the other registration information, such as the username and user ID.
- To authenticate users, the authenticator uses the private key to generate a digitally signed message. The website front end sends this message to the server, which uses the stored public key to verify the signature. If verification succeeds, the user can be signed in.

WebAuthn has several advantages over passwords:

- It is much more convenient for users, who can, for example, use a biometric reader on their device to sign into a website instead of having to remember a password.
- Because it uses digital signatures instead of passwords, the user's secrets never have to leave their device, so there is much less risk of them being stolen.
- Because the digitally signed messages are specific to a domain, WebAuthn is resistant to phishing attacks. If an attacker tricks the user into entering their credentials on the attacker's site, the attacker cannot use those credentials on the real site, because the domain in the credentials will not match the real site.

There are two distinct flows involved in WebAuthn:

- _Registration_, in which a new user signs up.
- _Authentication_, in which a returning user signs in.

## Registration

The registration flow contains the following steps:

1. The user asks to sign up to a website, for example by clicking a "Sign up" button in the website's UI.

2. The website front end makes an HTTP request to the server for a _challenge_, which is a long random number.

3. The website front end calls `navigator.credentials.create()`, passing in the challenge sent by the server in step 2, and various other parameters, which may include:

   - Information about the website for which the user is registering, which in WebAuthn is called the _relying party_. This includes a domain associated with the website, and a human-readable name for it. The domain must be the effective domain of the document origin, or a suffix of that domain.
   - Information about the user, including a user ID, a username, and a display name.
   - Any preferences the website has for specific authenticators or types of authenticator.
   - Any preferences the website has for the cryptographic algorithm to use.
   - Whether and how the website wants the authenticator to provide evidence of its own authenticity: that is, for example, whether it is a real Yubikey device. This is called _attestation_.

4. The `navigator.credentials.create()` implementation asks the appropriate authenticator to create the cryptographic objects that represent a registration.

   - The authenticator may first ask the user to authenticate themselves, for example using a biometric reader.
   - The authenticator then generates a new public/private key pair. This will be specific to both the user and the website, and is called the _credential_ key pair.
   - The authenticator will also generate an attestation. If the server did not ask for attestation, then the authenticator will generate an empty attestation: otherwise the attestation will typically consist of a digital signature, calculated using a separate attestation key, over the challenge from the server and the credential public key.
   - The authenticator stores the private half of the credential key pair, and returns the public half, along with the attestation, to `navigator.credentials.create()`. The `navigator.credentials.create()` method in turn returns these objects to the website front end code.

5. The website front end code sends the credential public key and the attestation to the server. The server verifies the attestation: if an attestation was requested, this involves verifying the signature it contains, and checking that the key used to create the signature is itself properly certified as belonging to the authenticator. If verification succeeds, the server creates an account for the new user, storing the credential public key along with the other account information.

### Attestation

Since the authenticator controls access to the credential private key, WebAuthn places a lot of trust in the authenticator. Attestation is a process within registration, which provides evidence to the server about where the authenticator itself came from, which the server can use to decide whether to trust the authenticator.

For example, attestation might enable a server to know that a credential was really produced by a Yubikey.

In the `attestation` parameter to `navigator.credentials.create()`, a website can specify the type of attestation it requires. If a website indicates that it is not interested in attestation, then it can indicate that, and this is also the default if no preference is given.

## Authentication

The authentication flow consists of the following steps:

1. The user asks to sign into the website, for example by clicking a "Sign in" button in the website's UI.

2. The website front end makes an HTTP request to the server for a _challenge_, which is a long random number.

3. The website front end calls `navigator.credentials.get()`, passing in the challenge sent by the server in step 2, and various other parameters, including:

   - Whether and how the user needs to be involved
   - The domain for which the authentication will be valid
   - Whether the website requires or prefers the user to be verified, for example using biometrics or a PIN.
   - An identifier for the credential public key to use, if it is known. This can help in finding the authenticator to use.

4. The `navigator.credentials.get()` implementation asks the appropriate authenticator to create the cryptographic objects we'll need to authenticate the user.

## WebAuthn glossary

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
