# Authentication

Authentication is the process of verifying that an entity - such as a user of a website - is who they claim to be. You'll most likely need to think about authentication if you want users to sign into your website.

If users can sign into your website, there are typically things signed-in users can do, or data they can access, that you don't want to make generally available. For example, signed in users might be able to:

- Make use of a service they have paid for.
- Spend money.
- Access private personal or corporate information.
- Interact socially with others in the persona associated with the account.

All these abilities, and more, make user account access an important target for attackers. If an attacker is able to sign into your site by pretending to be a legitimate user, the attacker could access and exploit, for example, the user's private data, financial credentials, or confidental corporate secrets. They could also impersonate the user on your site, causing reputational and potentially financial damage.

In this set of guides we'll looks at the main techniques available for authenticating users on the web, and good practices for them.

- [Passwords](authentication/passwords)
- [One-time passwords](one-time-passwords)
- [Federated identity](federated-identity)
- [Web Authentication](web-authentication)
