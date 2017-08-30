# dex - A federated OpenID Connect provider

![logo](Documentation/logos/dex-horizontal-color.png)

Dex is an identity service that uses [OpenID Connect][openid-connect] to drive authentication for other apps.

Dex is NOT a user-management system, but acts as a portal to other identity providers through "connectors." This lets dex defer authentication to LDAP servers, SAML providers, or established identity providers like GitHub, Google, and Active Directory. Clients write their authentication logic once to talk to dex, then dex handles the protocols for a given backend.

## ID Tokens

ID Tokens are an OAuth2 extension introduced by OpenID Connect and dex's primary feature. ID Tokens are [JSON Web Tokens][jwt-io] (JWTs) signed by dex and returned as part of the OAuth2 response that attest to the end user's identity. An example JWT might look like:

```
eyJhbGciOiJSUzI1NiIsImtpZCI6IjlkNDQ3NDFmNzczYjkzOGNmNjVkZDMyNjY4NWI4NjE4MGMzMjRkOTkifQ.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjU1NTYvZGV4Iiwic3ViIjoiQ2djeU16UXlOelE1RWdabmFYUm9kV0kiLCJhdWQiOiJleGFtcGxlLWFwcCIsImV4cCI6MTQ5Mjg4MjA0MiwiaWF0IjoxNDkyNzk1NjQyLCJhdF9oYXNoIjoiYmk5NmdPWFpTaHZsV1l0YWw5RXFpdyIsImVtYWlsIjoiZXJpYy5jaGlhbmdAY29yZW9zLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJncm91cHMiOlsiYWRtaW5zIiwiZGV2ZWxvcGVycyJdLCJuYW1lIjoiRXJpYyBDaGlhbmcifQ.OhROPq_0eP-zsQRjg87KZ4wGkjiQGnTi5QuG877AdJDb3R2ZCOk2Vkf5SdP8cPyb3VMqL32G4hLDayniiv8f1_ZXAde0sKrayfQ10XAXFgZl_P1yilkLdknxn6nbhDRVllpWcB12ki9vmAxklAr0B1C4kr5nI3-BZLrFcUR5sQbxwJj4oW1OuG6jJCNGHXGNTBTNEaM28eD-9nhfBeuBTzzO7BKwPsojjj4C9ogU4JQhGvm_l4yfVi0boSx8c0FX3JsiB0yLa1ZdJVWVl9m90XmbWRSD85pNDQHcWZP9hR6CMgbvGkZsgjG32qeRwUL_eNkNowSBNWLrGNPoON1gMg
```

ID Tokens contains standard claims assert which client app logged the user in, when the token expires, and the identity of the user.

```json
{
  "iss": "http://127.0.0.1:5556/dex",
  "sub": "CgcyMzQyNzQ5EgZnaXRodWI",
  "aud": "example-app",
  "exp": 1492882042,
  "iat": 1492795642,
  "at_hash": "bi96gOXZShvlWYtal9Eqiw",
  "email": "jane.doe@coreos.com",
  "email_verified": true,
  "groups": [
    "admins",
    "developers"
  ],
  "name": "Jane Doe"
}
```

Because these tokens are signed by dex and [contain standard-based claims][standard-claims] other services can consume them as service-to-service credentials. Systems that can already consume OpenID Connect ID Tokens issued by dex include:

* [Kubernetes][kubernetes]
* [AWS STS][aws-sts]

For details on how to request or validate an ID Token, see [_"Writing apps that use dex"_][using-dex].

## Kubernetes + dex

Dex's main production use is as an auth-N addon in CoreOS's enterprise Kubernetes solution, [Tectonic][tectonic]. Dex runs natively on top of any Kubernetes cluster using Third Party Resources and can drive API server authentication through the OpenID Connect plugin. Clients, such as the [Tectonic Console][tectonic-console] and `kubectl`, can act on behalf users who can login to the cluster through any identity provider dex supports.

More docs for running dex as a Kubernetes authenticator can be found [here](Documentation/kubernetes.md).

## Documentation

* [Getting started](Documentation/getting-started.md)
* [Intro to OpenID Connect](Documentation/openid-connect.md)
* [Writing apps that use dex][using-dex]
* [What's new in v2](Documentation/v2.md)
* [Custom scopes, claims, and client features](Documentation/custom-scopes-claims-clients.md)
* [Storage options](Documentation/storage.md)
* [gRPC API](Documentation/api.md)
* [Using Kubernetes with dex](Documentation/kubernetes.md)
* Identity provider logins
  * [LDAP](Documentation/ldap-connector.md)
  * [GitHub](Documentation/github-connector.md)
  * [GitLab](Documentation/gitlab-connector.md)
  * [SAML 2.0](Documentation/saml-connector.md)
  * [OpenID Connect](Documentation/oidc-connector.md) (includes Google, Salesforce, Azure, etc.)
* Client libraries
  * [Go][go-oidc]

## Reporting a security vulnerability

Due to their public nature, GitHub and mailing lists are NOT appropriate places for reporting vulnerabilities. Please refer to CoreOS's [security disclosure][disclosure] process when reporting issues that may be security related.

## Getting help

* For feature requests and bugs, file an [issue][issues].
* For general discussion about both using and developing dex, join the [dex-dev][dex-dev] mailing list.
* For more details on dex development plans, check out the GitHub [milestones][milestones].

[openid-connect]: https://openid.net/connect/
[standard-claims]: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
[using-dex]: Documentation/using-dex.md
[jwt-io]: https://jwt.io/
[kubernetes]: http://kubernetes.io/docs/admin/authentication/#openid-connect-tokens
[aws-sts]: https://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html
[tectonic]: https://tectonic.com/
[tectonic-console]: https://tectonic.com/enterprise/docs/latest/usage/index.html#tectonic-console
[go-oidc]: https://github.com/coreos/go-oidc
[issues]: https://github.com/coreos/dex/issues
[dex-dev]: https://groups.google.com/forum/#!forum/dex-dev
[milestones]: https://github.com/coreos/dex/milestones
[disclosure]: https://coreos.com/security/disclosure/
