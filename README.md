# Emissary

Outsource user managment to an OIDC identity provider.

Emissary makes it easy to enable your application to act as an OIDC client. It is
identity provider-agnostic, meaning your application can use emissary to connect with any
spec-compliant identity provider for user management.

## Status

This is pre-alpha software currently used internally at Hypo. Expect breaking changes.

### Supported identity providers

Emissary aims to be 100% compliant with the [OIDC 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
and [OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) specifications, so it should
work with any spec-compliant identity provider. If you run into compatibility issues, pleas
file a ticket.

### Supported flows

| Flow | Supported? |
| ---- | ---------- |
| Authorization | Yes |
| Implicit | No |
| Hybrid | No |

(Learn more [here](https://openid.net/specs/openid-connect-core-1_0.html#Authentication).)

Please open an issue if you'd like to see support for an unsupported flow.

### Client authentication strategies

| Strategy | Supported? |
| -------- | ---------- |
| `client_secret_basic` | Yes |
| `client_secret_post` | No |
| `client_secret_jwt` | No |
| `private_key_jwt` | No |

(Learn more [here](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication).)

Please open an issue if you'd like to see support for an unsupported authentication strategy.

## Testing

To run Clojure tests:

```bash
clojure -M:test
```

To run ClojureScript tests:
(TODO)


## Development

To start Clojure and ClojureScript repls:

```
# In your shell
clojure -M:dev:cider

;; in emacs
cider-connect-clj

;; In your repl
(user/main)

;; in emacs
cider-connect-sibling-cljs

;; in your repl
(user/main)
```
