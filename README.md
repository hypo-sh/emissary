# Emissary

Outsource user managment to an OIDC identity provider.

## Status

This is pre-alpha software currently used internally at Hypo. Expect breaking changes.

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
