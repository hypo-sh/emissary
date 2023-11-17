# Changelog

All notable changes to this project will be documented in this file.

## [HEAD]

## Changed

- Changed arguments to `unsign-jwt`
- Removed `unsign-access-token`
- Changed arguments to `save-session!` callback

## [b2eebe3321ededc59abea8be6989daa1bde63b09]

### Changed

#### Config

- Renamed `:openid-config-uri` to `:issuer`
- `:issuer` should no longer include the `.well-known/openid-configuration` suffix
- Renamed `:aud` to `:audience`
- Renamed `:post-login-redirect-uri-fn` to `:login-success-redirect-uri-fn`
- Renamed `:tokens-request-failure-redirect-uri-fn` to `:login-failure-redirect-uri-fn`
- Renamed `:post-logout-redirect-uri` to `:logout-success-redirect-uri`

#### Other

- Login handler no longer validates access token
- Broke `unsign-token` into `unsign-access-token` and `unsign-id-token`
- Improved login failure error messaging

## [f59b5791583b15554ddcb29441a1474aed458d60]

### Added

- Add `:client-base-uri` to config. `tokens-request-failure-redirect-uri-fn` and
  `post-login-redirect-uri-fn` now each take this URI as an initial argument.

## [cd994050cabaa80b4ddc8ceb98ace6be61b50d9f]

### Changed

- Renamed `hypo.emissary/build-config` to `hypo.emissary/download-remote-config`

## [8db2f93c38e39c54bfe31026fec84ce2adadca6b]

### Fixed

- Fix function spec signature

## [30dcc41bc92f9d5d08fc4bcb3b20ce8d93fdf993]

### Added

 - Add `hypo.emissary.malli` ns and create spec for configs
 - Add `hypo.emissary/config->browser-config`
 - Add `:tokens-request-failure-redirect-uri-fn` to config map
 - Add `:post-login-redirect-uri-fn` to config map
 - Added two new dependencies:
   - `metosin/malli`
   - `com.github.eval/malli-select`

### Changed

 - Renamed `hypo.emissary/build-config` to `hypo.emissary/build-config`
 
## [f9b3abb778bf7c84d059ec03e862b4354dad55d6]

### Changed

 - Renamed `emissary.core` to `hypo.emissary`
 - Renamed `emissary.test-util` to `hypo.emissary.test-util`
 - Renamed `emissary.core-test` to `hypo.emissary-test`
 - Renamed `make-handle-oidc` to `make-authentication-redirect-handler`
 - Renamed `make-handle-logout` to `make-logout-handler`
