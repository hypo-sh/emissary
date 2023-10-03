# Changelog

All notable changes to this project will be documented in this file.

## [HEAD]

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
