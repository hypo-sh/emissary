# Changelog

All notable changes to this project will be documented in this file.

## [HEAD]

### Changed

 - Renamed `hypo.emissary/build-config` to `hypo.emissary/build-config`
 - Take two no dependencies:
   - `metosin/malli`
   - `com.github.eval/malli-select`
 - Add `hypo.emissary.malli` ns and create spec for configs
 - Add `hypo.emissary/config->browser-config`
 - Add `:authentication-error-redirect-fn` to config map

## [HEAD]

### Changed

 - Renamed `emissary.core` to `hypo.emissary`
 - Renamed `emissary.test-util` to `hypo.emissary.test-util`
 - Renamed `emissary.core-test` to `hypo.emissary-test`
 - Renamed `make-handle-oidc` to `make-authentication-redirect-handler`
 - Renamed `make-handle-logout` to `make-logout-handler`
