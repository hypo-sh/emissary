(ns clj-oidc.test-util
  (:require [buddy.core.keys :as ks]
            [buddy.sign.jwt :as jwt]
            [buddy.sign.jwk :as jwk])
  (:import [java.security KeyPairGenerator SecureRandom]))

(defn- generate-keypair-rsa
  []
  (let [kg (KeyPairGenerator/getInstance "RSA")]
    (.initialize kg
                 1024
                 (SecureRandom/getInstanceStrong))
    (.genKeyPair kg)))

(defn generate-jwk [kid]
  (let [pair (generate-keypair-rsa)]
    (merge
     (ks/jwk (.getPrivate pair) (.getPublic pair))
     {:kid kid})))

(defn test-sign [jwk kid claims]
  (jwt/sign claims (jwk/private-key jwk) {:alg :rs256
                                          :header
                                          {:kid kid}}))

(defn test-unsign [jwk jwt verify]
  (jwt/unsign jwt (jwk/public-key jwk) (merge {:alg :rs256} verify)))

(let [jwk (generate-jwk "abc")
      jwt (test-sign jwk "abc" {:iss "jake"})]
  (println
   (jwt/decode-header jwt))
  (test-unsign jwk jwt {:iss "jake"}))
