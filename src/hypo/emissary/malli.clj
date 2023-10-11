(ns hypo.emissary.malli
  (:require [malli.util :as mu]
            [dk.thinkcreate.malli-select :as ms]))

(def CompleteConfig
  [:map
   [:issuer string?]
   [:tokens-request-failure-redirect-uri-fn [:=> [:cat string? string? string? string?] string?]]
   [:post-login-redirect-uri-fn [:=> [:cat string? string?] string?]]
   [:client-base-uri string?]
   [:client-secret string?]
   [:redirect-uri string?]
   [:audience string?]
   [:client-id string?]
   [:insecure-mode? boolean?]
   [:scope [:set string?]]
   [:response-type [:set string?]]
   [:trusted-audiences [:set string?]]
   [:post-logout-redirect-uri string?]
   [:keys [:sequential
           [:map [:kid string?]]]]
   [:authorization-endpoint string?]
   [:token-endpoint string?]
   [:end-session-endpoint string?]])

(def InitialConfig
  (ms/select CompleteConfig
             [:issuer
              :client-secret
              :client-base-uri
              :redirect-uri
              :audience
              :client-id
              :insecure-mode?
              :scope
              :response-type
              :trusted-audiences
              :post-logout-redirect-uri
              :tokens-request-failure-redirect-uri-fn
              :post-login-redirect-uri-fn]))

(def BrowserConfig
  (mu/closed-schema
   (ms/select CompleteConfig
              [:redirect-uri
               :client-id
               :scope
               :response-type
               :authorization-endpoint])))
