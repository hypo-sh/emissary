(ns hypo.emissary.malli)

(def EmissaryConfigSchema
  [:map
   [:openid-config-uri string?]
   [:redirect-uri string?]
   [:aud string?]
   [:iss string?]
   [:client-id string?]
   [:insecure-mode? boolean?]
   [:scope [:set string?]]
   [:response-type [:set string?]]
   [:trusted-audiences [:set string?]]
   [:post-logout-redirect-uri string?]])
