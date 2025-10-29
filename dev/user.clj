(ns user
  (:require
   [ol.clave.account :as account]))
((requiring-resolve 'hashp.install/install!))

(comment
  (do
    (require
     '[portal.colors]
     '[portal.api :as p])
    (p/open {:theme :portal.colors/gruvbox})
    (add-tap p/submit)
    (require '[clj-reload.core :as clj-reload])
    (clj-reload/init {:dirs ["src" "dev" "test"]}))

  (clj-reload/reload)

  (clojure.repl.deps/sync-deps)
  ;;

  (require '[ol.clave.account :as account])
  (require '[ol.clave.impl.commands :as commands])
  (require '[ol.clave.impl.crypto :as crypto])
  (account/generate-keypair)

  (let [account (account/create "mailto:test@example.com" true)
        key (account/generate-keypair)]
    (spit "test/fixtures/test-account.edn" (account/serialize account key)))

  (account/deserialize (slurp "test/fixtures/test-account.edn"))
  (account/deserialize (slurp "test/fixtures/bad-account.edn"))
;
  )
