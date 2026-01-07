(ns ol.clave.session-test
  "Unit tests for session validation and configuration."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.account :as account]
   [ol.clave.commands :as commands]
   [ol.clave.errors :as errors]
   [ol.clave.impl.test-util]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as specs]))

(deftest require-account-context-validates-session
  (testing "account operations require account-key in session"
    (let [bg-lease (lease/background)
          session {::specs/directory-url "https://localhost:14000/dir"
                   ::specs/nonces '()
                   ::specs/http {}
                   ::specs/directory {}
                   ::specs/account-kid "https://localhost:14000/account/123"
                   ::specs/poll-interval 5000
                   ::specs/poll-timeout 60000}
          account {::specs/contact ["mailto:test@example.com"]
                   ::specs/termsOfServiceAgreed true}]
      (is (thrown-with-error-type? errors/missing-account-context
                                   (commands/get-account bg-lease session account)))))

  (testing "account operations require account-kid in session"
    (let [bg-lease (lease/background)
          [_account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          session {::specs/directory-url "https://localhost:14000/dir"
                   ::specs/nonces '()
                   ::specs/http {}
                   ::specs/directory {}
                   ::specs/account-key account-key
                   ::specs/poll-interval 5000
                   ::specs/poll-timeout 60000}
          account {::specs/contact ["mailto:test@example.com"]
                   ::specs/termsOfServiceAgreed true}]
      (is (thrown-with-error-type? errors/missing-account-context
                                   (commands/get-account bg-lease session account))))))

(deftest set-polling-updates-session-defaults
  (let [session {::specs/poll-interval 5000 ::specs/poll-timeout 60000}]
    (is (= {::specs/poll-interval 1000 ::specs/poll-timeout 30000}
           (commands/set-polling session {:interval-ms 1000 :timeout-ms 30000}))
        "updates both keys")
    (is (= {::specs/poll-interval 2000 ::specs/poll-timeout 60000}
           (commands/set-polling session {:interval-ms 2000}))
        "updates only interval when timeout not provided")
    (is (= {::specs/poll-interval 5000 ::specs/poll-timeout 15000}
           (commands/set-polling session {:timeout-ms 15000}))
        "updates only timeout when interval not provided")
    (is (= session (commands/set-polling session {}))
        "empty opts returns session unchanged")))

(deftest find-account-by-key-requires-account-key
  (testing "find-account-by-key throws when session has no account key"
    (let [bg-lease (lease/background)
          session {::specs/directory-url "https://localhost:14000/dir"
                   ::specs/nonces '()
                   ::specs/http {}
                   ::specs/directory {::specs/newAccount "https://localhost:14000/sign-me-up"}
                   ::specs/poll-interval 5000
                   ::specs/poll-timeout 60000}]
      (is (thrown-with-error-type? errors/invalid-account-key
                                   (commands/find-account-by-key bg-lease session))))))
