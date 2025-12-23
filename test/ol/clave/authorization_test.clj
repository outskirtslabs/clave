(ns ol.clave.authorization-test
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.account :as account]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as commands]
   [ol.clave.errors :as errors]
   [ol.clave.impl.test-util :as util]
   [ol.clave.specs :as specs]))

(use-fixtures :each util/pebble-challenge-fixture)

(defn- fresh-session
  []
  (let [[acct key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
        [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                      {:http-client util/http-client-opts
                                                       :account-key key})
        [session _account] (commands/new-account session acct)]
    session))

(deftest get-authorization-includes-key-authorization
  (testing "get-authorization returns challenges with key authorization"
    (let [session (fresh-session)
          identifiers [{:type "dns" :value "localhost"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order session order-request)
          authz-url (first (::specs/authorizations order))
          [_session authz] (commands/get-authorization session authz-url)
          http-challenge (challenge/find-by-type authz "http-01")]
      (is (= "pending" (::specs/status authz)))
      (is (string? (::specs/key-authorization http-challenge))))))

(deftest respond-challenge-validates-authorization
  (testing "respond-challenge triggers validation and poll-authorization returns valid"
    (let [session (fresh-session)
          identifiers [{:type "dns" :value "localhost"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order session order-request)
          authz-url (first (::specs/authorizations order))
          [session authz] (commands/get-authorization session authz-url)
          http-challenge (challenge/find-by-type authz "http-01")
          token (challenge/token http-challenge)
          key-auth (challenge/key-authorization http-challenge (::specs/account-key session))]
      (util/challtestsrv-add-http01 token key-auth)
      (let [[session _challenge] (commands/respond-challenge session http-challenge)
            [_session updated] (commands/poll-authorization session authz-url
                                                            {:timeout-ms 15000
                                                             :interval-ms 250})]
        (is (= "valid" (::specs/status updated)))))))

(deftest respond-challenge-invalidates-authorization
  (testing "poll-authorization reports invalid when key authorization is wrong"
    (let [session (fresh-session)
          identifiers [{:type "dns" :value "localhost"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order session order-request)
          authz-url (first (::specs/authorizations order))
          [session authz] (commands/get-authorization session authz-url)
          http-challenge (challenge/find-by-type authz "http-01")
          token (challenge/token http-challenge)]
      (util/challtestsrv-add-http01 token "bad-key-authorization")
      (let [[session _challenge] (commands/respond-challenge session http-challenge)]
        (is (thrown-with-error-type? errors/authorization-invalid
                                     (commands/poll-authorization session authz-url
                                                                  {:timeout-ms 15000
                                                                   :interval-ms 250})))))))

(deftest poll-authorization-times-out
  (testing "poll-authorization times out when no challenge is fulfilled"
    (let [session (fresh-session)
          identifiers [{:type "dns" :value "localhost"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order session order-request)
          authz-url (first (::specs/authorizations order))]
      (is (thrown-with-error-type? errors/authorization-timeout
                                   (commands/poll-authorization session authz-url
                                                                {:timeout-ms 1000
                                                                 :interval-ms 100}))))))

(deftest poll-authorization-honors-max-attempts
  (testing "poll-authorization throws after max-attempts with :attempts in ex-data"
    (let [session (fresh-session)
          identifiers [{:type "dns" :value "localhost"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order session order-request)
          authz-url (first (::specs/authorizations order))
          ex (try
               (commands/poll-authorization session authz-url
                                            {:timeout-ms 60000
                                             :interval-ms 10
                                             :max-attempts 1})
               nil
               (catch clojure.lang.ExceptionInfo e e))]
      (is (= errors/authorization-timeout (:type (ex-data ex))))
      (is (= 1 (:attempts (ex-data ex)))
          "ex-data should include :attempts equal to max-attempts")))

  (testing "poll-authorization with max-attempts=3 makes exactly 3 attempts"
    (let [session (fresh-session)
          identifiers [{:type "dns" :value "localhost"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order session order-request)
          authz-url (first (::specs/authorizations order))
          ex (try
               (commands/poll-authorization session authz-url
                                            {:timeout-ms 60000
                                             :interval-ms 10
                                             :max-attempts 3})
               nil
               (catch clojure.lang.ExceptionInfo e e))]
      (is (= errors/authorization-timeout (:type (ex-data ex))))
      (is (= 3 (:attempts (ex-data ex)))
          "ex-data should include :attempts equal to max-attempts"))))

(deftest deactivate-authorization-sets-status
  (testing "deactivate-authorization transitions to deactivated"
    (let [session (fresh-session)
          identifiers [{:type "dns" :value "localhost"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order session order-request)
          authz-url (first (::specs/authorizations order))
          [session authz] (commands/get-authorization session authz-url)
          [_session deactivated] (commands/deactivate-authorization session authz)]
      (is (= "deactivated" (::specs/status deactivated))))))
