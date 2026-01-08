(ns ol.clave.authorization-integration-test
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.acme.commands :as commands]
   [ol.clave.errors :as errors]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as util]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as specs]))

(use-fixtures :once pebble/pebble-challenge-fixture)

(deftest get-authorization-includes-key-authorization
  (testing "get-authorization returns challenges with key authorization"
    (let [bg-lease (lease/background)
          session (util/fresh-session)
          identifiers [{:type "dns" :value "localhost"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order bg-lease session order-request)
          authz-url (first (::specs/authorizations order))
          [_session authz] (commands/get-authorization bg-lease session authz-url)
          http-challenge (challenge/find-by-type authz "http-01")]
      (is (= "pending" (::specs/status authz)))
      (is (string? (::specs/key-authorization http-challenge))))))

(deftest respond-challenge-validates-authorization
  (testing "respond-challenge triggers validation and poll-authorization returns valid"
    (let [bg-lease (lease/background)
          session (util/fresh-session)
          identifiers [{:type "dns" :value "localhost"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order bg-lease session order-request)
          authz-url (first (::specs/authorizations order))
          [session authz] (commands/get-authorization bg-lease session authz-url)
          http-challenge (challenge/find-by-type authz "http-01")
          token (challenge/token http-challenge)
          key-auth (challenge/key-authorization http-challenge (::specs/account-key session))]
      (pebble/challtestsrv-add-http01 token key-auth)
      (let [[session _challenge] (commands/respond-challenge bg-lease session http-challenge)
            session (commands/set-polling session {:timeout-ms 15000 :interval-ms 250})
            [_session updated] (commands/poll-authorization bg-lease session authz-url)]
        (is (= "valid" (::specs/status updated)))))))

(deftest respond-challenge-invalidates-authorization
  (testing "poll-authorization reports invalid when key authorization is wrong"
    (let [bg-lease (lease/background)
          session (util/fresh-session)
          identifiers [{:type "dns" :value "localhost"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order bg-lease session order-request)
          authz-url (first (::specs/authorizations order))
          [session authz] (commands/get-authorization bg-lease session authz-url)
          http-challenge (challenge/find-by-type authz "http-01")
          token (challenge/token http-challenge)]
      (pebble/challtestsrv-add-http01 token "bad-key-authorization")
      (let [[session _challenge] (commands/respond-challenge bg-lease session http-challenge)
            session (commands/set-polling session {:timeout-ms 15000 :interval-ms 250})]
        (is (thrown-with-error-type? errors/authorization-invalid
                                     (commands/poll-authorization bg-lease session authz-url)))))))

(deftest poll-authorization-times-out
  (testing "poll-authorization times out when no challenge is fulfilled"
    (let [bg-lease (lease/background)
          session (-> (util/fresh-session)
                      (commands/set-polling {:timeout-ms 1000 :interval-ms 100}))
          identifiers [{:type "dns" :value "localhost"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order bg-lease session order-request)
          authz-url (first (::specs/authorizations order))]
      (is (thrown-with-error-type? errors/authorization-timeout
                                   (commands/poll-authorization bg-lease session authz-url))))))

(deftest deactivate-authorization-sets-status
  (testing "deactivate-authorization transitions to deactivated"
    (let [bg-lease (lease/background)
          session (util/fresh-session)
          identifiers [{:type "dns" :value "localhost"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order bg-lease session order-request)
          authz-url (first (::specs/authorizations order))
          [session authz] (commands/get-authorization bg-lease session authz-url)
          [_session deactivated] (commands/deactivate-authorization bg-lease session authz)]
      (is (= "deactivated" (::specs/status deactivated))))))

(deftest poll-authorization-respects-lease-deadline
  (testing "poll-authorization times out at lease deadline even if session timeout is longer"
    (let [bg-lease (lease/background)
          session (-> (util/fresh-session)
                      (commands/set-polling {:interval-ms 100}))
          identifiers [{:type "dns" :value "localhost"}]
          [session order] (commands/new-order bg-lease session {::specs/identifiers identifiers})
          authz-url (first (::specs/authorizations order))
          [poll-lease cancel] (lease/with-timeout bg-lease 1000)
          start (System/currentTimeMillis)]
      (try
        (is (thrown-with-error-type? errors/authorization-timeout
                                     (commands/poll-authorization poll-lease session authz-url)))
        (let [elapsed (- (System/currentTimeMillis) start)]
          (is (< elapsed 3000)
              (str "Expected timeout around 1s (lease deadline), but took " elapsed "ms")))
        (finally
          (cancel))))))

(deftest poll-authorization-uses-session-defaults
  (testing "poll-authorization uses session poll-timeout when lease has no deadline"
    (let [bg-lease (lease/background)
          session (-> (util/fresh-session)
                      (commands/set-polling {:timeout-ms 500 :interval-ms 50}))
          identifiers [{:type "dns" :value "localhost"}]
          [session order] (commands/new-order bg-lease session {::specs/identifiers identifiers})
          authz-url (first (::specs/authorizations order))
          start (System/currentTimeMillis)]
      (is (thrown-with-error-type? errors/authorization-timeout
                                   (commands/poll-authorization bg-lease session authz-url)))
      (let [elapsed (- (System/currentTimeMillis) start)]
        (is (< elapsed 2000)
            (str "Expected timeout around 500ms (session default), but took " elapsed "ms"))))))
