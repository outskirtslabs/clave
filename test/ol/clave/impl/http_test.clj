(ns ol.clave.impl.http-test
  (:require
   [ol.clave.impl.commands :as commands]
   [ol.clave.impl.http :as http]
   [ol.clave.impl.test-util :refer [http-client-opts] :as util]
   [clojure.test :refer [deftest is testing use-fixtures]])
  (:import
   [java.time Duration Instant]))

((requiring-resolve 'hashp.install/install!))

(use-fixtures :once util/pebble-fixture)

(deftest get-nonce-test
  (let [[session _] (commands/new-session "https://localhost:14000/dir" {:http-client http-client-opts})
        [session _] (commands/load-directory session)
        [_ nonce] (http/get-nonce session {:cancel-token nil})]
    (is (string? nonce))))

(deftest header-normalization-case-insensitive
  (testing "normalize-headers lowercases keys"
    (let [normalized (@#'ol.clave.impl.http/normalize-headers {"Replay-Nonce" "abc"})]
      (is (= {"replay-nonce" "abc"} normalized)))))

(deftest header-normalization-seq-input
  (testing "normalize-headers handles sequence of pairs"
    (let [normalized (@#'ol.clave.impl.http/normalize-headers [["Replay-Nonce" "abc"]
                                                               [:cache-control "no-store"]])]
      (is (= {"replay-nonce" "abc"
              "cache-control" "no-store"}
             normalized)))))

(deftest get-header-case-insensitive
  (testing "get-header works regardless of header case"
    (let [resp {:headers {"replay-nonce" "abc"}}]
      (is (= "abc" (http/get-header resp "Replay-Nonce")))
      (is (= "abc" (http/get-header resp "replay-nonce"))))))

(deftest parse-http-time-variants
  (let [expected (Instant/parse "2015-10-21T07:28:00Z")]
    (testing "IMF-fixdate format"
      (is (= expected
             (http/parse-http-time "Wed, 21 Oct 2015 07:28:00 GMT"))))
    (testing "Obsolete RFC 850 format"
      (is (= expected
             (http/parse-http-time "Wednesday, 21-Oct-15 07:28:00 GMT"))))
    (testing "ANSI C asctime format"
      (is (= expected
             (http/parse-http-time "Wed Oct 21 07:28:00 2015"))))
    (testing "Invalid input yields nil"
      (is (nil? (http/parse-http-time "not-a-date"))))
    (testing "Blank input yields nil"
      (is (nil? (http/parse-http-time "   "))))))

(deftest retry-after-time-parsing
  (let [baseline (Instant/parse "2025-10-29T12:00:00Z")
        date-header "Wed, 29 Oct 2025 11:59:00 GMT"]
    (with-redefs [ol.clave.impl.http/now (fn [] baseline)]
      (testing "Delta-seconds header uses response Date baseline"
        (let [resp {:headers {"retry-after" "30"
                              "date" date-header}}
              expected (Instant/parse "2025-10-29T11:59:30Z")]
          (is (= expected (http/retry-after-header->instant resp)))
          (is (= expected (http/retry-after-time resp)))))
      (testing "Delta-seconds without Date falls back to now"
        (let [resp {:headers {"retry-after" "45"}}
              expected (Instant/parse "2025-10-29T12:00:45Z")]
          (is (= expected (http/retry-after-header->instant resp)))
          (is (= expected (http/retry-after-time resp)))))
      (testing "HTTP-date header"
        (let [resp {:headers {"retry-after" "Wed, 21 Oct 2015 07:28:00 GMT"}}
              expected (Instant/parse "2015-10-21T07:28:00Z")]
          (is (= expected (http/retry-after-header->instant resp)))
          (is (= expected (http/retry-after-time resp)))))
      (testing "Invalid header produces nil"
        (let [resp {:headers {"retry-after" "later maybe"}}]
          (is (nil? (http/retry-after-header->instant resp)))
          (is (nil? (http/retry-after-time resp)))))
      (testing "Missing header produces nil"
        (let [resp {:headers {}}]
          (is (nil? (http/retry-after-header->instant resp)))
          (is (nil? (http/retry-after-time resp))))))))

(deftest retry-after-duration-calculation
  (let [future-now (Instant/parse "2015-10-21T07:27:00Z")
        past-now (Instant/parse "2015-10-21T07:29:00Z")
        header "Wed, 21 Oct 2015 07:28:00 GMT"
        fallback (Duration/ofSeconds 5)
        delta-now (Instant/parse "2025-10-29T12:00:00Z")
        delta-header "Wed, 29 Oct 2025 12:00:00 GMT"]
    (testing "Delta seconds uses Date baseline to build target instant"
      (with-redefs [ol.clave.impl.http/now (fn [] delta-now)]
        (is (= (Duration/ofSeconds 30)
               (http/retry-after {:headers {"retry-after" "30"
                                            "date" delta-header}}
                                 fallback)))))
    (testing "Future retry-after yields positive duration"
      (with-redefs [ol.clave.impl.http/now (fn [] future-now)]
        (is (= (Duration/ofSeconds 60)
               (http/retry-after {:headers {"retry-after" header}} fallback)))))
    (testing "Past retry-after collapses to zero"
      (with-redefs [ol.clave.impl.http/now (fn [] past-now)]
        (is (= Duration/ZERO
               (http/retry-after {:headers {"retry-after" header}} fallback)))))
    (testing "Invalid header uses fallback"
      (with-redefs [ol.clave.impl.http/now (fn [] future-now)]
        (is (= fallback
               (http/retry-after {:headers {"retry-after" "soon"}} fallback)))))))
