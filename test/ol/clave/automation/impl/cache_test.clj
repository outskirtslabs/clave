(ns ol.clave.automation.impl.cache-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation.impl.cache :as cache])
  (:import
   [java.time Duration Instant]))

;; Helper to create test bundles
(defn- make-bundle
  [{:keys [hash names not-before not-after ocsp-staple managed]
    :or {not-before (Instant/now)
         not-after (.plus (Instant/now) (Duration/ofDays 90))
         managed true}}]
  {:hash hash
   :names names
   :not-before not-before
   :not-after not-after
   :ocsp-staple ocsp-staple
   :managed managed})

(deftest cache-certificate-test
  (testing "adds to empty cache with proper index"
    (let [cache-atom (atom {:certs {} :index {} :capacity nil})
          bundle (make-bundle {:hash "abc123"
                               :names ["example.com" "www.example.com"]})]
      (cache/cache-certificate cache-atom bundle)
      (is (= {"abc123" bundle} (:certs @cache-atom)))
      (is (= {"example.com" ["abc123"] "www.example.com" ["abc123"]}
             (:index @cache-atom)))))

  (testing "preserves existing certificates"
    (let [bundle1 (make-bundle {:hash "abc123" :names ["example.com"]})
          bundle2 (make-bundle {:hash "def456" :names ["other.com"]})
          cache-atom (atom {:certs {"abc123" bundle1}
                            :index {"example.com" ["abc123"]}
                            :capacity nil})]
      (cache/cache-certificate cache-atom bundle2)
      (is (= {"abc123" bundle1 "def456" bundle2} (:certs @cache-atom)))
      (is (= {"example.com" ["abc123"] "other.com" ["def456"]} (:index @cache-atom)))))

  (testing "multiple certs for same domain accumulate in index"
    (let [bundle1 (make-bundle {:hash "abc123" :names ["example.com"]})
          bundle2 (make-bundle {:hash "def456" :names ["example.com"]})
          cache-atom (atom {:certs {"abc123" bundle1}
                            :index {"example.com" ["abc123"]}
                            :capacity nil})]
      (cache/cache-certificate cache-atom bundle2)
      (is (= {"abc123" bundle1 "def456" bundle2} (:certs @cache-atom)))
      (is (= #{"abc123" "def456"} (set (get-in @cache-atom [:index "example.com"])))))))

(deftest lookup-cert-test
  (testing "exact match returns certificate"
    (let [bundle (make-bundle {:hash "abc123" :names ["example.com"]})
          cache-atom (atom {:certs {"abc123" bundle}
                            :index {"example.com" ["abc123"]}})]
      (is (= bundle (cache/lookup-cert cache-atom "example.com")))))

  (testing "subdomain matches wildcard certificate"
    (let [bundle (make-bundle {:hash "abc123" :names ["*.example.com"]})
          cache-atom (atom {:certs {"abc123" bundle}
                            :index {"*.example.com" ["abc123"]}})]
      (is (= bundle (cache/lookup-cert cache-atom "foo.example.com")))
      (is (= bundle (cache/lookup-cert cache-atom "bar.example.com")))))

  (testing "returns nil when no match"
    (let [bundle (make-bundle {:hash "abc123" :names ["example.com"]})
          cache-atom (atom {:certs {"abc123" bundle}
                            :index {"example.com" ["abc123"]}})]
      (is (nil? (cache/lookup-cert cache-atom "other.com")))
      (is (nil? (cache/lookup-cert cache-atom "sub.example.com")))))

  (testing "exact match takes precedence over wildcard"
    (let [wildcard (make-bundle {:hash "wild" :names ["*.example.com"]})
          exact (make-bundle {:hash "exact" :names ["www.example.com"]})
          cache-atom (atom {:certs {"wild" wildcard "exact" exact}
                            :index {"*.example.com" ["wild"]
                                    "www.example.com" ["exact"]}})]
      (is (= exact (cache/lookup-cert cache-atom "www.example.com")))
      (is (= wildcard (cache/lookup-cert cache-atom "foo.example.com"))))))

(deftest remove-certificate-test
  (testing "removes cert and cleans up empty index entries"
    (let [bundle (make-bundle {:hash "abc123"
                               :names ["example.com" "www.example.com"]})
          cache-atom (atom {:certs {"abc123" bundle}
                            :index {"example.com" ["abc123"]
                                    "www.example.com" ["abc123"]}
                            :capacity nil})]
      (cache/remove-certificate cache-atom bundle)
      (is (= {:certs {} :index {} :capacity nil} @cache-atom))))

  (testing "preserves other certs sharing same domain in index"
    (let [bundle1 (make-bundle {:hash "abc123" :names ["example.com"]})
          bundle2 (make-bundle {:hash "def456" :names ["example.com"]})
          cache-atom (atom {:certs {"abc123" bundle1 "def456" bundle2}
                            :index {"example.com" ["abc123" "def456"]}
                            :capacity nil})]
      (cache/remove-certificate cache-atom bundle1)
      (is (= {"def456" bundle2} (:certs @cache-atom)))
      (is (= {"example.com" ["def456"]} (:index @cache-atom))))))

(deftest update-ocsp-staple-test
  (testing "updates staple in cached bundle"
    (let [bundle (make-bundle {:hash "abc123" :names ["example.com"]})
          cache-atom (atom {:certs {"abc123" bundle}
                            :index {"example.com" ["abc123"]}})
          new-staple {:response-bytes [1 2 3]}]
      (cache/update-ocsp-staple cache-atom "abc123" new-staple)
      (is (= new-staple (get-in @cache-atom [:certs "abc123" :ocsp-staple]))))))

(deftest newer-than-cache?-test
  (let [now (Instant/now)
        old-time (.minus now (Duration/ofDays 10))
        new-time (.minus now (Duration/ofDays 5))]
    (testing "true when stored is newer"
      (is (true? (cache/newer-than-cache? {:not-before new-time} {:not-before old-time}))))
    (testing "false when stored is older"
      (is (false? (cache/newer-than-cache? {:not-before old-time} {:not-before new-time}))))
    (testing "false when same age"
      (is (false? (cache/newer-than-cache? {:not-before new-time} {:not-before new-time}))))))

(deftest hash-certificate-test
  (let [cert1 [(.getBytes "cert-data-1" "UTF-8")]
        cert2 [(.getBytes "cert-data-2" "UTF-8")]]
    (testing "same data produces identical hash"
      (is (= (cache/hash-certificate cert1) (cache/hash-certificate cert1))))
    (testing "different data produces different hash"
      (is (not= (cache/hash-certificate cert1) (cache/hash-certificate cert2))))))

(deftest handle-command-result-test
  (testing "obtain success adds cert to cache"
    (let [bundle (make-bundle {:hash "new123" :names ["example.com"]})
          cache-atom (atom {:certs {} :index {} :capacity nil})]
      (cache/handle-command-result cache-atom
                                   {:command :obtain-certificate}
                                   {:status :success :bundle bundle})
      (is (= {"new123" bundle} (:certs @cache-atom)))
      (is (= {"example.com" ["new123"]} (:index @cache-atom)))))

  (testing "obtain failure leaves cache unchanged"
    (let [cache-atom (atom {:certs {} :index {} :capacity nil})]
      (cache/handle-command-result cache-atom
                                   {:command :obtain-certificate}
                                   {:status :error})
      (is (= {} (:certs @cache-atom)))))

  (testing "renew success replaces old cert with new"
    (let [old-bundle (make-bundle {:hash "old" :names ["example.com"]})
          new-bundle (make-bundle {:hash "new" :names ["example.com"]})
          cache-atom (atom {:certs {"old" old-bundle}
                            :index {"example.com" ["old"]}
                            :capacity nil})]
      (cache/handle-command-result cache-atom
                                   {:command :renew-certificate :bundle old-bundle}
                                   {:status :success :bundle new-bundle})
      (is (= {"new" new-bundle} (:certs @cache-atom)))
      (is (= {"example.com" ["new"]} (:index @cache-atom)))))

  (testing "renew failure leaves cache unchanged"
    (let [bundle (make-bundle {:hash "old" :names ["example.com"]})
          cache-atom (atom {:certs {"old" bundle}
                            :index {"example.com" ["old"]}
                            :capacity nil})]
      (cache/handle-command-result cache-atom
                                   {:command :renew-certificate :bundle bundle}
                                   {:status :error})
      (is (= {"old" bundle} (:certs @cache-atom)))))

  (testing "fetch-ocsp success updates staple"
    (let [bundle (make-bundle {:hash "abc" :names ["example.com"]})
          cache-atom (atom {:certs {"abc" bundle}
                            :index {"example.com" ["abc"]}
                            :capacity nil})
          staple {:response-bytes [1 2 3]}]
      (cache/handle-command-result cache-atom
                                   {:command :fetch-ocsp :bundle bundle}
                                   {:status :success :ocsp-response staple})
      (is (= staple (get-in @cache-atom [:certs "abc" :ocsp-staple])))))

  (testing "fetch-ocsp failure leaves cache unchanged"
    (let [bundle (make-bundle {:hash "abc" :names ["example.com"]})
          cache-atom (atom {:certs {"abc" bundle}
                            :index {"example.com" ["abc"]}
                            :capacity nil})]
      (cache/handle-command-result cache-atom
                                   {:command :fetch-ocsp :bundle bundle}
                                   {:status :error})
      (is (nil? (get-in @cache-atom [:certs "abc" :ocsp-staple]))))))

(deftest eviction-test
  (testing "evicts when at capacity"
    (let [b1 (make-bundle {:hash "h1" :names ["d1.com"]})
          b2 (make-bundle {:hash "h2" :names ["d2.com"]})
          b3 (make-bundle {:hash "h3" :names ["d3.com"]})
          b4 (make-bundle {:hash "h4" :names ["d4.com"]})
          cache-atom (atom {:certs {"h1" b1 "h2" b2 "h3" b3}
                            :index {"d1.com" ["h1"] "d2.com" ["h2"] "d3.com" ["h3"]}
                            :capacity 3})]
      (cache/cache-certificate cache-atom b4)
      (is (= 3 (count (:certs @cache-atom))))
      (is (contains? (:certs @cache-atom) "h4"))))

  (testing "no eviction under capacity"
    (let [b1 (make-bundle {:hash "h1" :names ["d1.com"]})
          b2 (make-bundle {:hash "h2" :names ["d2.com"]})
          cache-atom (atom {:certs {"h1" b1}
                            :index {"d1.com" ["h1"]}
                            :capacity 3})]
      (cache/cache-certificate cache-atom b2)
      (is (= 2 (count (:certs @cache-atom))))))

  (testing "no eviction when unlimited"
    (let [b1 (make-bundle {:hash "h1" :names ["d1.com"]})
          b2 (make-bundle {:hash "h2" :names ["d2.com"]})
          b3 (make-bundle {:hash "h3" :names ["d3.com"]})
          b4 (make-bundle {:hash "h4" :names ["d4.com"]})
          cache-atom (atom {:certs {"h1" b1 "h2" b2 "h3" b3}
                            :index {"d1.com" ["h1"] "d2.com" ["h2"] "d3.com" ["h3"]}
                            :capacity nil})]
      (cache/cache-certificate cache-atom b4)
      (is (= 4 (count (:certs @cache-atom))))))

  (testing "non-managed certs protected from eviction"
    (let [manual (make-bundle {:hash "manual" :names ["manual.com"] :managed false})
          b1 (make-bundle {:hash "h1" :names ["d1.com"]})
          b2 (make-bundle {:hash "h2" :names ["d2.com"]})
          b3 (make-bundle {:hash "h3" :names ["d3.com"]})
          cache-atom (atom {:certs {"manual" manual "h1" b1 "h2" b2}
                            :index {"manual.com" ["manual"] "d1.com" ["h1"] "d2.com" ["h2"]}
                            :capacity 3})]
      (cache/cache-certificate cache-atom b3)
      (let [certs (:certs @cache-atom)]
        (is (= 3 (count certs)))
        (is (contains? certs "manual"))
        (is (contains? certs "h3")))))

  (testing "update does not trigger eviction"
    (let [b1 (make-bundle {:hash "h1" :names ["d1.com"]})
          b2 (make-bundle {:hash "h2" :names ["d2.com"]})
          b3 (make-bundle {:hash "h3" :names ["d3.com"]})
          b1-updated (make-bundle {:hash "h1" :names ["d1.com"] :ocsp-staple {:updated true}})
          cache-atom (atom {:certs {"h1" b1 "h2" b2 "h3" b3}
                            :index {"d1.com" ["h1"] "d2.com" ["h2"] "d3.com" ["h3"]}
                            :capacity 3})]
      (cache/cache-certificate cache-atom b1-updated)
      (is (= 3 (count (:certs @cache-atom))))
      (is (= {:updated true} (get-in @cache-atom [:certs "h1" :ocsp-staple]))))))

(deftest concurrency-test
  (testing "concurrent updates to different domains"
    (let [initial (make-bundle {:hash "initial" :names ["initial.com"]})
          cache-atom (atom {:certs {"initial" initial}
                            :index {"initial.com" ["initial"]}
                            :capacity nil})
          bundles (mapv #(make-bundle {:hash (str "h" %) :names [(str "d" % ".com")]})
                        (range 100))
          futures (mapv #(future (cache/cache-certificate cache-atom %)) bundles)]
      (run! deref futures)
      (let [{:keys [certs index]} @cache-atom]
        (is (= 101 (count certs)))
        (is (= 101 (count index)))
        (is (every? (fn [[h b]] (= h (:hash b))) certs)))))

  (testing "concurrent updates to same domain"
    (let [cache-atom (atom {:certs {} :index {} :capacity nil})
          bundles (mapv #(make-bundle {:hash (str "h" %) :names ["shared.com"]})
                        (range 50))
          futures (mapv #(future (cache/cache-certificate cache-atom %)) bundles)]
      (run! deref futures)
      (let [{:keys [certs index]} @cache-atom]
        (is (= 50 (count certs)))
        (is (= 50 (count (get index "shared.com"))))
        (is (every? #(contains? certs %) (get index "shared.com")))))))