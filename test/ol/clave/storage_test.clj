(ns ol.clave.storage-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.lease :as lease]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file])
  (:import
   [java.nio.charset StandardCharsets]
   [java.nio.file FileVisitOption Files NoSuchFileException Path]
   [java.nio.file.attribute FileAttribute]
   [java.time Duration]
   [java.util Arrays]))

(set! *warn-on-reflection* true)

(defn- delete-recursively! [^Path p]
  (when (Files/exists p (make-array java.nio.file.LinkOption 0))
    (with-open [stream (Files/walk p (make-array FileVisitOption 0))]
      (->> (iterator-seq (.iterator stream))
           (sort-by #(.getNameCount ^Path %) >)
           (run! #(Files/deleteIfExists ^Path %))))))

(defn- bytes-filled
  ^bytes
  [^long n b]
  (let [arr (byte-array n)]
    (Arrays/fill arr (byte b))
    arr))

(defn- bytes-uniform?
  [^bytes bs b]
  (let [target (byte b)
        len (alength bs)]
    (loop [idx 0]
      (cond
        (>= idx len) true
        (= target (aget bs idx)) (recur (inc idx))
        :else false))))

(defn- lock-file ^Path [^Path root name]
  (-> root
      (.resolve "locks")
      (.resolve (str (storage/safe-key name) ".lock"))))

(defn- read-lock-meta [^Path filename]
  (let [s (String. (Files/readAllBytes filename) StandardCharsets/UTF_8)
        parts (str/split (str/trim s) #"\s+")]
    {:created-ms (Long/parseLong (first parts))
     :updated-ms (Long/parseLong (second parts))}))

(defn- write-lock-meta! [^Path filename created-ms updated-ms]
  (Files/createDirectories (.getParent filename) (make-array FileAttribute 0))
  (Files/write filename
               (.getBytes (str created-ms " " updated-ms "\n") StandardCharsets/UTF_8)
               ^"[Ljava.nio.file.OpenOption;"
               (into-array java.nio.file.OpenOption
                           [java.nio.file.StandardOpenOption/CREATE
                            java.nio.file.StandardOpenOption/WRITE
                            java.nio.file.StandardOpenOption/TRUNCATE_EXISTING])))

(deftest safe-key-sanitizes-components
  (testing "Safe key sanitization"
    (is (= "example.com" (storage/safe-key "example.com")))
    (is (= "wildcard_.example.com" (storage/safe-key "*.example.com")))
    (is (= "afoo" (storage/safe-key "a/../../../foo")))
    (is (= "bfoo" (storage/safe-key "b\\..\\..\\..\\foo")))
    (is (= "cfoo" (storage/safe-key "c/foo")))))

(deftest file-storage-rejects-traversal
  (let [dir (Path/of (test-util/temp-storage-dir) (make-array String 0))
        fs (file/file-storage {:root dir})
        l (lease/background)]
    (try
      (is (thrown? IllegalArgumentException
                   (storage/store! fs l "../bad" (.getBytes "x" StandardCharsets/UTF_8))))
      (finally
        (delete-recursively! dir)))))

(deftest file-storage-missing-key-errors
  (let [dir (Path/of (test-util/temp-storage-dir) (make-array String 0))
        fs (file/file-storage {:root dir})
        l (lease/background)]
    (try
      (is (thrown? NoSuchFileException (storage/load fs l "missing")))
      (is (thrown? NoSuchFileException (storage/stat fs l "missing")))
      (is (thrown? NoSuchFileException (storage/list fs l "missing" false)))
      (finally
        (delete-recursively! dir)))))

(deftest file-storage-list-semantics
  (let [dir (Path/of (test-util/temp-storage-dir) (make-array String 0))
        fs (file/file-storage {:root dir})
        l (lease/background)]
    (try
      (storage/store! fs l "a/file1" (.getBytes "x" StandardCharsets/UTF_8))
      (storage/store! fs l "a/b/file2" (.getBytes "y" StandardCharsets/UTF_8))
      (is (= #{"a/file1" "a/b"}
             (set (storage/list fs l "a" false))))
      (is (= #{"a/file1" "a/b" "a/b/file2"}
             (set (storage/list fs l "a" true))))
      (finally
        (delete-recursively! dir)))))

(deftest file-storage-delete-recursive
  (let [dir (Path/of (test-util/temp-storage-dir) (make-array String 0))
        fs (file/file-storage {:root dir})
        l (lease/background)]
    (try
      (storage/store! fs l "a/file1" (.getBytes "x" StandardCharsets/UTF_8))
      (storage/store! fs l "a/b/file2" (.getBytes "y" StandardCharsets/UTF_8))
      (storage/delete! fs l "a")
      (is (false? (storage/exists? fs l "a/file1")))
      (is (false? (storage/exists? fs l "a/b/file2")))
      (finally
        (delete-recursively! dir)))))

(deftest file-storage-stale-lock-is-reclaimed
  (let [dir (Path/of (test-util/temp-storage-dir) (make-array String 0))
        fs (file/file-storage {:root dir})
        l (lease/background)
        lock (lock-file dir "stale")
        stale-ms (- (System/currentTimeMillis) 15000)]
    (try
      (write-lock-meta! lock stale-ms stale-ms)
      (storage/lock! fs l "stale")
      (is (Files/exists lock (make-array java.nio.file.LinkOption 0)))
      (storage/unlock! fs l "stale")
      (finally
        (delete-recursively! dir)))))

(deftest file-storage-lock-freshener-updates-meta
  (let [dir (Path/of (test-util/temp-storage-dir) (make-array String 0))
        fs (file/file-storage {:root dir})
        l (lease/background)
        lock (lock-file dir "fresh")]
    (try
      (storage/lock! fs l "fresh")
      (let [start-updated (:updated-ms (read-lock-meta lock))
            done? (#'file/update-lockfile-freshness! lock)
            current-updated (:updated-ms (read-lock-meta lock))]
        (is (false? done?))
        (is (< start-updated current-updated)))
      (storage/unlock! fs l "fresh")
      (finally
        (delete-recursively! dir)))))

(deftest file-storage-empty-lockfile-is-reclaimed
  (let [dir (Path/of (test-util/temp-storage-dir) (make-array String 0))
        fs (file/file-storage {:root dir})
        l (lease/background)
        lock (lock-file dir "empty")]
    (try
      (Files/createDirectories (.getParent lock) (make-array FileAttribute 0))
      (Files/createFile lock (make-array FileAttribute 0))
      (with-redefs [file/sleep-with-lease! (fn [_ _] nil)]
        (let [[ok err] (#'file/obtain-lock! dir l "empty" 20)]
          (is (true? ok))
          (is (nil? err))))
      (is (Files/exists lock (make-array java.nio.file.LinkOption 0)))
      (storage/unlock! fs l "empty")
      (finally
        (delete-recursively! dir)))))

(deftest file-storage-list-respects-lease-cancellation
  (let [dir (Path/of (test-util/temp-storage-dir) (make-array String 0))
        fs (file/file-storage {:root dir})
        l (lease/background)
        [cancellable cancel] (lease/with-cancel (lease/background))]
    (try
      (storage/store! fs l "a/file1" (.getBytes "x" StandardCharsets/UTF_8))
      (storage/store! fs l "a/file2" (.getBytes "y" StandardCharsets/UTF_8))
      (cancel)
      (is (thrown? clojure.lang.ExceptionInfo
                   (storage/list fs cancellable "a" true)))
      (finally
        (delete-recursively! dir)))))

(deftest file-storage-atomic-write-no-partial-reads
  (let [dir (Path/of (test-util/temp-storage-dir) (make-array String 0))
        fs (file/file-storage {:root dir})
        l (lease/background)
        size (* 1024 1024)
        a (bytes-filled size 97)
        b (bytes-filled size 98)]
    (try
      (storage/store! fs l "atomic" a)
      (let [done (promise)]
        (future
          (try
            (storage/store! fs l "atomic" b)
            (deliver done :ok)
            (catch Throwable t
              (deliver done t))))
        (loop [i 0]
          (when (< i 25)
            (let [dat (storage/load fs l "atomic")]
              (is (= size (alength ^bytes dat)))
              (is (or (bytes-uniform? dat 97)
                      (bytes-uniform? dat 98))))
            (Thread/sleep 10)
            (recur (inc i))))
        (let [result @done]
          (when (instance? Throwable result)
            (throw result))))
      (finally
        (delete-recursively! dir)))))

(deftest file-storage-store-load
  (let [dir (Path/of (test-util/temp-storage-dir) (make-array String 0))
        fs (file/file-storage {:root dir})
        l (lease/background)]
    (try
      (storage/store! fs l "foo" (.getBytes "bar" java.nio.charset.StandardCharsets/UTF_8))
      (is (= "bar" (storage/load-string fs l "foo")))
      (finally
        (delete-recursively! dir)))))

(deftest file-storage-constructor-opts
  (let [dir (Path/of (test-util/temp-storage-dir) (make-array String 0))
        l (lease/background)]
    (try
      (testing "one-arg constructor accepts opts with :root"
        (let [fs (file/file-storage {:root dir})]
          (storage/store! fs l "foo" (.getBytes "bar" StandardCharsets/UTF_8))
          (is (= "bar" (storage/load-string fs l "foo")))))

      (testing "one-arg constructor requires a valid :root"
        (is (thrown-with-msg? clojure.lang.ExceptionInfo
                              #":root"
                              (file/file-storage {})))
        (is (thrown-with-msg? clojure.lang.ExceptionInfo
                              #":root"
                              (file/file-storage {:root :not-a-path}))))
      (finally
        (delete-recursively! dir)))))

(deftest file-storage-store-load-race
  (let [dir (Path/of (test-util/temp-storage-dir) (make-array String 0))
        fs (file/file-storage {:root dir})
        l (lease/background)
        size (* 4096 1024)
        a (bytes-filled size 97)
        b (bytes-filled size 98)
        done (promise)]
    (try
      (storage/store! fs l "foo" a)
      (future
        (try
          (storage/store! fs l "foo" b)
          (deliver done :ok)
          (catch Throwable t
            (deliver done t))))
      (let [dat (storage/load fs l "foo")
            result @done]
        (when (instance? Throwable result)
          (throw result))
        (is (= size (alength ^bytes dat)))
        (is (or (bytes-uniform? dat 97)
                (bytes-uniform? dat 98))))
      (finally
        (delete-recursively! dir)))))

(deftest file-storage-locking
  (let [dir (Path/of (test-util/temp-storage-dir) (make-array String 0))
        fs (file/file-storage {:root dir})
        l (lease/background)
        [cancelled cancel] (lease/with-cancel (lease/background))]
    (cancel)
    (try
      (storage/lock! fs l "foo")
      (with-redefs [file/lock-poll-interval (Duration/ofMillis 5)
                    file/sleep-with-lease! (fn [_ _] nil)]
        (is (false? (storage/try-lock! fs l "foo"))))
      (is (thrown? clojure.lang.ExceptionInfo
                   (storage/lock! fs cancelled "foo")))
      (storage/unlock! fs l "foo")
      (is (true? (storage/try-lock! fs l "foo")))
      (storage/unlock! fs l "foo")
      (finally
        (delete-recursively! dir)))))

(deftest first-path-test
  (testing "first-path extracts first from colon-separated list"
    (is (= "/var/lib/foo" (#'file/first-path "/var/lib/foo")))
    (is (= "/var/lib/foo" (#'file/first-path "/var/lib/foo:/var/lib/bar")))
    (is (= "/a" (#'file/first-path "/a:/b:/c")))
    (is (nil? (#'file/first-path "")))
    (is (nil? (#'file/first-path nil)))))

(deftest data-dir-test
  (testing "data-dir returns a non-empty string"
    (is (not-empty (file/data-dir))))

  (testing "data-dir with app-name returns a non-empty string"
    (is (not-empty (file/data-dir "myapp")))))
