(ns ol.clave.impl.coredns-harness
  (:require
   [babashka.fs :as fs]
   [babashka.process :as p]
   [clojure.string :as str])
  (:import
   [java.net InetSocketAddress ServerSocket Socket]))

(defn allocate-port
  []
  (with-open [socket (ServerSocket. 0)]
    (.getLocalPort socket)))

(defn write-files!
  [directory files]
  (doseq [[path content] files]
    (spit (str (fs/path directory path)) content)))

(defn wait-ready!
  [process port]
  (let [deadline (+ (System/currentTimeMillis) 5000)]
    (loop []
      (let [ready? (try
                     (with-open [socket (Socket.)]
                       (.connect socket (InetSocketAddress. "127.0.0.1" (int port)) 100)
                       true)
                     (catch Exception _
                       false))]
        (cond
          ready? true
          (>= (System/currentTimeMillis) deadline)
          (throw (ex-info "CoreDNS did not become ready"
                          {:port port
                           :process process}))
          :else
          (do
            (Thread/sleep 25)
            (recur)))))))

(defn with-coredns
  [{:keys [corefile files command]} f]
  (let [directory (fs/create-temp-dir {:prefix "clave-coredns-"})]
    (try
      (let [port (allocate-port)
            command (or command (System/getProperty "clave.test.coredns") "coredns")
            replace-port #(str/replace % "{{PORT}}" (str port))
            corefile-path (fs/path directory "Corefile")
            output-path (fs/path directory "coredns.log")]
        (write-files! directory (update-vals files replace-port))
        (spit (str corefile-path) (replace-port corefile))
        (let [process (p/process [command "-conf" (str corefile-path)]
                                 {:dir (str directory)
                                  :out (str output-path)
                                  :err :out})]
          (try
            (wait-ready! process port)
            (f {:port port
                :resolver (str "127.0.0.1:" port)
                :directory directory
                :process process
                :output-path output-path})
            (finally
              (p/destroy process)))))
      (finally
        (fs/delete-tree directory {:force true})))))
