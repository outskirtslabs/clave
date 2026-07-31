(ns ol.clave.impl.dns-server
  (:require
   [clojure.string :as str])
  (:import
   [java.io ByteArrayOutputStream]
   [java.net DatagramPacket DatagramSocket InetSocketAddress SocketException]
   [java.nio.charset StandardCharsets]
   [java.util Arrays]))

(defn write-u16!
  [^ByteArrayOutputStream out n]
  (.write out (bit-and (unsigned-bit-shift-right n 8) 0xff))
  (.write out (bit-and n 0xff)))

(defn write-u32!
  [^ByteArrayOutputStream out n]
  (.write out (bit-and (unsigned-bit-shift-right n 24) 0xff))
  (.write out (bit-and (unsigned-bit-shift-right n 16) 0xff))
  (.write out (bit-and (unsigned-bit-shift-right n 8) 0xff))
  (.write out (bit-and n 0xff)))

(defn write-bytes!
  [^ByteArrayOutputStream out ^bytes value]
  (.write out value 0 (alength value)))

(defn read-u16
  [^bytes message offset]
  (bit-or (bit-shift-left (bit-and (aget message offset) 0xff) 8)
          (bit-and (aget message (inc offset)) 0xff)))

(defn dns-name-bytes
  ^bytes [name]
  (let [out (ByteArrayOutputStream.)]
    (doseq [label (str/split (str/replace name #"\.$" "") #"\.")]
      (let [label-bytes (.getBytes ^String label StandardCharsets/US_ASCII)]
        (.write out (alength label-bytes))
        (write-bytes! out label-bytes)))
    (.write out 0)
    (.toByteArray out)))

(defn question
  [^bytes message]
  (loop [offset 12
         labels []]
    (let [length (bit-and (aget message offset) 0xff)]
      (if (zero? length)
        (let [type-offset (inc offset)]
          {:name (str (str/join "." labels) ".")
           :type (read-u16 message type-offset)
           :end (+ type-offset 4)})
        (let [start (inc offset)
              next-offset (+ start length)]
          (recur next-offset
                 (conj labels (String. message start length StandardCharsets/US_ASCII))))))))

(defn soa-data
  ^bytes [zone]
  (let [out (ByteArrayOutputStream.)]
    (write-bytes! out (dns-name-bytes (str "ns." zone)))
    (write-bytes! out (dns-name-bytes (str "hostmaster." zone)))
    (doseq [value [1 60 30 3600 30]]
      (write-u32! out value))
    (.toByteArray out)))

(defn response
  ^bytes [zone ^bytes query]
  (let [{:keys [name type end]} (question query)
        answer? (and (= type 6) (= (str/lower-case name) (str/lower-case zone)))
        out (ByteArrayOutputStream.)]
    (write-u16! out (read-u16 query 0))
    (write-u16! out 0x8180)
    (write-u16! out 1)
    (write-u16! out (if answer? 1 0))
    (write-u16! out 0)
    (write-u16! out 0)
    (write-bytes! out (Arrays/copyOfRange query 12 (int end)))
    (when answer?
      (let [rdata (soa-data zone)]
        (write-bytes! out (dns-name-bytes name))
        (write-u16! out 6)
        (write-u16! out 1)
        (write-u32! out 30)
        (write-u16! out (alength rdata))
        (write-bytes! out rdata)))
    (.toByteArray out)))

(defn start!
  [zone]
  (let [socket (DatagramSocket. nil)
        _ (.setReuseAddress socket true)
        _ (.bind socket (InetSocketAddress. "127.0.0.1" 0))
        running (atom true)
        events (atom [])
        thread (Thread/startVirtualThread
                ^Runnable
                (fn []
                  (while @running
                    (try
                      (let [buffer (byte-array 4096)
                            packet (DatagramPacket. buffer (alength buffer))]
                        (.receive socket packet)
                        (let [query (Arrays/copyOf buffer (.getLength packet))
                              answer (response zone query)]
                          (swap! events conj (question query))
                          (.send socket (DatagramPacket. answer
                                                         (alength answer)
                                                         (.getAddress packet)
                                                         (.getPort packet)))))
                      (catch SocketException _)))))]
    {:socket socket
     :thread thread
     :running running
     :events events
     :port (.getLocalPort socket)}))

(defn stop!
  [{:keys [^DatagramSocket socket ^Thread thread running]}]
  (reset! running false)
  (.close socket)
  (.join thread 1000))
