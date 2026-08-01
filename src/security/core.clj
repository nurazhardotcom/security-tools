(ns security.core
  "Shared I/O and data helpers for all security automation tools.
  Everything here is a pure function; all I/O happens only in -main entry points."
  (:require [clojure.string :as str]))

;; ---------------------------------------------------------------------------
;; CSV parsing / writing (self-contained, no external deps)
;; ---------------------------------------------------------------------------

(defn read-csv-rows
  "Parses CSV text into a seq of rows, each a vector of string fields.
  RFC 4180 quoting: fields may be wrapped in double quotes, a pair of quotes
  inside a quoted field is an escaped quote, and commas/newlines inside quoted
  fields are preserved. Lenient extras: blank lines are skipped, a trailing
  newline does not produce an extra empty row, CRLF line endings are accepted,
  and unclosed quotes / stray chars after a closing quote are kept literally."
  [csv-text]
  (if (nil? csv-text)
    []
    (let [n (count csv-text)]
      (loop [i 0
             state :field
             field ""
             row []
             rows []
             touched false]
        (if (>= i n)
          (let [row (if (or touched (not (str/blank? field)) (seq row))
                      (conj row field)
                      row)]
            (if (seq row) (conj rows row) rows))
          (let [c (.charAt csv-text i)
                sep? (or (= c \newline) (= c \return))
                crlf? (and (= c \return) (< (inc i) n) (= \newline (.charAt csv-text (inc i))))
                nxt (if crlf? (+ i 2) (inc i))
                finish-row (fn [rows]
                             (let [full-row (conj row field)]
                               (if (and (= full-row [""]) (not touched))
                                 rows
                                 (conj rows full-row))))]
            (case state
              :field
              (cond
                (= c \")
                (recur nxt :quoted field row rows true)

                (= c \,)
                (recur nxt :field "" (conj row field) rows touched)

                sep?
                (recur nxt :field "" [] (finish-row rows) false)

                :else
                (recur nxt :field (str field c) row rows true))

              :quoted
              (if (= c \")
                (recur nxt :after-quote field row rows touched)
                (recur nxt :quoted (str field c) row rows touched))

              :after-quote
              (cond
                (= c \")
                (recur nxt :quoted (str field \") row rows touched)

                (= c \,)
                (recur nxt :field "" (conj row field) rows touched)

                sep?
                (recur nxt :field "" [] (finish-row rows) false)

                :else
                (recur nxt :field (str field c) row rows touched)))))))))

(defn field->csv
  "Encodes one field for CSV output, quoting when necessary."
  [v]
  (let [s (str v)]
    (if (or (str/includes? s ",")
            (str/includes? s "\"")
            (str/includes? s "\n")
            (str/includes? s "\r"))
      (str "\"" (str/replace s "\"" "\"\"") "\"")
      s)))

(defn rows->csv
  "Serializes a seq of rows (each a seq of values) to CSV text."
  [rows]
  (str/join "\n" (map #(str/join "," (map field->csv %)) rows)))

(defn csv->maps
  "Parses CSV text into a seq of maps keyed by the (trimmed) header row."
  [csv-text]
  (let [rows (read-csv-rows csv-text)]
    (when (seq rows)
      (let [[header & data] rows
            ks (mapv #(keyword (str/trim %)) header)]
        (mapv #(zipmap ks %) data)))))

(defn maps->csv
  "Serializes a seq of maps to CSV text. Column order follows the keys of the
  first map, with any extra keys from later maps appended."
  [maps]
  (if (empty? maps)
    ""
    (let [headers (reduce (fn [acc m] (into acc (remove (set acc)) (keys m)))
                          (vec (keys (first maps)))
                          (rest maps))]
      (rows->csv (cons (mapv name headers)
                       (mapv #(mapv (fn [k] (get % k "")) headers) maps))))))

;; ---------------------------------------------------------------------------
;; Generic helpers
;; ---------------------------------------------------------------------------

(defn to-double
  "Parses a string/number to a double, returning nil when it cannot be parsed."
  [x]
  (when (and (some? x) (not (str/blank? (str x))))
    (try
      (Double/parseDouble (str/trim (str x)))
      (catch Exception _ nil))))

(defn lc
  "Lowercases a value for case-insensitive comparisons."
  [x]
  (str/lower-case (str x)))

(defn clamp
  "Clamps x into the inclusive [lo hi] range."
  [lo hi x]
  (min hi (max lo x)))

(defn round2
  "Rounds a number to two decimal places."
  [x]
  (/ (Math/round (* (double x) 100.0)) 100.0))

(defn blank?
  "True when x is nil, or its string form is blank."
  [x]
  (or (nil? x) (str/blank? (str x))))
