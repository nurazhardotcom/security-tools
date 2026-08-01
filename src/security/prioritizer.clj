(ns security.prioritizer
  "Vulnerability remediation prioritizer.
  Input CSV columns: cve, cvss, severity, exploit_poc, asset_criticality, exposure.
  Output: input row + score (0-10), priority band, due_in_days, rationale.
  Deterministic weighted scoring; pure functions only, I/O in -main."
  (:require [security.core :as core]))

(def severity-weights
  {"critical" 1.0 "high" 0.75 "medium" 0.5 "low" 0.25})

(def criticality-weights
  {"critical" 1.0 "high" 0.8 "medium" 0.6 "low" 0.4 "none" 0.0})

(def exploit-weights
  {"yes" 1.0 "true" 1.0 "no" 0.0 "unknown" 0.4})

(def exposure-weights
  {"internet" 1.0 "internal" 0.6 "limited" 0.3 "none" 0.0})

(def weights
  "Contribution of each factor to the final 0-10 score."
  {:cvss 0.50 :severity 0.25 :criticality 0.15 :exploit 0.05 :exposure 0.05})

(def bands
  "Priority bands keyed by minimum score."
  [[8.0 "critical"] [6.5 "high"] [4.0 "medium"] [0.0 "low"]])

(def due-days
  {"critical" 7 "high" 14 "medium" 30 "low" 60})

(defn weight-for
  "Looks up a weight table case-insensitively, defaulting to mid value 0.5."
  [table k]
  (get table (core/lc k) 0.5))

(defn score-finding
  "Computes the 0-10 remediation score for one finding map."
  [{:keys [cvss severity asset_criticality exploit_poc exposure]}]
  (let [cvss-n (or (core/to-double cvss) 0.0)
        sev (weight-for severity-weights severity)
        crit (weight-for criticality-weights asset_criticality)
        exp (weight-for exploit-weights exploit_poc)
        expo (weight-for exposure-weights exposure)]
    (core/round2
     (+ (* cvss-n (:cvss weights))
        (* 10.0 (:severity weights) sev)
        (* 10.0 (:criticality weights) crit)
        (* 10.0 (:exploit weights) exp)
        (* 10.0 (:exposure weights) expo)))))

(defn priority-band
  "Maps a score to its priority band."
  [score]
  (second (first (filter #(<= (first %) score) bands))))

(defn prioritize
  "Scores and sorts findings, attaching score, priority, due_in_days and rationale."
  [findings]
  (->> findings
       (map (fn [f]
              (let [score (score-finding f)
                    band (priority-band score)]
                (assoc f
                       :score (format "%.2f" (double score))
                       :priority band
                       :due_in_days (get due-days band)
                       :rationale (str "weighted score " (format "%.2f" (double score))
                                       " => " band)))))
       (sort-by (fn [f] (- (Double/parseDouble (:score f)))))))

(defn -main
  [& args]
  (let [[in-file out-file] args]
    (when-not in-file
      (binding [*out* *err*]
        (println "usage: bb -m security.prioritizer <in.csv> [out.csv]")
        (System/exit 1)))
    (let [findings (core/csv->maps (slurp in-file))
          results (prioritize findings)
          out (core/maps->csv results)]
      (if out-file
        (spit out-file out)
        (println out)))))
