(ns security.triage
  "Security findings triage assistant.
  Input CSV columns: finding_id, title, severity, cvss, asset_criticality,
  status, age_days.
  Output: input row + action, priority, due_hours, reason.
  Deterministic rule table; pure functions only, I/O in -main."
  (:require [security.core :as core]))

(defn triage-row
  "Applies the rule table to one finding, returning the row with action,
  priority, due_hours and reason. Earlier rules take precedence."
  [{:keys [severity asset_criticality status age_days cvss] :as f}]
  (let [sev (core/lc severity)
        crit (core/lc asset_criticality)
        cvss-n (or (core/to-double cvss) 0.0)
        age-n (or (core/to-double age_days) 0.0)]
    (assoc f
           :action
           (cond
             (= (core/lc status) "resolved") "auto-close"
             (or (= sev "critical") (>= cvss-n 9.0)) "escalate"
             (and (= sev "high") (= crit "critical")) "escalate"
             (= sev "high") "assign"
             (and (= sev "medium") (>= age-n 60.0)) "reassign"
             (= sev "medium") "assign"
             (= sev "low") "snooze"
             :else "review")
           :priority
           (cond
             (= (core/lc status) "resolved") "P5"
             (or (= sev "critical") (>= cvss-n 9.0)) "P1"
             (and (= sev "high") (= crit "critical")) "P1"
             (= sev "high") "P2"
             (and (= sev "medium") (>= age-n 60.0)) "P3"
             (= sev "medium") "P3"
             (= sev "low") "P5"
             :else "P4")
           :due_hours
           (cond
             (= (core/lc status) "resolved") 0
             (or (= sev "critical") (>= cvss-n 9.0)) 24
             (and (= sev "high") (= crit "critical")) 48
             (= sev "high") 72
             (and (= sev "medium") (>= age-n 60.0)) 168
             (= sev "medium") 336
             (= sev "low") 0
             :else 720)
           :reason
           (cond
             (= (core/lc status) "resolved") "Finding already resolved"
             (= sev "critical") "Critical severity requires immediate escalation"
             (>= cvss-n 9.0) (str "CVSS " cvss-n " meets critical threshold")
             (and (= sev "high") (= crit "critical")) "High severity on critical asset"
             (= sev "high") "High severity finding assigned for remediation"
             (and (= sev "medium") (>= age-n 60.0)) "Medium finding aging past 60 days"
             (= sev "medium") "Medium severity finding"
             (= sev "low") "Low severity, recheck on next cycle"
             :else "Manual review required"))))

(defn triage
  "Triage all findings."
  [findings]
  (map triage-row findings))

(defn -main
  [& args]
  (let [[in-file out-file] args]
    (when-not in-file
      (binding [*out* *err*]
        (println "usage: bb -m security.triage <in.csv> [out.csv]")
        (System/exit 1)))
    (let [out (core/maps->csv (triage (core/csv->maps (slurp in-file))))]
      (if out-file
        (spit out-file out)
        (println out)))))
