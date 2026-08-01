(ns security.tickets
  "Policy-to-ticket generator.
  Input CSV columns: policy_id, title, control, description, owner, risk_level, source.
  Output CSV: ticket_id, title, description, priority, due_days, assignee, source.
  Pure template functions; I/O in -main."
  (:require [clojure.string :as str]
            [security.core :as core]))

(def priorities
  {"critical" "P1" "high" "P2" "medium" "P3" "low" "P4"})

(def due-days
  {"critical" 7 "high" 14 "medium" 30 "low" 45})

(def acceptance-criteria
  ["Evidence of control review is recorded and dated"
   "Deviations or exceptions are documented and approved"
   "Access review results are attached before closure"])

(defn ticket
  "Generates a ticket map from one policy row."
  [{:keys [policy_id title control description owner risk_level source] :as p}]
  (let [risk (core/lc risk_level)
        priority (get priorities risk "P3")
        body (str/join "\n"
                       (concat [(str "Control: " control)
                                (str "Description: " description)
                                "Acceptance criteria:"]
                               (map #(str "- " %) acceptance-criteria)
                               [(str "Source: " source)]))]
    (assoc p
           :ticket_id (str "POL-" policy_id)
           :ticket_title (str "[POLICY REVIEW] " title)
           :description body
           :priority priority
           :due_days (get due-days risk 30)
           :assignee owner)))

(defn generate-tickets
  "Generates tickets for all policies."
  [policies]
  (map ticket policies))

(defn -main
  [& args]
  (let [[in-file out-file] args]
    (when-not in-file
      (binding [*out* *err*]
        (println "usage: bb -m security.tickets <in.csv> [out.csv]")
        (System/exit 1)))
    (let [out (core/maps->csv (generate-tickets (core/csv->maps (slurp in-file))))]
      (if out-file
        (spit out-file out)
        (println out)))))
