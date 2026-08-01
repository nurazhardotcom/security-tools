(ns security.triage-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [security.triage :as t]))

(defn row [& {:as m}]
  (t/triage-row (merge {:finding_id "F-1" :title "t" :severity "" :cvss ""}
                       m)))

(deftest resolved
  (let [r (row :status "resolved")]
    (is (= "auto-close" (:action r)))
    (is (= "P5" (:priority r)))
    (is (= 0 (:due_hours r)))))

(deftest critical-severity
  (let [r (row :severity "critical" :cvss "5.0")]
    (is (= "escalate" (:action r)))
    (is (= "P1" (:priority r)))
    (is (= 24 (:due_hours r)))))

(deftest high-cvss
  (let [r (row :severity "medium" :cvss "9.1")]
    (is (= "escalate" (:action r)))
    (is (= 24 (:due_hours r)))
    (is (str/includes? (:reason r) "9.1"))))

(deftest high-on-critical-asset
  (let [r (row :severity "high" :asset_criticality "critical")]
    (is (= "escalate" (:action r)))
    (is (= "P1" (:priority r)))
    (is (= 48 (:due_hours r)))))

(deftest high-on-other-asset
  (let [r (row :severity "high" :asset_criticality "high")]
    (is (= "assign" (:action r)))
    (is (= "P2" (:priority r)))
    (is (= 72 (:due_hours r)))))

(deftest aging-medium
  (let [r (row :severity "medium" :age_days "75")]
    (is (= "reassign" (:action r)))
    (is (= "P3" (:priority r)))
    (is (= 168 (:due_hours r)))))

(deftest fresh-medium
  (let [r (row :severity "medium" :age_days "15")]
    (is (= "assign" (:action r)))
    (is (= "P3" (:priority r)))
    (is (= 336 (:due_hours r)))))

(deftest low
  (let [r (row :severity "low")]
    (is (= "snooze" (:action r)))
    (is (= "P5" (:priority r)))))

(deftest unknown-severity
  (let [r (row)]
    (is (= "review" (:action r)))
    (is (= "P4" (:priority r)))
    (is (= 720 (:due_hours r)))))
