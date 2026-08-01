(ns security.prioritizer-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [security.core :as core]
            [security.prioritizer :as p]))

(def base
  {:cve "CVE-2026-0001" :cvss "9.8" :severity "critical"
   :exploit_poc "yes" :asset_criticality "critical" :exposure "internet"})

(deftest score-finding-weights
  (testing "maxed-out finding scores 9.90"
    (is (= 9.9 (p/score-finding base))))
  (testing "moderate finding"
    (is (= 7.13 (p/score-finding {:cvss "7.5" :severity "high"
                                  :asset_criticality "high" :exploit_poc "no"
                                  :exposure "internal"}))))
  (testing "low finding"
    (is (= 3.53 (p/score-finding {:cvss "4.3" :severity "low"
                                  :asset_criticality "low" :exploit_poc "no"
                                  :exposure "limited"}))))
  (testing "unknown values default to mid weights"
    (is (= 6.5 (p/score-finding {:cvss "8.0" :severity "whatever"
                                 :asset_criticality "weird" :exploit_poc "?"
                                 :exposure "?"}))))
  (testing "missing cvss treated as 0"
    (is (= 5.0 (p/score-finding {:cvss "" :severity "critical"
                                 :asset_criticality "critical"
                                 :exploit_poc "yes" :exposure "internet"}))))
  (testing "case-insensitive severity"
    (is (= 9.9 (p/score-finding (assoc base :severity "CRITICAL"))))))

(deftest priority-bands
  (is (= "critical" (p/priority-band 8.0)))
  (is (= "critical" (p/priority-band 9.9)))
  (is (= "high" (p/priority-band 6.5)))
  (is (= "medium" (p/priority-band 4.0)))
  (is (= "low" (p/priority-band 3.99)))
  (is (= "low" (p/priority-band 0.0))))

(deftest prioritize-sorts-and-attaches
  (let [low-row (assoc base :cve "A" :cvss "2.0" :severity "low" :asset_criticality "low"
                       :exploit_poc "no" :exposure "none")
        high-row (assoc base :cve "B" :cvss "9.0")
        a (p/score-finding low-row)
        b (p/score-finding high-row)
        out (p/prioritize [low-row high-row])]
    (is (= ["B" "A"] (map :cve out)))
    (is (= (format "%.2f" (double b)) (:score (first out))))
    (is (= (format "%.2f" (double a)) (:score (second out))))
    (is (= "critical" (:priority (first out))))
    (is (= "low" (:priority (second out))))
    (is (= 7 (:due_in_days (first out))))
    (is (= 60 (:due_in_days (second out))))
    (is (str/includes? (:rationale (first out)) "critical"))))

(deftest sample-end-to-end
  (let [findings (core/csv->maps
                  (slurp "data/vulns.csv"))
        out (p/prioritize findings)]
    (is (= ["CVE-2026-0001" "CVE-2026-0006" "CVE-2026-0005" "CVE-2026-0002"
            "CVE-2026-0003" "CVE-2026-0004"]
           (map :cve out)))
    (is (apply >= (map #(Double/parseDouble (:score %)) out)))))
