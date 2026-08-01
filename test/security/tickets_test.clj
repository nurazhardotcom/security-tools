(ns security.tickets-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [security.core :as core]
            [security.tickets :as t]))

(def policy
  {:policy_id "P-1" :title "User access reviews" :control "AC-1"
   :description "Quarterly review of user access, including contractors"
   :owner "iam-team" :risk_level "high" :source "NIST 800-53"})

(deftest ticket-shape
  (let [t (t/ticket policy)]
    (is (= "POL-P-1" (:ticket_id t)))
    (is (= "[POLICY REVIEW] User access reviews" (:ticket_title t)))
    (is (= "P2" (:priority t)))
    (is (= 14 (:due_days t)))
    (is (= "iam-team" (:assignee t)))))

(deftest description-template
  (let [t (t/ticket policy)
        body (:description t)]
    (is (str/includes? body "Control: AC-1"))
    (is (str/includes? body "Description: Quarterly review"))
    (is (str/includes? body "Acceptance criteria:"))
    (is (str/includes? body "- Evidence of control review is recorded and dated"))
    (is (str/includes? body "Source: NIST 800-53"))))

(deftest priority-mapping
  (is (= "P1" (:priority (t/ticket (assoc policy :risk_level "critical")))))
  (is (= "P2" (:priority (t/ticket (assoc policy :risk_level "high")))))
  (is (= "P3" (:priority (t/ticket (assoc policy :risk_level "medium")))))
  (is (= "P4" (:priority (t/ticket (assoc policy :risk_level "low")))))
  (is (= "P3" (:priority (t/ticket (assoc policy :risk_level "??")))))
  (is (= 7 (:due_days (t/ticket (assoc policy :risk_level "critical")))))
  (is (= 45 (:due_days (t/ticket (assoc policy :risk_level "low"))))))

(deftest csv-round-trip-preserves-multiline-description
  (let [tickets (t/generate-tickets [policy])
        csv (core/maps->csv tickets)
        back (core/csv->maps csv)]
    (is (= (:description (first tickets)) (:description (first back))))
    (is (= (:ticket_title (first tickets)) (:ticket_title (first back))))
    (is (= (:policy_id (first tickets)) (:policy_id (first back))))))
