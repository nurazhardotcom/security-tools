(ns security.classifier-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [security.classifier :as c]))

(defn req [& {:as m}]
  (c/classify-request (merge {:request_id "R-1" :requester "x" :role "user"
                              :privilege "" :justification "" :duration_days "1"
                              :emergency "no" :approver "boss"}
                             m)))

(deftest too-long-duration-denied
  (let [r (req :privilege "standard access" :justification "Quarterly tasks require it"
               :duration_days "95")]
    (is (= "deny" (:decision r)))
    (is (= "high" (:risk_level r)))
    (is (str/includes? (:reason r) "95"))))

(deftest missing-justification-escalated
  (let [r (req :privilege "standard access")]
    (is (= "escalate" (:decision r)))
    (is (= "high" (:risk_level r)))))

(deftest short-justification-escalated
  (let [r (req :privilege "standard access" :justification "Need it")]
    (is (= "escalate" (:decision r)))))

(deftest privileged-request-escalated
  (let [r (req :role "Server Admin" :privilege "root access"
               :justification "Patching vulnerability CVE-2026-0001")]
    (is (= "escalate" (:decision r)))
    (is (= "high" (:risk_level r)))))

(deftest emergency-with-ticket-approved
  (let [r (req :role "Server Admin" :privilege "root access"
               :justification "Incident I-4410 response" :duration_days "2"
               :emergency "yes")]
    (is (= "approve" (:decision r)))
    (is (= "high" (:risk_level r)))))

(deftest emergency-without-ticket-escalated
  (let [r (req :role "Server Admin" :privilege "root access"
               :justification "Something is broken on prod" :emergency "yes")]
    (is (= "escalate" (:decision r)))
    (is (= "high" (:risk_level r)))))

(deftest long-privileged-request-escalated
  (let [r (req :role "Dev" :privilege "all access on prod"
               :justification "Weekend deployment automation" :duration_days "10")]
    (is (= "escalate" (:decision r)))
    (is (= "high" (:risk_level r)))))

(deftest read-only-approved-low-risk
  (let [r (req :privilege "SELECT read-only" :justification "Quarterly report generation")]
    (is (= "approve" (:decision r)))
    (is (= "low" (:risk_level r))))
  (let [r (req :privilege "view logs" :justification "Debugging latency issue")]
    (is (= "approve" (:decision r)))))

(deftest standard-request-approved-medium-risk
  (let [r (req :privilege "deploy staging app"
               :justification "Nightly staging deployment" :role "Developer")]
    (is (= "approve" (:decision r)))
    (is (= "medium" (:risk_level r)))))

(deftest risk-keywords-are-lowercased
  (let [r (req :privilege "DOMAIN ADMIN rights"
               :justification "Quarterly password rotation" :duration_days "2")]
    (is (= "escalate" (:decision r)))))
