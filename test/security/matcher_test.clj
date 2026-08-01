(ns security.matcher-test
  (:require [clojure.test :refer [deftest is testing]]
            [security.core :as core]
            [security.matcher :as m]))

(def roles
  [{:role_id "R-DBA" :role_title "database administrator"
    :keywords "dba db sql oracle database admin"}
   {:role_id "R-ADM" :role_title "server administrator"
    :keywords "linux unix server admin root sudo"}
   {:role_id "R-SEC" :role_title "security analyst"
    :keywords "security soc incident siem threat analyst"}
   {:role_id "R-DEV" :role_title "developer"
    :keywords "developer code deploy ci cd app"}
   {:role_id "R-NET" :role_title "network engineer"
    :keywords "network firewall router vlan switch"}
   {:role_id "R-IA" :role_title "identity analyst"
    :keywords "identity iam access review pim pam"}])

(deftest tokens-normalization
  (is (= ["linux" "server" "admin"] (m/tokens "Linux Server Admin")))
  (is (= [] (m/tokens "")))
  (is (= [] (m/tokens nil))))

(deftest role-score-basics
  (let [j (m/tokens "Database Administrator")
        s (m/role-score j (first roles))]
    (is (= "R-DBA" (:role_id s)))
    (is (= ["database"] (:matched s)))
    (is (= 0.42 (:score s)))))

(deftest exact-match-is-strong
  (let [job (m/match-job roles {:user "alice" :title "Database Administrator"})]
    (is (= "R-DBA" (:best_role job)))
    (is (= "database" (:matched_keywords job)))
    (is (= "moderate" (:confidence job)))
    (is (= "0.42" (:score job)))))

(deftest sample-jobs
  (testing "linux admin"
    (let [job (m/match-job roles {:user "bob" :title "Linux Server Admin"})]
      (is (= "R-ADM" (:best_role job)))
      (is (= "linux server admin" (:matched_keywords job)))
      (is (= "0.45" (:score job)))))
  (testing "security analyst"
    (let [job (m/match-job roles {:user "carol" :title "Security Analyst"})]
      (is (= "R-SEC" (:best_role job)))
      (is (= "security analyst" (:matched_keywords job)))
      (is (= "0.53" (:score job)))))
  (testing "identity analyst matches R-IA"
    (let [job (m/match-job roles {:user "frank"
                                  :title "Identity and Access Management Analyst"})]
      (is (= "R-IA" (:best_role job)))
      (is (= "identity access" (:matched_keywords job)))
      (is (= "0.35" (:score job)))
      (is (= "moderate" (:confidence job)))))
  (testing "weak match still returns a best role"
    (let [job (m/match-job roles {:user "dave" :title "Senior Developer"})]
      (is (= "R-DEV" (:best_role job)))
      (is (= "0.27" (:score job)))
      (is (= "weak" (:confidence job))))))

(deftest alternatives-include-top-3
  (let [job (m/match-job roles {:user "carol" :title "Security Analyst"})]
    (is (= "R-IA (0.15); R-ADM (0.00); R-DBA (0.00)" (:alternatives job)))))

(deftest tie-breaks-alphabetically
  (let [roles2 [{:role_id "B" :role_title "alpha" :keywords ""}
                {:role_id "A" :role_title "beta" :keywords ""}]
        job (m/match-job roles2 {:user "u" :title "zzz"})]
    (is (= "A" (:best_role job)))
    (is (= "B (0.00)" (:alternatives job)))))

(deftest no-roles
  (let [job (m/match-job [] {:user "u" :title "Anything"})]
    (is (= "none" (:best_role job)))
    (is (= "weak" (:confidence job)))))

(deftest empty-title
  (let [job (m/match-job roles {:user "u" :title ""})]
    (is (= "weak" (:confidence job)))
    (is (= "0.00" (:score job)))))

(deftest sample-end-to-end
  (let [roles (core/csv->maps (slurp "data/roles.csv"))
        jobs (core/csv->maps (slurp "data/jobs.csv"))
        out (m/match-all roles jobs)]
    (is (= ["R-DBA" "R-ADM" "R-SEC" "R-DEV" "R-NET" "R-IA"]
           (map :best_role out)))
    (is (= 6 (count out)))))
