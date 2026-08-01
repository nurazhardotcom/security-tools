(ns security.summarizer-test
  (:require [clojure.test :refer [deftest is]]
            [security.core :as core]
            [security.summarizer :as s]))

(def sample
  (core/csv->maps (slurp "data/access_reviews.csv")))

(deftest by-system
  (is (= {"CI" 2 "CRM" 2 "ERP" 3 "HR" 1 "VPN" 1}
         (s/by-system sample))))

(deftest duplicates
  (is (= [{:user "alice" :system "ERP" :permission "finance_full" :occurrences 2}]
         (s/duplicates sample))))

(deftest orphaned
  (is (= [{:user "bob" :system "VPN" :permission "admin_vpn"}
          {:user "dave" :system "CRM" :permission "read_only"}]
         (map #(select-keys % [:user :system :permission])
              (s/orphaned sample)))))

(deftest unused
  (let [{:keys [unused usage_unknown]} (s/unused sample)]
    (is (= ["carol" "dave" "heidi"] (map :user unused)))
    (is (= [] usage_unknown))))

(deftest per-owner
  (is (= {"finance-ops" 3 "hr-team" 1 "platform" 2 "sales" 1}
         (s/per-owner sample))))

(deftest summarize-complete
  (let [summary (s/summarize sample)]
    (is (= 9 (:input_rows summary)))
    (is (= 8 (:unique_users summary)))
    (is (= 5 (:unique_systems summary)))
    (is (= 6 (:unique_permissions summary)))
    (is (= 1 (count (:duplicate_grants summary))))
    (is (= 2 (count (:orphaned_access summary))))
    (is (= 3 (count (:unused_access_over_90d summary))))
    (is (= 0 (count (:usage_unknown summary))))))

(deftest summarize-empty
  (let [summary (s/summarize [])]
    (is (= 0 (:input_rows summary)))
    (is (= {} (:grants_per_system summary)))
    (is (= [] (:duplicate_grants summary)))))
