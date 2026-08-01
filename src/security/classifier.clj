(ns security.classifier
  "Privileged-access request classifier.
  Input CSV columns: request_id, requester, role, privilege, justification,
  duration_days, emergency, approver.
  Output: input row + decision (approve/escalate/deny), risk_level, reason.
  Deterministic keyword rules; pure functions only, I/O in -main."
  (:require [clojure.set :as set]
            [clojure.string :as str]
            [security.core :as core]))

(def risk-keywords
  "Tokens in role/privilege that indicate elevated or standing privilege."
  #{"root" "admin" "administrator" "superuser" "sysadmin" "sa"
    "all" "wildcard" "*" "grant" "prod" "production" "domain-admin"})

(def approval-keywords
  "Tokens in the justification that indicate business context / a ticket."
  #{"ticket" "incident" "change" "rfc" "story" "task" "cab" "emergency"})

(def read-keywords
  "Tokens that indicate read-only access."
  #{"read" "readonly" "read-only" "list" "get" "view" "select" "monitor"})

(def max-duration-days
  "Requests longer than this are denied outright."
  90)

(def min-justification-chars
  "Justifications shorter than this are escalated."
  15)

(defn tokens
  "Normalizes text into a set of lowercase alphanumeric tokens."
  [s]
  (if (core/blank? s)
    #{}
    (set (->> (str/split (str/replace (str/lower-case (str s)) #"[^a-z0-9]" " ") #"\s+")
              (remove str/blank?)))))

(defn classify-request
  "Classifies one privileged-access request. Earlier rules take precedence."
  [{:keys [role privilege justification duration_days emergency] :as r}]
  (let [all-tokens (into (tokens role) (tokens privilege))
        just (str/trim (str justification))
        just-tokens (tokens just)
        duration (or (core/to-double duration_days) 0.0)
        has-risk (seq (set/intersection all-tokens risk-keywords))
        has-read (seq (set/intersection all-tokens read-keywords))
        has-approval (seq (set/intersection just-tokens approval-keywords))
        emergency? (= (core/lc emergency) "yes")]
    (cond
      (> duration max-duration-days)
      (assoc r :decision "deny" :risk_level "high"
             :reason (str "Duration " (format "%.0f" duration)
                          " days exceeds policy limit of " max-duration-days " days"))

      (< (count just) min-justification-chars)
      (assoc r :decision "escalate" :risk_level "high"
             :reason "Justification is missing or insufficient for privileged access")

      has-risk
      (cond
        (and emergency? has-approval)
        (assoc r :decision "approve" :risk_level "high"
               :reason "Privileged access with emergency break-glass ticket")

        emergency?
        (assoc r :decision "escalate" :risk_level "high"
               :reason "Emergency privileged access requires approver sign-off")

        (> duration 7.0)
        (assoc r :decision "escalate" :risk_level "high"
               :reason "Elevated privilege requested beyond 7 days")

        :else
        (assoc r :decision "escalate" :risk_level "high"
               :reason "Elevated privilege requires approver sign-off"))

      has-read
      (assoc r :decision "approve" :risk_level "low"
             :reason "Read-only access, no elevated privilege")

      :else
      (assoc r :decision "approve" :risk_level "medium"
             :reason "Standard access with justification, no elevated privilege"))))

(defn classify
  "Classify all requests."
  [requests]
  (map classify-request requests))

(defn -main
  [& args]
  (let [[in-file out-file] args]
    (when-not in-file
      (binding [*out* *err*]
        (println "usage: bb -m security.classifier <in.csv> [out.csv]")
        (System/exit 1)))
    (let [out (core/maps->csv (classify (core/csv->maps (slurp in-file))))]
      (if out-file
        (spit out-file out)
        (println out)))))
