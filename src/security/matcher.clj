(ns security.matcher
  "IAM/PAM job-matching assistant.
  Roles CSV columns: role_id, role_title, keywords (space or comma separated).
  Jobs CSV columns: user, title, dept.
  Output CSV: user, title, best_role, score, confidence, matched_keywords,
  alternatives.
  Deterministic token-overlap scoring; pure functions only, I/O in -main."
  (:require [clojure.set :as set]
            [clojure.string :as str]
            [security.core :as core]))

(defn tokens
  "Normalizes text into a sorted vector of lowercase alphanumeric tokens."
  [s]
  (if (core/blank? s)
    []
    (->> (str/split (str/replace (str/lower-case (str s)) #"[^a-z0-9]" " ") #"\s+")
         (remove str/blank?))))

(def kw-weight
  "Weight of keyword overlap in the final score."
  0.7)

(def title-weight
  "Weight of job-title-to-role-title overlap in the final score."
  0.3)

(defn role-score
  "Scores one job title against one role. Returns {:role-id .. :score .. :matched ..}."
  [job-tokens {:keys [role_id role_title keywords]}]
  (let [role-kws (tokens keywords)
        role-title-tokens (tokens role_title)
        job-set (set job-tokens)
        matched (filterv job-set role-kws)
        kw-overlap (if (seq role-kws)
                     (/ (count matched) (count role-kws))
                     0.0)
        title-overlap (if (seq job-set)
                        (/ (count (clojure.set/intersection job-set (set role-title-tokens)))
                           (count job-set))
                        0.0)
        score (core/round2 (core/clamp 0.0 1.0 (+ (* kw-weight kw-overlap)
                                                  (* title-weight title-overlap))))]
    {:role_id role_id
     :score score
     :matched matched}))

(defn best-match
  "Finds the best matching role for a job title. Ties break alphabetically by role_id.
  Returns {:best .. :alternatives ..}."
  [job-tokens roles]
  (let [scored (map #(role-score job-tokens %) roles)
        sorted (sort-by (juxt (comp - :score) :role_id) scored)
        best (first sorted)
        alternatives (take 3 (rest sorted))]
    {:best best
     :alternatives alternatives}))

(defn match-job
  "Matches one job row, attaching best_role, score, confidence, matched_keywords,
  alternatives."
  [roles job]
  (let [job-tokens (tokens (:title job))
        {:keys [best alternatives]} (best-match job-tokens roles)]
    (if (nil? best)
      (assoc job :best_role "none" :score "0.00" :confidence "weak"
             :matched_keywords "" :alternatives "")
      (let [score (:score best)
            confidence (cond
                         (>= score 0.6) "strong"
                         (>= score 0.3) "moderate"
                         :else "weak")
            alt-str (str/join "; "
                              (map #(str (:role_id %) " (" (format "%.2f" (:score %)) ")")
                                   alternatives))]
        (assoc job
               :best_role (:role_id best)
               :score (format "%.2f" (double score))
               :confidence confidence
               :matched_keywords (str/join " " (:matched best))
               :alternatives alt-str)))))

(defn match-all
  "Matches all jobs against all roles."
  [roles jobs]
  (map #(match-job roles %) jobs))

(defn -main
  [& args]
  (let [[roles-file jobs-file out-file] args]
    (when-not (and roles-file jobs-file)
      (binding [*out* *err*]
        (println "usage: bb -m security.matcher <roles.csv> <jobs.csv> [out.csv]")
        (System/exit 1)))
    (let [roles (core/csv->maps (slurp roles-file))
          jobs (core/csv->maps (slurp jobs-file))
          out (core/maps->csv (match-all roles jobs))]
      (if out-file
        (spit out-file out)
        (println out)))))
