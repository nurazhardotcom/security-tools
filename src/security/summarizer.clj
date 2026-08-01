(ns security.summarizer
  "Access review summarizer.
  Input CSV columns: user, system, permission, owner, last_used_days, status.
  Output: EDN summary with rollups, duplicates, orphaned and unused access.
  Pure functions only; I/O in -main."
  (:require [security.core :as core]))

(def unused-threshold-days
  "Access unused for more than this many days is flagged."
  90)

(defn by-system
  "Systems with the number of grants each has, alphabetically sorted."
  [rows]
  (into (sorted-map) (frequencies (map :system rows))))

(defn duplicates
  "Groups rows sharing user+system+permission, returning those with >1 occurrence,
  most duplicated first."
  [rows]
  (->> rows
       (group-by #(vector (:user %) (:system %) (:permission %)))
       (filter (fn [[_ v]] (> (count v) 1)))
       (map (fn [[k v]]
              {:user (nth k 0)
               :system (nth k 1)
               :permission (nth k 2)
               :occurrences (count v)}))
       (sort-by (juxt (comp - :occurrences) :user :system))))

(defn orphaned
  "Rows whose access has no owner (blank owner column)."
  [rows]
  (->> rows
       (filter #(core/blank? (:owner %)))
       (sort-by (juxt :user :system :permission))))

(defn unused
  "Rows with last_used_days > threshold. Rows with an unparseable or missing
  last_used_days are reported separately (usage_unknown)."
  [rows]
  (let [parsed (map (fn [r] (assoc r ::days (core/to-double (:last_used_days r)))) rows)]
    {:unused (->> parsed
                  (filter #(and (some? (::days %)) (> (::days %) unused-threshold-days)))
                  (map #(dissoc % ::days))
                  (sort-by (juxt :user :system :permission)))
     :usage_unknown (->> parsed
                         (filter #(nil? (::days %)))
                         (map #(dissoc % ::days))
                         (sort-by (juxt :user :system :permission)))}))

(defn per-owner
  "Number of grants per owner, alphabetically sorted."
  [rows]
  (->> rows
       (map :owner)
       (filter #(not (core/blank? %)))
       frequencies
       (into (sorted-map))))

(defn summarize
  "Produces the full summary map for a set of access review rows."
  [rows]
  (let [unused-info (unused rows)]
    {:input_rows (count rows)
     :unique_users (count (set (map :user rows)))
     :unique_systems (count (set (map :system rows)))
     :unique_permissions (count (set (map :permission rows)))
     :grants_per_system (by-system rows)
     :grants_per_owner (per-owner rows)
     :duplicate_grants (duplicates rows)
     :orphaned_access (orphaned rows)
     :unused_access_over_90d (:unused unused-info)
     :usage_unknown (:usage_unknown unused-info)}))

(defn -main
  [& args]
  (let [[in-file flags-file] args]
    (when-not in-file
      (binding [*out* *err*]
        (println "usage: bb -m security.summarizer <in.csv> [flags.csv]")
        (System/exit 1)))
    (let [rows (or (core/csv->maps (slurp in-file)) [])
          summary (summarize rows)]
      (println (pr-str summary))
      (when flags-file
        (let [flagged (concat (:duplicate_grants summary)
                              (:orphaned_access summary)
                              (:unused_access_over_90d summary)
                              (:usage_unknown summary))]
          (spit flags-file (core/maps->csv flagged)))))))
