(ns security.test-runner
  "Runs every test namespace. Exits 0 on success, 1 on any failure or error."
  (:require [clojure.test :as t]
            [security.classifier-test]
            [security.core-test]
            [security.matcher-test]
            [security.prioritizer-test]
            [security.summarizer-test]
            [security.tickets-test]
            [security.triage-test]))

(def test-namespaces
  '[security.core-test
    security.prioritizer-test
    security.summarizer-test
    security.triage-test
    security.classifier-test
    security.tickets-test
    security.matcher-test])

(defn -main
  [& _]
  (let [summary (apply t/run-tests test-namespaces)]
    (System/exit (if (and (zero? (:fail summary)) (zero? (:error summary))) 0 1))))
