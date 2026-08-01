(ns security.core-test
  (:require [clojure.test :refer [deftest is testing]]
            [security.core :as core]))

(deftest read-csv-rows-plain
  (is (= [["a" "b" "c"] ["1" "2" "3"]]
         (core/read-csv-rows "a,b,c\n1,2,3")))
  (is (= [["a" "b"]]
         (core/read-csv-rows "a,b\n")))
  (is (= [["a"]]
         (core/read-csv-rows "a\n"))))

(deftest read-csv-rows-quoting
  (testing "quoted field with comma"
    (is (= [["a,b" "c"]]
           (core/read-csv-rows "\"a,b\",c"))))
  (testing "escaped quotes"
    (is (= [["c\"d" "e"]]
           (core/read-csv-rows "\"c\"\"d\",e"))))
  (testing "newline inside quoted field"
    (is (= [["line1\nline2" "x"]]
           (core/read-csv-rows "\"line1\nline2\",x"))))
  (testing "CRLF line endings"
    (is (= [["a" "b"] ["c" "d"]]
           (core/read-csv-rows "a,b\r\nc,d"))))
  (testing "CR inside quoted field preserved"
    (is (= [["a\rb"]]
           (core/read-csv-rows "\"a\rb\"")))))

(deftest read-csv-rows-lenient
  (is (= [] (core/read-csv-rows "")))
  (is (= [] (core/read-csv-rows nil)))
  (testing "blank lines skipped"
    (is (= [["a" "b"] ["c" "d"]]
           (core/read-csv-rows "a,b\n\nc,d\n"))))
  (testing "unclosed quote"
    (is (= [["abc"]]
           (core/read-csv-rows "\"abc"))))
  (testing "spaces preserved"
    (is (= [[" a " "b "]]
           (core/read-csv-rows " a ,b "))))
  (testing "empty quoted field"
    (is (= [[""]]
           (core/read-csv-rows "\"\"")))))

(deftest rows->csv-and-back
  (is (= "\"a,b\",\"c\"\"d\""
         (core/rows->csv [["a,b" "c\"d"]])))
  (is (= "a,b\n1,2"
         (core/rows->csv [["a" "b"] ["1" "2"]])))
  (testing "round trip"
    (is (= [["a,b" "c" "d\ne"] ["x" "y" "z"]]
           (-> (core/rows->csv [["a,b" "c" "d\ne"] ["x" "y" "z"]])
               core/read-csv-rows)))))

(deftest csv->maps-basics
  (is (= [{:u "1" :s "x"} {:u "2" :s "y"}]
         (core/csv->maps "u,s\n1,x\n2,y")))
  (testing "headers trimmed, header-only file"
    (is (= [] (core/csv->maps " a ,b\n")))
    (is (= nil (core/csv->maps "")))))

(deftest maps->csv-basics
  (is (= "a,b\n1,2\n3,4"
         (core/maps->csv [{:a "1" :b "2"} {:a "3" :b "4"}])))
  (testing "extra keys appended, missing keys empty"
    (is (= "a,b,c\n1,2,\n4,,5"
           (core/maps->csv [{:a "1" :b "2"} {:a "4" :c "5"}]))))
  (testing "quotes fields with commas, header always present"
    (is (= "a\n\"1,2\""
           (core/maps->csv [{:a "1,2"}]))))
  (testing "empty input"
    (is (= "" (core/maps->csv []))))
  (testing "round trip"
    (is (= [{:a "x,y" :b "1"} {:a "q\"r" :b "2"}]
           (-> (core/maps->csv [{:a "x,y" :b "1"} {:a "q\"r" :b "2"}])
               core/csv->maps)))))

(deftest helpers
  (is (= 3.5 (core/to-double "3.5")))
  (is (= 5.0 (core/to-double 5)))
  (is (nil? (core/to-double "abc")))
  (is (nil? (core/to-double "")))
  (is (nil? (core/to-double nil)))
  (is (= "foo" (core/lc "FOO")))
  (is (= 3 (core/clamp 0 10 3)))
  (is (= 0 (core/clamp 0 10 -2)))
  (is (= 10 (core/clamp 0 10 42)))
  (is (= 7.13 (core/round2 7.125)))
  (is (core/blank? ""))
  (is (core/blank? nil))
  (is (not (core/blank? "x"))))
