// src/components/pages/nplus/NPlusTestList.js
import React from "react";
import GlobalTestList from "../../GlobalTestList";

const NPlusTestList = () => {
  return (
    <GlobalTestList
      category="nplus"
      title="CompTIA Network+ (N10-009) 📡"
      subtitle="Practice Test Collection"
      testPath="/practice-tests/network-plus"
    />
  );
};

export default NPlusTestList;
