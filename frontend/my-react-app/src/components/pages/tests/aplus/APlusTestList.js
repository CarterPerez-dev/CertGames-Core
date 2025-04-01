// src/components/pages/aplus/APlusTestList.js
import React from "react";
import GlobalTestList from "../../../GlobalTestList";

const APlusTestList = () => {
  return (
    <GlobalTestList
      category="aplus"
      title="CompTIA A+ Core 1 (1101) 💻"
      subtitle="Practice Test Collection"
      testPath="/practice-tests/a-plus"
    />
  );
};

export default APlusTestList;
