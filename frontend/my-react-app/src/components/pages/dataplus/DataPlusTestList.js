// src/components/pages/dataplus/DataPlusTestList.js
import React from "react";
import GlobalTestList from "../../GlobalTestList";

const DataPlusTestList = () => {
  return (
    <GlobalTestList
      category="dataplus"
      title="CompTIA Data+ (DA0-001) 📋"
      subtitle="Practice Test Collection"
      testPath="/practice-tests/data-plus"
    />
  );
};

export default DataPlusTestList;
