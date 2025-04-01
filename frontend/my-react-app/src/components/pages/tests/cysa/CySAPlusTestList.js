// src/components/pages/cysa/CySAPlusTestList.js
import React from "react";
import GlobalTestList from "../../../GlobalTestList";

const CySAPlusTestList = () => {
  return (
    <GlobalTestList
      category="cysa"
      title="CompTIA CySA+ (CS0-003) 🕵️‍♂️"
      subtitle="Practice Test Collection"
      testPath="/practice-tests/cysa-plus"
    />
  );
};

export default CySAPlusTestList;
