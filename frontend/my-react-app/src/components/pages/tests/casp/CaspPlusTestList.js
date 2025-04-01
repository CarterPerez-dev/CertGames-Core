// src/components/pages/casp/CaspPlusTestList.js
import React from "react";
import GlobalTestList from "../../../GlobalTestList";

const CaspPlusTestList = () => {
  return (
    <GlobalTestList
      category="caspplus"
      title="CompTIA Security-X (CAS-005) ⚔️"
      subtitle="Practice Test Collection"
      testPath="/practice-tests/casp-plus"
    />
  );
};

export default CaspPlusTestList;
