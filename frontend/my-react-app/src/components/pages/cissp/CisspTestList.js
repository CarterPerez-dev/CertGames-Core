// src/components/pages/cissp/CisspTestList.js
import React from "react";
import GlobalTestList from "../../GlobalTestList";

const CisspTestList = () => {
  return (
    <GlobalTestList
      category="cissp"
      title="(ISC)² CISSP 👾"
      subtitle="Practice Test Collection"
      testPath="/practice-tests/cissp"
    />
  );
};

export default CisspTestList;
