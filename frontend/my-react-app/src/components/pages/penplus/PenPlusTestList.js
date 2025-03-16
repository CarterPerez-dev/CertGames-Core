// src/components/pages/penplus/PenPlusTestList.js
import React from "react";
import GlobalTestList from "../../GlobalTestList";

const PenPlusTestList = () => {
  return (
    <GlobalTestList
      category="penplus"
      title="CompTIA PenTest+ (PT0-003) 🐍"
      subtitle="Practice Test Collection"
      testPath="/practice-tests/pen-plus"
    />
  );
};

export default PenPlusTestList;
