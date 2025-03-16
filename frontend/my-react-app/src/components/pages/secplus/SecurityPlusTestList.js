// src/components/pages/secplus/SecurityPlusTestList.js
import React from "react";
import GlobalTestList from "../../GlobalTestList";

const SecurityPlusTestList = () => {
  return (
    <GlobalTestList
      category="secplus"
      title="CompTIA Security+ (SY0-701) 🔐"
      subtitle="Practice Test Collection"
      testPath="/practice-tests/security-plus"
    />
  );
};

export default SecurityPlusTestList;
