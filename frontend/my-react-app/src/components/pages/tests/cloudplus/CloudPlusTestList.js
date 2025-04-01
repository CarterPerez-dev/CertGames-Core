// src/components/pages/cloudplus/CloudPlusTestList.js
import React from "react";
import GlobalTestList from "../../../GlobalTestList";

const CloudPlusTestList = () => {
  return (
    <GlobalTestList
      category="cloudplus"
      title="CompTIA Cloud+ (CV0-004) 🌩️"
      subtitle="Practice Test Collection"
      testPath="/practice-tests/cloud-plus"
    />
  );
};

export default CloudPlusTestList;
