// src/components/pages/serverplus/ServerPlusTestList.js
import React from "react";
import GlobalTestList from "../../../GlobalTestList";

const ServerPlusTestList = () => {
  return (
    <GlobalTestList
      category="serverplus"
      title="CompTIA Server+ (SK0-005) 🧛‍♂️"
      subtitle="Practice Test Collection"
      testPath="/practice-tests/server-plus"
    />
  );
};

export default ServerPlusTestList;
