// src/components/pages/linuxplus/LinuxPlusTestList.js
import React from "react";
import GlobalTestList from "../../../GlobalTestList";

const LinuxPlusTestList = () => {
  return (
    <GlobalTestList
      category="linuxplus"
      title="CompTIA Linux+ (XK0-005) 🐧"
      subtitle="Practice Test Collection"
      testPath="/practice-tests/linux-plus"
    />
  );
};

export default LinuxPlusTestList;
