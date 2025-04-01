import React, { memo } from "react";
import { useParams } from "react-router-dom";
import LinuxPlusTestList from "./LinuxPlusTestList";
import GlobalTestPage from "../../../GlobalTestPage";
import "../../../test.css";

const LinuxPlusTestPage = memo(() => {
  const { testId } = useParams();

  if (!testId) {
    return <LinuxPlusTestList />;
  }

  return (
    <GlobalTestPage
      testId={testId}
      category="linuxplus"
      backToListPath="/practice-tests/linux-plus"
    />
  );
});

export default LinuxPlusTestPage;

