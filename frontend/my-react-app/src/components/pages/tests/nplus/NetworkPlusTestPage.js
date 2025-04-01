import React, { memo } from "react";
import { useParams } from "react-router-dom";
import NPlusTestList from "./NPlusTestList";
import GlobalTestPage from "../../../GlobalTestPage";
import "../../../test.css";

const NetworkPlusTestPage = memo(() => {
  const { testId } = useParams();

  if (!testId) {
    return <NPlusTestList />;
  }

  return (
    <GlobalTestPage
      testId={testId}
      category="nplus"
      backToListPath="/practice-tests/network-plus"
    />
  );
});

export default NetworkPlusTestPage;

