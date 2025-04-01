import React, { memo } from "react";
import { useParams } from "react-router-dom";
import SecurityPlusTestList from "./SecurityPlusTestList";
import GlobalTestPage from "../../../GlobalTestPage";
import "../../../test.css";

const SecurityPlusTestPage = memo(() => {
  const { testId } = useParams();

  if (!testId) {
    return <SecurityPlusTestList />;
  }

  return (
    <GlobalTestPage
      testId={testId}
      category="secplus"
      backToListPath="/practice-tests/security-plus"
    />
  );
});

export default SecurityPlusTestPage;

