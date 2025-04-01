// APlusTestPage.js
import React, { memo } from "react";
import { useParams } from "react-router-dom";
import APlusTestList from "./APlusTestList";
import GlobalTestPage from "../../../GlobalTestPage";
import "../../../test.css";

// Memoize component to prevent unnecessary re-renders
const APlusTestPage = memo(() => {
  const { testId } = useParams();

  // If no testId in URL, show the test list
  if (!testId) {
    return <APlusTestList />;
  }

  // Otherwise, show the universal test runner
  return (
    <GlobalTestPage
      testId={testId}
      category="aplus"
      backToListPath="/practice-tests/a-plus"
    />
  );
});

export default APlusTestPage;
