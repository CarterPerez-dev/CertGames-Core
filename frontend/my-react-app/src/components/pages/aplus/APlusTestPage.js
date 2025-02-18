// APlusTestPage.js
import React from "react";
import { useParams } from "react-router-dom";
import APlusTestList from "./APlusTestList";  // your existing test list component
import GlobalTestPage from "../../GlobalTestPage"; // the new universal logic
import "../../test.css";

const APlusTestPage = () => {
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
};

export default APlusTestPage;

