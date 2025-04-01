import React, { memo } from "react";
import { useParams } from "react-router-dom";
import PenPlusTestList from "./PenPlusTestList";
import GlobalTestPage from "../../../GlobalTestPage";
import "../../../test.css";

const PenPlusTestPage = memo(() => {
  const { testId } = useParams();

  if (!testId) {
    return <PenPlusTestList />;
  }

  return (
    <GlobalTestPage
      testId={testId}
      category="penplus"
      backToListPath="/practice-tests/pen-plus"
    />
  );
});

export default PenPlusTestPage;

