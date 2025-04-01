import React, { memo } from "react";
import { useParams } from "react-router-dom";
import CaspPlusTestList from "./CaspPlusTestList";
import GlobalTestPage from "../../../GlobalTestPage";
import "../../../test.css";

const CaspPlusTestPage = memo(() => {
  const { testId } = useParams();

  if (!testId) {
    return <CaspPlusTestList />;
  }

  return (
    <GlobalTestPage
      testId={testId}
      category="caspplus"
      backToListPath="/practice-tests/casp-plus"
    />
  );
});

export default CaspPlusTestPage;

