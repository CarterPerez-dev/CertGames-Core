import React, { memo } from "react";
import { useParams } from "react-router-dom";
import CisspTestList from "./CisspTestList";
import GlobalTestPage from "../../../GlobalTestPage";
import "../../../test.css";

const CisspTestPage = memo(() => {
  const { testId } = useParams();

  if (!testId) {
    return <CisspTestList />;
  }

  return (
    <GlobalTestPage
      testId={testId}
      category="cissp"
      backToListPath="/practice-tests/cissp"
    />
  );
});

export default CisspTestPage;

