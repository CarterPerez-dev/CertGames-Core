import React, { memo } from "react";
import { useParams } from "react-router-dom";
import AplusCore2TestList from "./AplusCore2TestList";
import GlobalTestPage from "../../../GlobalTestPage";
import "../../../test.css";

const APlusCore2TestPage = memo(() => {
  const { testId } = useParams();

  // If no testId in URL, show the list
  if (!testId) {
    return <AplusCore2TestList />;
  }

  // Otherwise, show the global runner
  return (
    <GlobalTestPage
      testId={testId}
      category="aplus2"
      backToListPath="/practice-tests/aplus-core2"
    />
  );
});

export default APlusCore2TestPage;




