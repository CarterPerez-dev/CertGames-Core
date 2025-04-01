import React, { memo } from "react";
import { useParams } from "react-router-dom";
import CloudPlusTestList from "./CloudPlusTestList";
import GlobalTestPage from "../../../GlobalTestPage";
import "../../../test.css";

const CloudPlusTestPage = memo(() => {
  const { testId } = useParams();

  if (!testId) {
    return <CloudPlusTestList />;
  }

  return (
    <GlobalTestPage
      testId={testId}
      category="cloudplus"
      backToListPath="/practice-tests/cloud-plus"
    />
  );
});

export default CloudPlusTestPage;

