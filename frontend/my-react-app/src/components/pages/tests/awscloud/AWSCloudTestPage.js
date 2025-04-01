import React, { memo } from "react";
import { useParams } from "react-router-dom";
import AWSCloudTestList from "./AWSCloudTestList";
import GlobalTestPage from "../../../GlobalTestPage";
import "../../../test.css";

const AWSCloudTestPage = memo(() => {
  const { testId } = useParams();

  if (!testId) {
    return <AWSCloudTestList />;
  }

  return (
    <GlobalTestPage
      testId={testId}
      category="awscloud"
      backToListPath="/practice-tests/aws-cloud"
    />
  );
});

export default AWSCloudTestPage;

