// src/components/pages/awscloud/AWSCloudTestList.js
import React from "react";
import GlobalTestList from "../../../GlobalTestList";

const AWSCloudTestList = () => {
  return (
    <GlobalTestList
      category="awscloud"
      title="AWS Cloud Practitioner (CLE-C02) 🌥️"
      subtitle="Practice Test Collection"
      testPath="/practice-tests/aws-cloud"
    />
  );
};

export default AWSCloudTestList;
