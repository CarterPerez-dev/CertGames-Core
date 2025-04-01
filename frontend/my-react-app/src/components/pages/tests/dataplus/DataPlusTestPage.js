import React, { memo } from "react";
import { useParams } from "react-router-dom";
import DataPlusTestList from "./DataPlusTestList";
import GlobalTestPage from "../../../GlobalTestPage";
import "../../../test.css";

const DataPlusTestPage = memo(() => {
  const { testId } = useParams();

  if (!testId) {
    return <DataPlusTestList />;
  }

  return (
    <GlobalTestPage
      testId={testId}
      category="dataplus"
      backToListPath="/practice-tests/data-plus"
    />
  );
});

export default DataPlusTestPage;

