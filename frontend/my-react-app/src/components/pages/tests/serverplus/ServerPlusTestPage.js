import React, { memo } from "react";
import { useParams } from "react-router-dom";
import ServerPlusTestList from "./ServerPlusTestList";
import GlobalTestPage from "../../../GlobalTestPage";
import "../../../test.css";

const ServerPlusTestPage = memo(() => {
  const { testId } = useParams();

  if (!testId) {
    return <ServerPlusTestList />;
  }

  return (
    <GlobalTestPage
      testId={testId}
      category="serverplus"
      backToListPath="/practice-tests/server-plus"
    />
  );
});

export default ServerPlusTestPage;

