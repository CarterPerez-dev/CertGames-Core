// src/components/StructuredData.js
import React from 'react';
import { Helmet } from 'react-helmet';

const StructuredData = ({ data }) => {
  return (
    <Helmet>
      <script type="application/ld+json">
        {JSON.stringify(data)}
      </script>
    </Helmet>
  );
};

export default StructuredData;
