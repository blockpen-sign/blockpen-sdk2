import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import AddFieldsPage from "./pages/AddFieldsPage";
import SignPage from "./pages/SignPage";

const App: React.FC = () => {
  return (
    <Router>
      <Routes>
        <Route path="/add-fields/:documentId" element={<AddFieldsPage documentId="document-id-placeholder" />} />
        <Route path="/sign/:documentId/:signerId" element={<SignPage documentId="document-id-placeholder" signerId="signer-id-placeholder" />} />
      </Routes>
    </Router>
  );
};

export default App;
