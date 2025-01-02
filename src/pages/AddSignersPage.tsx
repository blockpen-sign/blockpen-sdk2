import React from "react";
import AddSigners from "../components/AddSigners";

const AddSignersPage: React.FC<{ documentId: string }> = ({ documentId }) => {
  return (
    <div>
      <h1>Add Signers</h1>
      <AddSigners documentId={documentId} />
    </div>
  );
};

export default AddSignersPage;
