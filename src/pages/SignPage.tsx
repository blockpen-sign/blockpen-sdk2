import React, { useState } from "react";
import { useSignDocument, useRejectDocument } from "../hooks/useSignDocument";

const SignPage: React.FC<{ documentId: string; signerId: string }> = ({ documentId, signerId }) => {
  const [signature, setSignature] = useState("");
  const [reason, setReason] = useState("");

  const signDocumentMutation = useSignDocument(documentId);
  const rejectDocumentMutation = useRejectDocument(documentId);

  const handleSign = () => {
    signDocumentMutation.mutate({ signerId, signature }, {
      onSuccess: () => alert("Document signed successfully!"),
      onError: () => alert("Signing failed."),
    });
  };

  const handleReject = () => {
    rejectDocumentMutation.mutate({ signerId, reason }, {
      onSuccess: () => alert("Document rejected."),
      onError: () => alert("Rejection failed."),
    });
  };

  return (
    <div>
      <h1>Sign Document</h1>
      <textarea
        placeholder="Your Signature"
        value={signature}
        onChange={(e) => setSignature(e.target.value)}
      />
      <button onClick={handleSign}>Sign</button>
      <textarea
        placeholder="Reason for Rejection"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
      />
      <button onClick={handleReject}>Reject</button>
    </div>
  );
};

export default SignPage;
