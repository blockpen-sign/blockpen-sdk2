import React, { useState } from "react";
import axios from "../api/axiosInstance";

const AddSigners: React.FC<{ documentId: string }> = ({ documentId }) => {
  const [signers, setSigners] = useState([{ email: "", name: "", role: "" }]);

  const handleChange = (index: number, field: string, value: string) => {
    const updatedSigners: any = [...signers];
    updatedSigners[index][field] = value;
    setSigners(updatedSigners);
  };

  const handleAddSigner = () => {
    setSigners([...signers, { email: "", name: "", role: "" }]);
  };

  const handleSubmit = async () => {
    try {
      await axios.post(`/documents/${documentId}/signers`, { signers });
      alert("Signers added successfully");
    } catch (err) {
      alert("Failed to add signers");
    }
  };

  return (
    <div>
      {signers.map((signer, index) => (
        <div key={index}>
          <input
            type="text"
            placeholder="Name"
            value={signer.name}
            onChange={(e) => handleChange(index, "name", e.target.value)}
          />
          <input
            type="email"
            placeholder="Email"
            value={signer.email}
            onChange={(e) => handleChange(index, "email", e.target.value)}
          />
          <input
            type="text"
            placeholder="Role"
            value={signer.role}
            onChange={(e) => handleChange(index, "role", e.target.value)}
          />
        </div>
      ))}
      <button onClick={handleAddSigner}>Add More Signers</button>
      <button onClick={handleSubmit}>Submit</button>
    </div>
  );
};

export default AddSigners;
