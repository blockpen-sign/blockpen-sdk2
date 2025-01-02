import React, { useState } from "react";
import { useAddFields } from "../hooks/useField";

const AddFieldsPage: React.FC<{ documentId: string }> = ({ documentId }) => {
  const [fields, setFields] = useState([{ x: 0, y: 0, width: 100, height: 50, signerId: "", fieldType: "signature" }]);
  const addFieldsMutation = useAddFields(documentId);

  const handleChange = (index: number, field: string, value: string | number) => {
    const updatedFields:any = [...fields];
    updatedFields[index][field] = value;
    setFields(updatedFields);
  };

  const handleSubmit = async () => {
    addFieldsMutation.mutate(fields, {
      onSuccess: () => alert("Fields added successfully!"),
      onError: () => alert("Failed to add fields."),
    });
  };

  return (
    <div>
      <h1>Add Fields</h1>
      {fields.map((field, index) => (
        <div key={index}>
          <input
            type="number"
            placeholder="X"
            value={field.x}
            onChange={(e) => handleChange(index, "x", Number(e.target.value))}
          />
          <input
            type="number"
            placeholder="Y"
            value={field.y}
            onChange={(e) => handleChange(index, "y", Number(e.target.value))}
          />
          <input
            type="text"
            placeholder="Signer ID"
            value={field.signerId}
            onChange={(e) => handleChange(index, "signerId", e.target.value)}
          />
        </div>
      ))}
      <button onClick={handleSubmit}>Submit</button>
    </div>
  );
};

export default AddFieldsPage;
