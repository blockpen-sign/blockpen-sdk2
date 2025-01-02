import React, { useState } from "react";
import axios from "../api/axiosInstance";

type Field = {
  x: number;
  y: number;
  width: number;
  height: number;
  signerId: string;
  fieldType: string;
};

type FieldKey = keyof Field;

const AddFields: React.FC<{ documentId: string }> = ({ documentId }) => {
    const [fields, setFields] = useState<Field[]>([
        { x: 0, y: 0, width: 100, height: 50, signerId: "", fieldType: "signature" },
    ]);


  const handleChange = (index: number, field: string, value: string | number) => {
    const updatedFields: any = [...fields];
    updatedFields[index][field] = value;
    setFields(updatedFields);
  };

  const handleSubmit = async () => {
    try {
      await axios.post(`/documents/${documentId}/fields`, { fields });
      alert("Fields added successfully");
    } catch (err) {
      alert("Failed to add fields");
    }
  };

  return (
    <div>
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

export default AddFields;
