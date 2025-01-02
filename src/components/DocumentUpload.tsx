import React, { useState } from "react";
import axios from "../api/axiosInstance";

const DocumentUpload: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    const formData = new FormData();
    formData.append("file", file);

    try {
      const { data } = await axios.post("/documents/upload", formData);
      alert(`Document uploaded: ${data.document.id}`);
    } catch (err) {
      alert("Upload failed");
    }
  };

  return (
    <div>
      <input title="file" type="file" onChange={handleFileChange} />
      <button onClick={handleUpload}>Upload</button>
    </div>
  );
};

export default DocumentUpload;
