import { useMutation, useQuery } from "@tanstack/react-query";
import axios from "../api/axiosInstance";

export const useUploadDocument = () =>
  useMutation({
    mutationFn: (file: File) => {
      const formData = new FormData();
      formData.append("file", file);
      return axios.post("/documents/upload", formData);
    }
  });

export const useDocumentDetails = (documentId: string) =>
  useQuery({
    queryKey: ["document", documentId],
    queryFn: () => axios.get(`/documents/${documentId}`).then((res) => res.data)
  });
