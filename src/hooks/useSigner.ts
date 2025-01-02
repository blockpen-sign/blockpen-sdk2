import { useMutation } from "@tanstack/react-query";
import axios from "../api/axiosInstance";

export const useAddSigners = (documentId: string) =>
  useMutation<
    { email: string; name: string; role: string }[],
    unknown,
    { email: string; name: string; role: string }[]
  >({
    mutationFn: async (
      signers: { email: string; name: string; role: string }[]
    ) => {
      const response = await axios.post<
        { email: string; name: string; role: string }[]
      >(`/documents/${documentId}/signers`, { signers });
      return response.data;
    },
  });
