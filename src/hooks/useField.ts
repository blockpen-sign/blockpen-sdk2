import { useMutation } from "@tanstack/react-query";
import axios from "../api/axiosInstance";

export const useAddFields = (documentId: string) =>
  useMutation<
    {
      x: number;
      y: number;
      width: number;
      height: number;
      signerId: string;
      fieldType: string;
    }[],
    unknown,
    {
      x: number;
      y: number;
      width: number;
      height: number;
      signerId: string;
      fieldType: string;
    }[]
  >({
    mutationFn: async (fields: {
      x: number;
      y: number;
      width: number;
      height: number;
      signerId: string;
      fieldType: string;
    }[]) => {
      const response = await axios.post<
        {
          x: number;
          y: number;
          width: number;
          height: number;
          signerId: string;
          fieldType: string;
        }[]
      >(`/documents/${documentId}/fields`, { fields });
      return response.data;
    },
  })