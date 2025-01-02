import { useMutation } from "@tanstack/react-query";
import axios from "../api/axiosInstance";

export const useSignDocument = (documentId: string) =>
  useMutation<{ signerId: string; signature: string }, Error, { signerId: string; signature: string }>({
    mutationFn: (signature: { signerId: string; signature: string }) =>
      axios.post(`/documents/${documentId}/sign`, signature),
    });

export const useRejectDocument = (documentId: string) =>
  useMutation<void, Error, { signerId: string; reason: string }>({
    mutationFn: (reason: { signerId: string; reason: string }) =>
      axios.post(`/documents/${documentId}/reject`, reason)
  })
  