import axios, { AxiosError } from "axios";
import type { ApiError } from "../types";

const http = axios.create({
  baseURL: "/",
  timeout: 15000,
  headers: {
    "Content-Type": "application/json"
  }
});

http.interceptors.request.use((config) => {
  const token = localStorage.getItem("authToken");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export function toApiError(error: unknown): ApiError {
  const fallback: ApiError = { error: "Unexpected error" };
  if (!(error instanceof AxiosError)) return fallback;

  const body = error.response?.data;
  if (typeof body === "string") {
    return { error: body };
  }

  if (body && typeof body === "object" && "error" in body) {
    const payload = body as ApiError;
    return { error: payload.error ?? fallback.error, code: payload.code };
  }

  return { error: error.message || fallback.error };
}

export { http };