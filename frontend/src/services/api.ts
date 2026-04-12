import { http } from "../lib/http";
import type { Group, Message, SendMessageRequest, User } from "../types";

export const api = {
  async register(payload: {
    username: string;
    fullName: string;
    password: string;
  }): Promise<User> {
    const { data } = await http.post<User>("/api/register", payload);
    return data;
  },

  async login(payload: { username: string; password: string }): Promise<User> {
    const { data } = await http.post<User>("/api/login", payload);
    return data;
  },

  async users(): Promise<User[]> {
    const { data } = await http.get<User[]>("/api/users");
    return data;
  },

  async profile(userId: number): Promise<User> {
    const { data } = await http.get<User>(`/api/profile?userId=${userId}`);
    return data;
  },

  async updateProfile(payload: {
    userId: number;
    username: string;
    fullName: string;
    bio: string;
    avatarUrl: string;
  }): Promise<User> {
    const { data } = await http.post<User>("/api/profile", payload);
    return data;
  },

  async groups(userId: number): Promise<Group[]> {
    const { data } = await http.get<Group[]>(`/api/groups?userId=${userId}`);
    return data;
  },

  async createGroup(payload: { name: string; creatorId: number; memberIds: number[] }): Promise<Group> {
    const { data } = await http.post<Group>("/api/groups", payload);
    return data;
  },

  async addGroupMember(payload: { groupId: number; userId: number; adderId: number }): Promise<{ status: string }> {
    const { data } = await http.post<{ status: string }>("/api/group/add", payload);
    return data;
  },

  async blocked(userId: number): Promise<number[]> {
    const { data } = await http.get<number[]>(`/api/blocked?userId=${userId}`);
    return data;
  },

  async block(blockerId: number, blockedId: number): Promise<{ status: string }> {
    const { data } = await http.post<{ status: string }>("/api/block", { blockerId, blockedId });
    return data;
  },

  async unblock(blockerId: number, blockedId: number): Promise<{ status: string }> {
    const { data } = await http.post<{ status: string }>("/api/unblock", { blockerId, blockedId });
    return data;
  },

  async online(): Promise<number[]> {
    const { data } = await http.get<number[]>("/api/online");
    return data;
  },

  async typing(from: number, to: number): Promise<{ status: string }> {
    const { data } = await http.post<{ status: string }>("/api/typing", { from, to });
    return data;
  },

  async upload(file: File): Promise<{ url: string }> {
    const formData = new FormData();
    formData.append("file", file);
    const { data } = await http.post<{ url: string }>("/api/upload", formData, {
      headers: { "Content-Type": "multipart/form-data" }
    });
    return data;
  },

  async messages(params: { userId: number; contactId?: number; groupId?: number }): Promise<Message[]> {
    const query = new URLSearchParams({ userId: String(params.userId) });
    if (params.contactId) query.set("contactId", String(params.contactId));
    if (params.groupId) query.set("groupId", String(params.groupId));
    const { data } = await http.get<Message[]>(`/api/messages?${query.toString()}`);
    return data;
  },

  async send(payload: SendMessageRequest): Promise<{ status: string; messageId: number }> {
    const { data } = await http.post<{ status: string; messageId: number }>("/api/send", {
      ...payload,
      type: "message"
    });
    return data;
  }
};