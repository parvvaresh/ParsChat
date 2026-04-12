import { create } from "zustand";
import { api } from "./services/api";
import { toApiError } from "./lib/http";
import type { ChatTarget, Group, Message, User } from "./types";

function decodeUserIdFromToken(token?: string | null): number | null {
  if (!token) return null;
  try {
    const payloadPart = token.split(".")[1];
    if (!payloadPart) return null;
    const json = JSON.parse(atob(payloadPart));
    const userId = Number(json.userId);
    return Number.isFinite(userId) ? userId : null;
  } catch {
    return null;
  }
}

type AuthState = {
  user: User | null;
  loading: boolean;
  error: string | null;
  login: (username: string, password: string) => Promise<boolean>;
  register: (username: string, fullName: string, password: string) => Promise<boolean>;
  updateProfile: (payload: { username: string; fullName: string; bio: string; avatarUrl: string }) => Promise<boolean>;
  hydrate: () => void;
  logout: () => void;
};

type ChatState = {
  users: User[];
  groups: Group[];
  onlineUserIds: number[];
  blockedUserIds: number[];
  selected: ChatTarget | null;
  messages: Message[];
  loading: boolean;
  error: string | null;
  bootstrap: (userId: number) => Promise<void>;
  refreshOnline: () => Promise<void>;
  setOnlineStatus: (userId: number, online: boolean) => void;
  createGroup: (name: string, memberIds: number[], userId: number) => Promise<void>;
  addMemberToGroup: (groupId: number, targetUserId: number, userId: number) => Promise<void>;
  blockUser: (targetUserId: number, userId: number) => Promise<void>;
  unblockUser: (targetUserId: number, userId: number) => Promise<void>;
  selectChat: (target: ChatTarget, userId: number) => Promise<void>;
  sendMessage: (content: string, userId: number) => Promise<void>;
  sendMedia: (mediaUrl: string, mediaType: string, userId: number) => Promise<void>;
  sendLocation: (latitude: number, longitude: number, userId: number) => Promise<void>;
  sendTyping: (userId: number) => Promise<void>;
  appendIncoming: (message: Message) => void;
};

type AuthSetter = (partial: Partial<AuthState> | ((state: AuthState) => Partial<AuthState>)) => void;
type AuthGetter = () => AuthState;
type ChatSetter = (partial: Partial<ChatState> | ((state: ChatState) => Partial<ChatState>)) => void;
type ChatGetter = () => ChatState;

export const useAuthStore = create<AuthState>((set: AuthSetter, get: AuthGetter) => ({
  user: null,
  loading: false,
  error: null,

  hydrate: () => {
    const raw = localStorage.getItem("user");
    const token = localStorage.getItem("authToken");
    if (!raw) return;

    try {
      const parsed = JSON.parse(raw) as Partial<User>;
      let userId = typeof parsed.id === "number" ? parsed.id : null;
      if (!userId) {
        userId = decodeUserIdFromToken(token);
      }

      if (!userId) {
        localStorage.removeItem("user");
        localStorage.removeItem("authToken");
        set({ user: null, error: null });
        return;
      }

      const mergedUser: User = {
        id: userId,
        username: parsed.username || "",
        fullName: parsed.fullName || "",
        bio: parsed.bio || "",
        avatarUrl: parsed.avatarUrl || "",
        token: parsed.token || token || undefined
      };

      set({ user: mergedUser });

      void api.profile(userId)
        .then((profile) => {
          const current = get().user;
          if (!current || current.id !== userId) return;
          const refreshed: User = {
            ...current,
            ...profile,
            token: current.token
          };
          localStorage.setItem("user", JSON.stringify(refreshed));
          set({ user: refreshed, error: null });
        })
        .catch(() => {
          // keep local cached user
        });
    } catch {
      localStorage.removeItem("user");
      localStorage.removeItem("authToken");
    }
  },

  login: async (username: string, password: string) => {
    set({ loading: true, error: null });
    try {
      const user = await api.login({ username, password });
      localStorage.setItem("user", JSON.stringify(user));
      if (user.token) localStorage.setItem("authToken", user.token);
      set({ user, loading: false, error: null });
      return true;
    } catch (error) {
      set({ loading: false, error: toApiError(error).error });
      return false;
    }
  },

  register: async (username: string, fullName: string, password: string) => {
    set({ loading: true, error: null });
    try {
      await api.register({ username, fullName, password });
      set({ loading: false, error: null });
      return true;
    } catch (error) {
      set({ loading: false, error: toApiError(error).error });
      return false;
    }
  },

  updateProfile: async (payload: { username: string; fullName: string; bio: string; avatarUrl: string }) => {
    const currentUser = JSON.parse(localStorage.getItem("user") || "null") as User | null;
    if (!currentUser) {
      set({ error: "Not authenticated" });
      return false;
    }

    set({ loading: true, error: null });
    try {
      const updated = await api.updateProfile({
        userId: currentUser.id,
        username: payload.username,
        fullName: payload.fullName,
        bio: payload.bio,
        avatarUrl: payload.avatarUrl
      });

      const mergedUser: User = { ...currentUser, ...updated };
      localStorage.setItem("user", JSON.stringify(mergedUser));
      set({ user: mergedUser, loading: false, error: null });
      return true;
    } catch (error) {
      set({ loading: false, error: toApiError(error).error });
      return false;
    }
  },

  logout: () => {
    localStorage.removeItem("user");
    localStorage.removeItem("authToken");
    set({ user: null, error: null });
  }
}));

export const useChatStore = create<ChatState>((set: ChatSetter, get: ChatGetter) => ({
  users: [],
  groups: [],
  onlineUserIds: [],
  blockedUserIds: [],
  selected: null,
  messages: [],
  loading: false,
  error: null,

  bootstrap: async (userId: number) => {
    set({ loading: true, error: null });
    try {
      const [users, groups, blockedUserIds, onlineUserIds] = await Promise.all([
        api.users(),
        api.groups(userId),
        api.blocked(userId),
        api.online()
      ]);
      set({
        users: users.filter((u) => u.id !== userId),
        groups,
        blockedUserIds,
        onlineUserIds,
        loading: false,
        error: null
      });
    } catch (error) {
      set({ loading: false, error: toApiError(error).error });
    }
  },

  refreshOnline: async () => {
    try {
      const onlineUserIds = await api.online();
      set({ onlineUserIds });
    } catch {
      // Presence is best-effort.
    }
  },

  setOnlineStatus: (userId: number, online: boolean) => {
    set((state: ChatState) => {
      const exists = state.onlineUserIds.includes(userId);
      if (online && !exists) {
        return { onlineUserIds: [...state.onlineUserIds, userId] };
      }
      if (!online && exists) {
        return { onlineUserIds: state.onlineUserIds.filter((id: number) => id !== userId) };
      }
      return state;
    });
  },

  createGroup: async (name: string, memberIds: number[], userId: number) => {
    if (!name.trim()) {
      set({ error: "Group name is required" });
      return;
    }

    try {
      await api.createGroup({ name: name.trim(), creatorId: userId, memberIds });
      const groups = await api.groups(userId);
      set({ groups, error: null });
    } catch (error) {
      set({ error: toApiError(error).error });
    }
  },

  addMemberToGroup: async (groupId: number, targetUserId: number, userId: number) => {
    try {
      await api.addGroupMember({ groupId, userId: targetUserId, adderId: userId });
      set({ error: null });
    } catch (error) {
      set({ error: toApiError(error).error });
    }
  },

  blockUser: async (targetUserId: number, userId: number) => {
    try {
      await api.block(userId, targetUserId);
      set((state: ChatState) => ({
        blockedUserIds: state.blockedUserIds.includes(targetUserId)
          ? state.blockedUserIds
          : [...state.blockedUserIds, targetUserId],
        error: null
      }));
    } catch (error) {
      set({ error: toApiError(error).error });
    }
  },

  unblockUser: async (targetUserId: number, userId: number) => {
    try {
      await api.unblock(userId, targetUserId);
      set((state: ChatState) => ({
        blockedUserIds: state.blockedUserIds.filter((id: number) => id !== targetUserId),
        error: null
      }));
    } catch (error) {
      set({ error: toApiError(error).error });
    }
  },

  selectChat: async (target: ChatTarget, userId: number) => {
    set({ selected: target, loading: true, error: null });
    try {
      const messages =
        target.kind === "user"
          ? await api.messages({ userId, contactId: target.id })
          : await api.messages({ userId, groupId: target.id });
      set({ messages, loading: false, error: null });
    } catch (error) {
      set({ loading: false, error: toApiError(error).error });
    }
  },

  sendMessage: async (content: string, userId: number) => {
    const selected = get().selected;
    if (!selected || !content.trim()) return;

    if (selected.kind === "user" && get().blockedUserIds.includes(selected.id)) {
      set({ error: "This user is blocked" });
      return;
    }

    const payload =
      selected.kind === "user"
        ? { from: userId, to: selected.id, content: content.trim() }
        : { from: userId, groupId: selected.id, content: content.trim() };

    try {
      const response = await api.send(payload);
      const optimistic: Message = {
        id: response.messageId,
        type: "message",
        from: userId,
        to: selected.kind === "user" ? selected.id : undefined,
        groupId: selected.kind === "group" ? selected.id : undefined,
        content: content.trim(),
        timestamp: Math.floor(Date.now() / 1000)
      };
      set((state: ChatState) => ({ messages: [...state.messages, optimistic] }));
    } catch (error) {
      set({ error: toApiError(error).error });
    }
  },

  sendMedia: async (mediaUrl: string, mediaType: string, userId: number) => {
    const selected = get().selected;
    if (!selected) return;

    if (selected.kind === "user" && get().blockedUserIds.includes(selected.id)) {
      set({ error: "This user is blocked" });
      return;
    }

    const payload =
      selected.kind === "user"
        ? { from: userId, to: selected.id, mediaUrl, mediaType }
        : { from: userId, groupId: selected.id, mediaUrl, mediaType };

    try {
      const response = await api.send(payload);
      const optimistic: Message = {
        id: response.messageId,
        type: "message",
        from: userId,
        to: selected.kind === "user" ? selected.id : undefined,
        groupId: selected.kind === "group" ? selected.id : undefined,
        mediaUrl,
        mediaType,
        timestamp: Math.floor(Date.now() / 1000)
      };
      set((state: ChatState) => ({ messages: [...state.messages, optimistic], error: null }));
    } catch (error) {
      set({ error: toApiError(error).error });
    }
  },

  sendLocation: async (latitude: number, longitude: number, userId: number) => {
    const selected = get().selected;
    if (!selected) return;

    if (selected.kind === "user" && get().blockedUserIds.includes(selected.id)) {
      set({ error: "This user is blocked" });
      return;
    }

    const payload =
      selected.kind === "user"
        ? { from: userId, to: selected.id, content: "Location", latitude, longitude }
        : { from: userId, groupId: selected.id, content: "Location", latitude, longitude };

    try {
      const response = await api.send(payload);
      const optimistic: Message = {
        id: response.messageId,
        type: "message",
        from: userId,
        to: selected.kind === "user" ? selected.id : undefined,
        groupId: selected.kind === "group" ? selected.id : undefined,
        content: "Location",
        latitude,
        longitude,
        timestamp: Math.floor(Date.now() / 1000)
      };
      set((state: ChatState) => ({ messages: [...state.messages, optimistic], error: null }));
    } catch (error) {
      set({ error: toApiError(error).error });
    }
  },

  sendTyping: async (userId: number) => {
    const selected = get().selected;
    if (!selected || selected.kind !== "user") {
      return;
    }

    try {
      await api.typing(userId, selected.id);
    } catch {
      // best-effort signal
    }
  },

  appendIncoming: (message: Message) => {
    const selected = get().selected;
    if (!selected) return;

    const belongsToCurrentChat =
      selected.kind === "group"
        ? message.groupId === selected.id
        : (message.from === selected.id || message.to === selected.id) && !message.groupId;

    if (!belongsToCurrentChat) return;
    set((state: ChatState) => ({ messages: [...state.messages, message] }));
  }
}));